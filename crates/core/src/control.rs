//! Task control: an independent state machine, cancellation token and event
//! channel for each tab.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// State of a controlled task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Idle,
    Running,
    Paused,
    Stopping,
    Finished,
}

impl TaskState {
    pub fn label(&self) -> &'static str {
        match self {
            TaskState::Idle => "idle",
            TaskState::Running => "running",
            TaskState::Paused => "paused",
            TaskState::Stopping => "stopping",
            TaskState::Finished => "finished",
        }
    }
}

/// Handle passed to a probe task: emit events, check cancellation / pause and
/// sleep in an interruptible way.
pub struct ProbeHandle<E> {
    tx: mpsc::UnboundedSender<E>,
    cancel: CancellationToken,
    paused: Arc<AtomicBool>,
}

impl<E> Clone for ProbeHandle<E> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            cancel: self.cancel.clone(),
            paused: self.paused.clone(),
        }
    }
}

impl<E: Send + 'static> ProbeHandle<E> {
    pub fn send(&self, event: E) {
        let _ = self.tx.send(event);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// Resolves as soon as the task is cancelled, for use in `select!`.
    pub async fn cancelled(&self) {
        self.cancel.cancelled().await;
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Relaxed)
    }

    /// Block while paused, until either resumed or cancelled.
    pub async fn wait_if_paused(&self) {
        while self.is_paused() {
            if self.is_cancelled() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Interruptible sleep. Returns `true` if the task was cancelled.
    pub async fn sleep(&self, d: Duration) -> bool {
        tokio::select! {
            _ = tokio::time::sleep(d) => false,
            _ = self.cancel.cancelled() => true,
        }
    }
}

/// Task controller for a single tab. Each instance owns its own cancellation
/// token and channel, so tabs never interfere with one another.
pub struct TaskController<E> {
    pub state: TaskState,
    cancel: CancellationToken,
    paused: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    rx: mpsc::UnboundedReceiver<E>,
}

impl<E: Send + 'static> TaskController<E> {
    pub fn new() -> Self {
        let (_tx, rx) = mpsc::unbounded_channel();
        Self {
            state: TaskState::Idle,
            cancel: CancellationToken::new(),
            paused: Arc::new(AtomicBool::new(false)),
            handle: None,
            rx,
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(
            self.state,
            TaskState::Running | TaskState::Paused | TaskState::Stopping
        )
    }

    /// Start a task, aborting any previous one.
    ///
    /// A runtime `Handle` is required: use `Handle::spawn` rather than the global
    /// `tokio::spawn`, because the UI thread is not inside a runtime context and
    /// the global spawn would panic there.
    pub fn start<F, Fut>(&mut self, rt: &tokio::runtime::Handle, f: F)
    where
        F: FnOnce(ProbeHandle<E>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
        self.cancel = CancellationToken::new();
        self.paused = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::unbounded_channel();
        let handle = ProbeHandle {
            tx,
            cancel: self.cancel.clone(),
            paused: self.paused.clone(),
        };
        let inner = handle.clone();
        self.handle = Some(rt.spawn(async move {
            f(inner).await;
        }));
        self.rx = rx;
        self.state = TaskState::Running;
    }

    pub fn pause(&mut self) {
        if self.state == TaskState::Running {
            self.paused.store(true, Ordering::Relaxed);
            self.state = TaskState::Paused;
        }
    }

    pub fn resume(&mut self) {
        if self.state == TaskState::Paused {
            self.paused.store(false, Ordering::Relaxed);
            self.state = TaskState::Running;
        }
    }

    pub fn stop(&mut self) {
        if self.is_active() {
            self.cancel.cancel();
            self.state = TaskState::Stopping;
        }
    }

    /// Drain and return all pending events; if the task has ended, move the
    /// state to `Finished`.
    pub fn drain(&mut self) -> Vec<E> {
        let mut out = Vec::new();
        while let Ok(e) = self.rx.try_recv() {
            out.push(e);
        }
        if self.is_active() {
            if let Some(h) = &self.handle {
                if h.is_finished() {
                    self.state = TaskState::Finished;
                    self.handle = None;
                }
            }
        }
        out
    }
}

impl<E> Default for TaskController<E>
where
    E: Send + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controller_drain_and_finish() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handle = rt.handle().clone();
        rt.block_on(async {
            let mut c: TaskController<i32> = TaskController::new();
            c.start(&handle, |h| async move {
                h.send(1);
                h.send(2);
            });
            assert_eq!(c.state, TaskState::Running);
            // Wait for the task to finish.
            tokio::time::sleep(Duration::from_millis(20)).await;
            let mut got = c.drain();
            let mut more = c.drain();
            got.append(&mut more);
            assert_eq!(got, vec![1, 2]);
            assert_eq!(c.state, TaskState::Finished);
        });
    }

    #[test]
    fn pause_resume_stop() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handle = rt.handle().clone();
        rt.block_on(async {
            let mut c: TaskController<()> = TaskController::new();
            c.start(&handle, |h| async move {
                loop {
                    h.wait_if_paused().await;
                    if h.is_cancelled() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            });
            c.pause();
            assert_eq!(c.state, TaskState::Paused);
            c.resume();
            assert_eq!(c.state, TaskState::Running);
            c.stop();
            assert_eq!(c.state, TaskState::Stopping);
            tokio::time::sleep(Duration::from_millis(20)).await;
            c.drain();
            assert_eq!(c.state, TaskState::Finished);
        });
    }

    /// Reproduces and guards against a regression: calling `start` from outside
    /// a runtime context (e.g. the UI thread). The global `tokio::spawn` panics
    /// there, while `Handle::spawn` works.
    #[test]
    fn start_outside_runtime_context() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let handle = rt.handle().clone();
        // Note: not inside block_on / enter, simulating the UI thread.
        let mut c: TaskController<i32> = TaskController::new();
        c.start(&handle, |h| async move {
            h.send(42);
        });
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(c.drain(), vec![42]);
    }

    #[test]
    fn drain_returns_empty_when_idle() {
        let mut c: TaskController<i32> = TaskController::new();
        assert!(c.drain().is_empty());
    }
}
