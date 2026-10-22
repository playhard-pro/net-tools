//! Application configuration persistence.

use net_tools_core::config::AppConfig;

/// Name of the dedicated application directory inside the system config
/// directory. The fixed name keeps deletion scoped to our own data.
const APP_DIR_NAME: &str = "net-tools";

/// Name of the configuration file managed by the application.
const CONFIG_FILE_NAME: &str = "config.toml";

/// Directory that holds the application's persisted data.
pub fn config_dir() -> Option<std::path::PathBuf> {
    Some(dirs::config_dir()?.join(APP_DIR_NAME))
}

fn config_path() -> Option<std::path::PathBuf> {
    Some(config_dir()?.join(CONFIG_FILE_NAME))
}

/// Delete the persisted configuration and input history.
///
/// Only files owned by the application are removed. The directory itself is
/// removed when it becomes empty, so unrelated files a user may have placed
/// there are never deleted. A missing file or directory counts as success.
pub fn reset() -> std::io::Result<()> {
    let Some(dir) = config_dir() else {
        return Ok(());
    };
    reset_dir(&dir)
}

/// Implementation of [`reset`] for a specific directory, kept separate so the
/// safety behavior can be tested without touching the real user config.
fn reset_dir(dir: &std::path::Path) -> std::io::Result<()> {
    remove_if_exists(&dir.join(CONFIG_FILE_NAME))?;
    match std::fs::remove_dir(dir) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        // Keep the directory when it still contains files we do not own.
        Err(err) if err.kind() == std::io::ErrorKind::DirectoryNotEmpty => Ok(()),
        Err(err) => Err(err),
    }
}

/// Remove one file, ignoring an already missing path.
fn remove_if_exists(path: &std::path::Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

/// Load the previously saved configuration; returns `None` on failure.
pub fn load() -> Option<AppConfig> {
    let path = config_path()?;
    let text = std::fs::read_to_string(path).ok()?;
    toml::from_str(&text).ok()
}

/// Save the configuration (best effort).
pub fn save(cfg: &AppConfig) {
    if let Some(path) = config_path() {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(text) = toml::to_string_pretty(cfg) {
            let _ = std::fs::write(path, text);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_removes_owned_file_but_keeps_unrelated_ones() {
        let base = std::env::temp_dir().join(format!(
            "net-tools-reset-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let owned = base.join(CONFIG_FILE_NAME);
        let foreign = base.join("notes.txt");
        std::fs::write(&owned, "config").unwrap();
        std::fs::write(&foreign, "user data").unwrap();

        reset_dir(&base).unwrap();

        assert!(!owned.exists(), "the application config must be removed");
        assert!(foreign.exists(), "unrelated files must be kept");
        assert!(
            base.exists(),
            "the directory stays while foreign files exist"
        );

        std::fs::remove_file(&foreign).unwrap();
        std::fs::remove_dir(&base).unwrap();
    }
}
