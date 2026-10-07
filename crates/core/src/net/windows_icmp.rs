//! Windows ICMPv6 engine for reply TTL (hop limit).
//!
//! On Windows an ICMPv6 socket does not carry the outer IPv6 header, so the
//! reply hop limit is only available as ancillary data. surge-ping never fills
//! it in (it hardcodes the value), and neither tokio nor socket2 expose the
//! control messages, so this module reads them directly with `WSARecvMsg`.
//!
//! Only IPv6 needs this: on Windows the IPv4 replies still include their header
//! and surge-ping already reports that TTL. The socket is opened as a datagram
//! socket when possible and as a raw socket otherwise, mirroring surge-ping.

use std::io;
use std::mem;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::os::windows::io::AsRawSocket;
use std::ptr;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use windows_sys::Win32::Networking::WinSock::{
    setsockopt, WSAIoctl, WSAPoll, CMSGHDR, IPPROTO_IPV6, IPV6_HOPLIMIT, LPFN_WSARECVMSG,
    POLLRDNORM, SIO_GET_EXTENSION_FUNCTION_POINTER, SOCKADDR, SOCKADDR_STORAGE, SOCKET,
    SOCKET_ERROR, WSABUF, WSAEWOULDBLOCK, WSAID_WSARECVMSG, WSAMSG, WSAPOLLFD,
};

/// ICMPv6 echo request type.
const ICMPV6_ECHO_REQUEST: u8 = 128;
/// ICMPv6 echo reply type.
const ICMPV6_ECHO_REPLY: u8 = 129;
/// The IPv6 base header is this long; present on a raw socket that keeps it.
const IPV6_HEADER_LEN: usize = 40;
/// Control message buffer large enough for the hop limit message.
const CONTROL_SIZE: usize = 128;

/// One IPv6 ping socket plus the resolved `WSARecvMsg` entry point.
pub(super) struct Engine {
    socket: Socket,
    recv_msg: LPFN_WSARECVMSG,
}

/// The reply TTL of one probe.
pub(super) struct Reply {
    pub from: IpAddr,
    pub ttl: Option<u8>,
    pub rtt: Duration,
}

/// Open the engine, or fail so the caller can fall back to surge-ping.
pub(super) fn open() -> io::Result<Engine> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6))
        .or_else(|_| Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)))?;
    socket.set_nonblocking(true)?;
    let handle = socket.as_raw_socket() as SOCKET;
    enable_hop_limit(handle)?;
    let recv_msg = resolve_recv_msg(handle)?;
    Ok(Engine { socket, recv_msg })
}

/// Send one echo request and wait for its reply, up to `timeout`.
pub(super) fn probe(
    engine: &Engine,
    target: Ipv6Addr,
    seq: u16,
    payload: &[u8],
    timeout: Duration,
) -> io::Result<Option<Reply>> {
    let packet = echo_request(seq, payload);
    engine.socket.send_to(
        &packet,
        &SockAddr::from(SocketAddr::new(IpAddr::V6(target), 0)),
    )?;

    let start = Instant::now();
    let deadline = start + timeout;
    let handle = engine.socket.as_raw_socket() as SOCKET;

    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        let remaining_ms = (deadline - now).as_millis().min(i32::MAX as u128) as i32;
        let mut poll_fd = WSAPOLLFD {
            fd: handle,
            events: POLLRDNORM,
            revents: 0,
        };
        let ready = unsafe { WSAPoll(&mut poll_fd, 1, remaining_ms) };
        if ready == SOCKET_ERROR {
            return Err(io::Error::last_os_error());
        }
        if ready == 0 {
            return Ok(None);
        }

        let mut source: SOCKADDR_STORAGE = unsafe { mem::zeroed() };
        let mut buf = [0u8; 1500];
        let mut control = [0u8; CONTROL_SIZE];
        let mut data_buffer = WSABUF {
            len: buf.len() as u32,
            buf: buf.as_mut_ptr(),
        };
        let mut msg = WSAMSG {
            name: &mut source as *mut _ as *mut SOCKADDR,
            namelen: mem::size_of::<SOCKADDR_STORAGE>() as i32,
            lpBuffers: &mut data_buffer,
            dwBufferCount: 1,
            Control: WSABUF {
                len: control.len() as u32,
                buf: control.as_mut_ptr(),
            },
            dwFlags: 0,
        };
        let mut bytes: u32 = 0;
        let recv_msg = engine.recv_msg.expect("WSARecvMsg was resolved in open()");
        let rc = unsafe { recv_msg(handle, &mut msg, &mut bytes, ptr::null_mut(), None) };
        if rc == SOCKET_ERROR {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(WSAEWOULDBLOCK) {
                // Readable but nothing consumable: back off instead of
                // spinning until the deadline.
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
            return Err(err);
        }

        // A raw socket may keep the IPv6 header in front of the ICMPv6 message;
        // a datagram socket does not, so detect which one is present.
        let offset = if bytes as usize > 0 && (buf[0] >> 4) == 6 {
            IPV6_HEADER_LEN
        } else {
            0
        };
        if bytes as usize >= offset + 8 && buf[offset] == ICMPV6_ECHO_REPLY {
            let reply_seq = u16::from_be_bytes([buf[offset + 6], buf[offset + 7]]);
            if reply_seq == seq {
                return Ok(Some(Reply {
                    from: IpAddr::V6(target),
                    ttl: hop_limit(&msg),
                    rtt: start.elapsed(),
                }));
            }
        }
    }
}

/// Ask the socket to return the received hop limit as control data.
fn enable_hop_limit(handle: SOCKET) -> io::Result<()> {
    let on: i32 = 1;
    let rc = unsafe {
        setsockopt(
            handle,
            IPPROTO_IPV6,
            IPV6_HOPLIMIT,
            &on as *const i32 as *const u8,
            mem::size_of::<i32>() as i32,
        )
    };
    if rc == SOCKET_ERROR {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Resolve the `WSARecvMsg` function through `WSAIoctl`, as Winsock requires.
fn resolve_recv_msg(handle: SOCKET) -> io::Result<LPFN_WSARECVMSG> {
    let mut function: LPFN_WSARECVMSG = None;
    let mut bytes: u32 = 0;
    let rc = unsafe {
        WSAIoctl(
            handle,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            &WSAID_WSARECVMSG as *const _ as *const core::ffi::c_void,
            mem::size_of_val(&WSAID_WSARECVMSG) as u32,
            &mut function as *mut _ as *mut core::ffi::c_void,
            mem::size_of::<LPFN_WSARECVMSG>() as u32,
            &mut bytes,
            ptr::null_mut(),
            None,
        )
    };
    if rc == SOCKET_ERROR {
        return Err(io::Error::last_os_error());
    }
    Ok(function)
}

/// Read the hop limit control message from a completed receive.
fn hop_limit(msg: &WSAMSG) -> Option<u8> {
    let base = msg.Control.buf as *const u8;
    let total = msg.Control.len as usize;
    let mut offset = 0usize;
    while offset + mem::size_of::<CMSGHDR>() <= total {
        let header = unsafe { &*(base.add(offset) as *const CMSGHDR) };
        if header.cmsg_len < mem::size_of::<CMSGHDR>() || offset + header.cmsg_len > total {
            break;
        }
        if header.cmsg_level == IPPROTO_IPV6 && header.cmsg_type == IPV6_HOPLIMIT {
            let data = offset + aligned(mem::size_of::<CMSGHDR>());
            if data + 4 <= total {
                let value = unsafe { ptr::read_unaligned(base.add(data) as *const i32) };
                if (0..=u8::MAX as i32).contains(&value) {
                    return Some(value as u8);
                }
            }
            return None;
        }
        offset += aligned(header.cmsg_len);
    }
    None
}

/// Control messages are aligned to the pointer size.
fn aligned(len: usize) -> usize {
    (len + mem::size_of::<usize>() - 1) & !(mem::size_of::<usize>() - 1)
}

/// Build an echo request. The identifier and checksum are left for the kernel.
fn echo_request(seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + payload.len());
    buf.push(ICMPV6_ECHO_REQUEST);
    buf.push(0);
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_request_layout() {
        let packet = echo_request(0x1234, &[1, 2]);
        assert_eq!(packet.len(), 8 + 2);
        assert_eq!(packet[0], ICMPV6_ECHO_REQUEST);
        assert_eq!(&packet[6..8], &[0x12, 0x34]);
    }

    #[test]
    fn alignment_rounds_up_to_pointer() {
        let align = mem::size_of::<usize>();
        assert_eq!(aligned(align), align);
        assert!(aligned(align + 1) > align);
        assert_eq!(aligned(align + 1) % align, 0);
    }
}
