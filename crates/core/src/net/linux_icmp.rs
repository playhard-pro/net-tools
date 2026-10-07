//! Linux unprivileged ICMP engine (ping and MTR).
//!
//! Linux exposes a `SOCK_DGRAM` ICMP ("ping") socket that any user may open,
//! unlike a raw socket which needs `CAP_NET_RAW`. That datagram socket does not
//! carry the outer IP header, so the pieces a traceroute-style tool needs are
//! delivered out of band instead:
//!
//! * the reply TTL / hop limit arrives as control data (`IP_RECVTTL` for IPv4,
//!   `IPV6_RECVHOPLIMIT` for IPv6);
//! * the ICMP errors sent by intermediate routers arrive on the socket error
//!   queue when `IP_RECVERR` is enabled.
//!
//! surge-ping reads only the plain payload, which is why a Linux run lost the
//! ping TTL and produced an MTR route without intermediate hops. This module
//! drives the datagram socket directly so both work without elevation.

use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

/// ICMPv4 echo request type.
const ICMP_ECHO_REQUEST: u8 = 8;
/// ICMPv4 echo reply type.
const ICMP_ECHO_REPLY: u8 = 0;
/// ICMPv4 time exceeded type; every other ICMP error ends the path.
const ICMP_TIME_EXCEEDED: u8 = 11;
/// ICMPv6 echo request type.
const ICMPV6_ECHO_REQUEST: u8 = 128;
/// ICMPv6 echo reply type.
const ICMPV6_ECHO_REPLY: u8 = 129;
/// ICMPv6 time exceeded type; every other ICMPv6 error ends the path.
const ICMPV6_TIME_EXCEEDED: u8 = 3;

/// A control message buffer large enough for a TTL word or a
/// `sock_extended_err` plus the offending address.
const CONTROL_SIZE: usize = 512;

/// Outcome of one probe. `reached` is only meaningful in MTR mode: a
/// time-exceeded message comes from a router on the way, everything else ends
/// the path.
pub(super) struct Reply {
    pub from: IpAddr,
    pub ttl: Option<u8>,
    pub rtt: Duration,
    pub reached: bool,
}

/// What a single read from the socket produced.
enum Read {
    /// A message that belongs to the probe in flight.
    Reply(Reply),
    /// A message for another probe (late reply, unrelated error).
    Stale,
    /// The socket had nothing to read right now.
    Empty,
}

/// Whether the unprivileged datagram ICMP socket is usable for `ip`.
pub(super) fn can_open(ip: IpAddr) -> bool {
    open(ip, None, false).is_ok()
}

/// Open a datagram ICMP socket for `ip`.
///
/// The socket always asks for the reply TTL / hop limit. `observe_errors`
/// additionally routes routers' ICMP errors to the error queue, which MTR needs
/// and plain ping does not.
pub(super) fn open(ip: IpAddr, ttl: Option<u32>, observe_errors: bool) -> io::Result<Socket> {
    let (domain, protocol) = if ip.is_ipv6() {
        (Domain::IPV6, Protocol::ICMPV6)
    } else {
        (Domain::IPV4, Protocol::ICMPV4)
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(protocol))?;

    if let Some(ttl) = ttl {
        match ip {
            IpAddr::V4(_) => socket.set_ttl_v4(ttl)?,
            IpAddr::V6(_) => socket.set_unicast_hops_v6(ttl)?,
        }
    }

    match ip {
        IpAddr::V4(_) => {
            set_int_option(&socket, libc::IPPROTO_IP, libc::IP_RECVTTL, 1)?;
            if observe_errors {
                set_int_option(&socket, libc::IPPROTO_IP, libc::IP_RECVERR, 1)?;
            }
        }
        IpAddr::V6(_) => {
            set_int_option(&socket, libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT, 1)?;
            if observe_errors {
                set_int_option(&socket, libc::IPPROTO_IPV6, libc::IPV6_RECVERR, 1)?;
            }
        }
    }

    Ok(socket)
}

/// Send one echo request and wait for its answer, up to `timeout`.
///
/// Returns `Ok(None)` on timeout. When `observe_errors` is set the router
/// errors on the socket error queue are reported, otherwise they are only
/// drained so they cannot stall the readable state.
pub(super) fn probe(
    socket: &Socket,
    target: IpAddr,
    seq: u16,
    payload: &[u8],
    timeout: Duration,
    observe_errors: bool,
) -> io::Result<Option<Reply>> {
    let packet = echo_request(target, seq, payload);
    socket.send_to(&packet, &SockAddr::from(SocketAddr::new(target, 0)))?;

    let start = Instant::now();
    let deadline = start + timeout;
    let fd = socket.as_raw_fd();

    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        let remaining_ms = (deadline - now).as_millis().min(i32::MAX as u128) as i32;
        let mut poll_fd = libc::pollfd {
            fd,
            // A pending error queue entry is signalled as POLLERR, not POLLIN.
            events: libc::POLLIN | libc::POLLERR,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll_fd, 1, remaining_ms) };
        if ready < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if ready == 0 {
            return Ok(None);
        }

        if observe_errors {
            if let Read::Reply(reply) = read_error(socket, seq, start)? {
                return Ok(Some(reply));
            }
        } else {
            // Drain (and drop) router errors so POLLERR does not spin.
            let _ = read_error(socket, seq, start)?;
        }
        if let Read::Reply(reply) = read_normal(socket, target, seq, start)? {
            return Ok(Some(reply));
        }

        // A socket-level error can raise POLLERR without producing a readable
        // message. Back off briefly instead of spinning until the timeout.
        if poll_fd.revents & libc::POLLIN == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// Read one message from the normal receive path (echo reply).
fn read_normal(socket: &Socket, target: IpAddr, seq: u16, start: Instant) -> io::Result<Read> {
    let mut buf = [0u8; 1500];
    let mut control = [0u8; CONTROL_SIZE];
    let mut source: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let (n, msg) = recv(
        socket,
        &mut buf,
        &mut control,
        &mut source,
        libc::MSG_DONTWAIT,
    )?;
    let Some(n) = n else {
        return Ok(Read::Empty);
    };
    let data = &buf[..n];
    // An ICMP header is type, code, checksum, identifier, sequence.
    if data.len() < 8 {
        return Ok(Read::Stale);
    }
    let expected = if target.is_ipv6() {
        ICMPV6_ECHO_REPLY
    } else {
        ICMP_ECHO_REPLY
    };
    if data[0] != expected {
        return Ok(Read::Stale);
    }
    if u16::from_be_bytes([data[6], data[7]]) != seq {
        return Ok(Read::Stale);
    }
    let from = source_ip(&source).unwrap_or(target);
    Ok(Read::Reply(Reply {
        from,
        ttl: read_ttl(&msg),
        rtt: start.elapsed(),
        reached: true,
    }))
}

/// Read one message from the socket error queue (router error).
fn read_error(socket: &Socket, seq: u16, start: Instant) -> io::Result<Read> {
    let mut buf = [0u8; 1500];
    let mut control = [0u8; CONTROL_SIZE];
    let mut source: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let flags = libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT;
    let (n, msg) = recv(socket, &mut buf, &mut control, &mut source, flags)?;
    let Some(n) = n else {
        return Ok(Read::Empty);
    };
    let data = &buf[..n];
    // The error queue returns the echoed request, so the sequence number is
    // still at the same offset as on the wire.
    if data.len() < 8 || u16::from_be_bytes([data[6], data[7]]) != seq {
        return Ok(Read::Stale);
    }

    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        let level = unsafe { (*cmsg).cmsg_level };
        let kind = unsafe { (*cmsg).cmsg_type };
        let is_icmp_error = (level == libc::IPPROTO_IP && kind == libc::IP_RECVERR)
            || (level == libc::IPPROTO_IPV6 && kind == libc::IPV6_RECVERR);
        if is_icmp_error {
            let base = unsafe { libc::CMSG_DATA(cmsg) };
            let extended =
                unsafe { std::ptr::read_unaligned(base as *const libc::sock_extended_err) };
            let from_icmp = extended.ee_origin == libc::SO_EE_ORIGIN_ICMP
                || extended.ee_origin == libc::SO_EE_ORIGIN_ICMP6;
            if !from_icmp {
                return Ok(Read::Stale);
            }
            // Only a time-exceeded message marks a router; a destination
            // unreachable ends the path like the target's own reply.
            let reached =
                extended.ee_type != ICMP_TIME_EXCEEDED && extended.ee_type != ICMPV6_TIME_EXCEEDED;
            return match offender_ip(base) {
                Some(from) => Ok(Read::Reply(Reply {
                    from,
                    ttl: None,
                    rtt: start.elapsed(),
                    reached,
                })),
                None => Ok(Read::Stale),
            };
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
    }
    Ok(Read::Stale)
}

/// Build an echo request. The identifier and checksum are left for the kernel,
/// which fills them in for a datagram ICMP socket.
fn echo_request(target: IpAddr, seq: u16, payload: &[u8]) -> Vec<u8> {
    let msg_type = if target.is_ipv6() {
        ICMPV6_ECHO_REQUEST
    } else {
        ICMP_ECHO_REQUEST
    };
    let mut buf = Vec::with_capacity(8 + payload.len());
    buf.push(msg_type);
    buf.push(0);
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Receive one datagram together with its control data and source address.
///
/// Returns `Ok(None)` when the socket has nothing to read. Owns `msg` for the
/// caller so the control messages can be walked afterwards.
fn recv(
    socket: &Socket,
    buf: &mut [u8],
    control: &mut [u8],
    source: &mut libc::sockaddr_storage,
    flags: libc::c_int,
) -> io::Result<(Option<usize>, libc::msghdr)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = source as *mut _ as *mut libc::c_void;
    msg.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control.len() as _;

    let n = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msg, flags) };
    if n < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            return Ok((None, msg));
        }
        return Err(err);
    }
    Ok((Some(n as usize), msg))
}

/// Extract the reply TTL / hop limit from the control messages.
fn read_ttl(msg: &libc::msghdr) -> Option<u8> {
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(msg) };
    while !cmsg.is_null() {
        let level = unsafe { (*cmsg).cmsg_level };
        let kind = unsafe { (*cmsg).cmsg_type };
        if (level == libc::IPPROTO_IP && kind == libc::IP_TTL)
            || (level == libc::IPPROTO_IPV6 && kind == libc::IPV6_HOPLIMIT)
        {
            let data = unsafe { libc::CMSG_DATA(cmsg) };
            let value = unsafe { std::ptr::read_unaligned(data as *const libc::c_int) };
            if (0..=u8::MAX as libc::c_int).contains(&value) {
                return Some(value as u8);
            }
            return None;
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(msg, cmsg) };
    }
    None
}

/// Parse the address that follows a `sock_extended_err` in the error control
/// message.
fn offender_ip(base: *const u8) -> Option<IpAddr> {
    let addr = unsafe { base.add(mem::size_of::<libc::sock_extended_err>()) };
    let family = u16::from_ne_bytes(unsafe { [*addr, *addr.add(1)] });
    match family as libc::c_int {
        libc::AF_INET => {
            let mut octets = [0u8; 4];
            for (i, byte) in octets.iter_mut().enumerate() {
                *byte = unsafe { *addr.add(4 + i) };
            }
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        libc::AF_INET6 => {
            let mut octets = [0u8; 16];
            for (i, byte) in octets.iter_mut().enumerate() {
                *byte = unsafe { *addr.add(8 + i) };
            }
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// Parse the source address of a received datagram.
fn source_ip(source: &libc::sockaddr_storage) -> Option<IpAddr> {
    match source.ss_family as libc::c_int {
        libc::AF_INET => {
            let addr = unsafe { &*(source as *const _ as *const libc::sockaddr_in) };
            Some(IpAddr::V4(Ipv4Addr::from(
                addr.sin_addr.s_addr.to_ne_bytes(),
            )))
        }
        libc::AF_INET6 => {
            let addr = unsafe { &*(source as *const _ as *const libc::sockaddr_in6) };
            Some(IpAddr::V6(Ipv6Addr::from(addr.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

/// Set a boolean-ish integer socket option.
fn set_int_option(
    socket: &Socket,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            &value as *const _ as *const libc::c_void,
            mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_request_layout() {
        let packet = echo_request("127.0.0.1".parse().unwrap(), 0x1234, &[1, 2, 3]);
        assert_eq!(packet.len(), 8 + 3);
        assert_eq!(packet[0], ICMP_ECHO_REQUEST);
        assert_eq!(&packet[6..8], &[0x12, 0x34]);
        assert_eq!(&packet[8..], &[1, 2, 3]);
    }

    #[test]
    fn ipv6_echo_request_type() {
        let packet = echo_request("::1".parse().unwrap(), 1, &[]);
        assert_eq!(packet[0], ICMPV6_ECHO_REQUEST);
    }
}
