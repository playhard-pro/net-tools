//! Raw ICMP / ICMPv6 capture shared by TCP traceroute and Path MTU discovery.
//!
//! The socket is deliberately raw: intermediate routers answer a probe with an
//! ICMP error, and the quoted original packet is what lets callers match that
//! error back to the probe in flight. Raw sockets need elevation on most
//! platforms; permission errors are returned unchanged so callers can show the
//! existing guidance or request a UAC helper.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

/// Smallest IPv4 header length.
const IPV4_MIN_HEADER: usize = 20;
/// Fixed IPv6 header length.
const IPV6_HEADER: usize = 40;
/// ICMP / ICMPv6 header length.
const ICMP_HEADER: usize = 8;

/// The transport packet quoted inside an ICMP error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QuotedPacket {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// IP protocol number (ICMP is 1, TCP is 6, UDP is 17, ICMPv6 is 58).
    pub protocol: u8,
    pub src_port: u16,
    pub dst_port: u16,
    /// ICMP echo identifier when the quoted packet is an echo request.
    pub echo_id: Option<u16>,
    /// ICMP echo sequence number when the quoted packet is an echo request.
    pub echo_seq: Option<u16>,
}

/// Meaning of one received ICMP message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MessageKind {
    EchoReply,
    TimeExceeded,
    Unreachable,
    PacketTooBig,
    Other(u8),
}

/// One parsed ICMP / ICMPv6 message.
#[derive(Debug, Clone, Copy)]
pub(crate) struct IcmpMessage {
    pub from: IpAddr,
    pub kind: MessageKind,
    /// ICMP code, needed to tell fragmentation-needed apart from other
    /// destination-unreachable messages.
    pub code: u8,
    /// Echo identifier for echo replies.
    pub echo_id: Option<u16>,
    /// Echo sequence number for echo replies.
    pub echo_seq: Option<u16>,
    pub quoted: Option<QuotedPacket>,
}

/// Raw ICMP socket bound to one address family.
pub(crate) struct Capture {
    socket: Socket,
    family_v6: bool,
}

impl Capture {
    /// Open a non-blocking raw ICMP socket for the family of `target`.
    pub(crate) fn open(target: IpAddr) -> io::Result<Self> {
        let family_v6 = target.is_ipv6();
        let (domain, protocol) = if family_v6 {
            (Domain::IPV6, Protocol::ICMPV6)
        } else {
            (Domain::IPV4, Protocol::ICMPV4)
        };
        let socket = Socket::new(domain, Type::RAW, Some(protocol))?;
        socket.set_nonblocking(true)?;
        Ok(Self { socket, family_v6 })
    }

    /// Open a capture socket for ICMP errors about traffic sent to `target`.
    ///
    /// On Windows a plain raw ICMP socket may not receive transport-layer ICMP
    /// errors. A raw IPv4 socket with `SIO_RCVALL` receives the complete IP
    /// stream, from which the caller can pick the ICMP errors it needs.
    #[cfg(windows)]
    pub(crate) fn open_capture(target: IpAddr) -> io::Result<Self> {
        if target.is_ipv6() {
            return Self::open(target);
        }
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(0)))?;
        let local = local_addr_for(target, 33434)?;
        socket.bind(&SockAddr::from(SocketAddr::new(local.ip(), 0)))?;
        if enable_rcvall(&socket).is_err() {
            // Keep the previous behaviour as a fallback: some hardened hosts
            // allow raw ICMP but not promiscuous capture.
            return Self::open(target);
        }
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket,
            family_v6: false,
        })
    }

    /// Non-Windows platforms receive ICMP errors on the normal raw socket.
    #[cfg(not(windows))]
    pub(crate) fn open_capture(target: IpAddr) -> io::Result<Self> {
        Self::open(target)
    }

    /// Access the underlying socket, for sharing a poll loop with another fd.
    pub(crate) fn socket(&self) -> &Socket {
        &self.socket
    }

    /// Send an already checksummed ICMP message to `target`.
    pub(crate) fn send_to(&self, packet: &[u8], target: IpAddr) -> io::Result<usize> {
        self.socket
            .send_to(packet, &SockAddr::from(SocketAddr::new(target, 0)))
    }

    /// Disable local fragmentation for this socket.
    ///
    /// IPv4 sets DF; IPv6 has no DF bit, so the equivalent option prevents the
    /// local stack from fragmenting the probe itself.
    pub(crate) fn set_no_fragment(&self) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let (level, name, value) = if self.family_v6 {
                #[cfg(target_os = "linux")]
                {
                    (
                        libc::IPPROTO_IPV6,
                        libc::IPV6_MTU_DISCOVER,
                        libc::IP_PMTUDISC_DO,
                    )
                }
                #[cfg(not(target_os = "linux"))]
                {
                    // XNU/BSD expose the IPv6 don't-fragment switch without a
                    // symbolic constant in libc.
                    (libc::IPPROTO_IPV6, 62, 1)
                }
            } else {
                #[cfg(target_os = "linux")]
                {
                    (
                        libc::IPPROTO_IP,
                        libc::IP_MTU_DISCOVER,
                        libc::IP_PMTUDISC_DO,
                    )
                }
                #[cfg(not(target_os = "linux"))]
                {
                    (libc::IPPROTO_IP, libc::IP_DONTFRAG, 1)
                }
            };
            let rc = unsafe {
                libc::setsockopt(
                    self.socket.as_raw_fd(),
                    level,
                    name,
                    &value as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&value) as libc::socklen_t,
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawSocket;
            use windows_sys::Win32::Networking::WinSock::{
                setsockopt, IPPROTO_IP, IPPROTO_IPV6, IPV6_DONTFRAG, IP_DONTFRAGMENT, SOCKET_ERROR,
            };
            let (level, name, value) = if self.family_v6 {
                (IPPROTO_IPV6, IPV6_DONTFRAG, 1i32)
            } else {
                (IPPROTO_IP, IP_DONTFRAGMENT, 1i32)
            };
            let rc = unsafe {
                setsockopt(
                    self.socket.as_raw_socket() as _,
                    level,
                    name,
                    &value as *const i32 as *const u8,
                    std::mem::size_of_val(&value) as i32,
                )
            };
            if rc == SOCKET_ERROR {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "disabling fragmentation is not supported on this platform",
            ))
        }
    }

    /// Receive and parse one message without blocking.
    ///
    /// Returns `Ok(None)` when no message is ready. Packets that do not contain
    /// a parsable ICMP header are ignored.
    pub(crate) fn recv(&self) -> io::Result<Option<IcmpMessage>> {
        let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 2048];
        let (n, source) = match self.socket.recv_from(&mut buf) {
            Ok(value) => value,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => return Ok(None),
            Err(e) => return Err(e),
        };
        let Some(socket_source) = source.as_socket().map(|addr| addr.ip()) else {
            return Ok(None);
        };
        // Safety: recv_from initialized the first `n` bytes.
        let data = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
        Ok(parse_message(data, self.family_v6, socket_source))
    }
}

/// Parse a raw datagram. The outer IP header is present on some platforms and
/// absent on others, so its presence is detected from the first nibble.
fn parse_message(buf: &[u8], family_v6: bool, socket_source: IpAddr) -> Option<IcmpMessage> {
    if buf.is_empty() {
        return None;
    }
    let version = buf[0] >> 4;
    let (header_len, header_source) = if version == 4 {
        if buf.len() < IPV4_MIN_HEADER {
            return None;
        }
        let len = ((buf[0] & 0x0f) as usize) * 4;
        if len < IPV4_MIN_HEADER || buf.len() < len {
            return None;
        }
        let src = IpAddr::V4(Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]));
        (len, Some(src))
    } else if version == 6 {
        if buf.len() < IPV6_HEADER {
            return None;
        }
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&buf[8..24]);
        (IPV6_HEADER, Some(IpAddr::V6(Ipv6Addr::from(octets))))
    } else {
        // No outer header: the datagram starts with the ICMP message itself.
        (0, None)
    };

    if buf.len() < header_len + ICMP_HEADER {
        return None;
    }
    let icmp_type = buf[header_len];
    let code = buf[header_len + 1];
    let kind = classify(icmp_type, code, family_v6);
    let from = header_source.unwrap_or(socket_source);
    let (echo_id, echo_seq) = if matches!(kind, MessageKind::EchoReply) {
        (
            Some(u16::from_be_bytes([
                buf[header_len + 4],
                buf[header_len + 5],
            ])),
            Some(u16::from_be_bytes([
                buf[header_len + 6],
                buf[header_len + 7],
            ])),
        )
    } else {
        (None, None)
    };

    let quoted = if matches!(
        kind,
        MessageKind::TimeExceeded | MessageKind::Unreachable | MessageKind::PacketTooBig
    ) {
        parse_quoted(&buf[header_len + ICMP_HEADER..], family_v6)
    } else {
        None
    };

    Some(IcmpMessage {
        from,
        kind,
        code,
        echo_id,
        echo_seq,
        quoted,
    })
}

/// Map an ICMP type / code to a family-independent meaning.
fn classify(icmp_type: u8, code: u8, family_v6: bool) -> MessageKind {
    match (family_v6, icmp_type) {
        (false, 0) => MessageKind::EchoReply,
        (false, 3) if code == 4 => MessageKind::PacketTooBig,
        (false, 3) => MessageKind::Unreachable,
        (false, 11) => MessageKind::TimeExceeded,
        (true, 129) => MessageKind::EchoReply,
        (true, 1) => MessageKind::Unreachable,
        (true, 2) => MessageKind::PacketTooBig,
        (true, 3) => MessageKind::TimeExceeded,
        _ => MessageKind::Other(icmp_type),
    }
}

/// Parse the IP + transport headers quoted after an ICMP error.
fn parse_quoted(buf: &[u8], outer_v6: bool) -> Option<QuotedPacket> {
    if buf.is_empty() {
        return None;
    }
    let version = buf[0] >> 4;
    if version == 4 {
        if buf.len() < IPV4_MIN_HEADER {
            return None;
        }
        let ihl = ((buf[0] & 0x0f) as usize) * 4;
        if ihl < IPV4_MIN_HEADER || buf.len() < ihl + 4 {
            return None;
        }
        let protocol = buf[9];
        let src = IpAddr::V4(Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]));
        let dst = IpAddr::V4(Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]));
        port_pair(buf, ihl, protocol, src, dst)
    } else if version == 6 {
        if buf.len() < IPV6_HEADER + 4 {
            return None;
        }
        let protocol = buf[6];
        let mut src_octets = [0u8; 16];
        src_octets.copy_from_slice(&buf[8..24]);
        let mut dst_octets = [0u8; 16];
        dst_octets.copy_from_slice(&buf[24..40]);
        port_pair(
            buf,
            IPV6_HEADER,
            protocol,
            IpAddr::V6(Ipv6Addr::from(src_octets)),
            IpAddr::V6(Ipv6Addr::from(dst_octets)),
        )
    } else {
        // Some raw sockets omit the outer header; the quoted packet should
        // still start with an IP header, so this cannot be matched safely.
        let _ = outer_v6;
        None
    }
}

/// Extract source/destination ports for TCP or UDP probes.
fn port_pair(
    buf: &[u8],
    offset: usize,
    protocol: u8,
    src: IpAddr,
    dst: IpAddr,
) -> Option<QuotedPacket> {
    if protocol == 1 || protocol == 58 {
        if buf.len() < offset + 8 {
            return None;
        }
        return Some(QuotedPacket {
            src,
            dst,
            protocol,
            src_port: 0,
            dst_port: 0,
            echo_id: Some(u16::from_be_bytes([buf[offset + 4], buf[offset + 5]])),
            echo_seq: Some(u16::from_be_bytes([buf[offset + 6], buf[offset + 7]])),
        });
    }
    if protocol != 6 && protocol != 17 {
        return None;
    }
    if buf.len() < offset + 4 {
        return None;
    }
    Some(QuotedPacket {
        src,
        dst,
        protocol,
        src_port: u16::from_be_bytes([buf[offset], buf[offset + 1]]),
        dst_port: u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]),
        echo_id: None,
        echo_seq: None,
    })
}

/// Poll a raw capture socket and another socket together.
///
/// Returns `(raw_readable, tcp_writable)` flags. A socket-level error is also
/// reported through the matching flag so the caller can inspect it.
pub(crate) fn poll_pair(
    raw: &Socket,
    tcp: &Socket,
    timeout: std::time::Duration,
) -> io::Result<(bool, bool)> {
    let remaining_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let mut fds = [
            libc::pollfd {
                fd: raw.as_raw_fd(),
                events: libc::POLLIN | libc::POLLERR,
                revents: 0,
            },
            libc::pollfd {
                fd: tcp.as_raw_fd(),
                events: libc::POLLOUT | libc::POLLERR | libc::POLLHUP,
                revents: 0,
            },
        ];
        let ready =
            unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, remaining_ms) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok((false, false));
            }
            return Err(error);
        }
        if ready == 0 {
            return Ok((false, false));
        }
        Ok((fds[0].revents != 0, fds[1].revents != 0))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{select, FD_SET, SOCKET_ERROR, TIMEVAL};
        let raw_fd = raw.as_raw_socket() as usize;
        let tcp_fd = tcp.as_raw_socket() as usize;
        let mut readfds = FD_SET {
            fd_count: 1,
            ..Default::default()
        };
        readfds.fd_array[0] = raw_fd;
        let mut writefds = FD_SET {
            fd_count: 1,
            ..Default::default()
        };
        writefds.fd_array[0] = tcp_fd;
        let mut exceptfds = FD_SET {
            fd_count: 2,
            ..Default::default()
        };
        exceptfds.fd_array[0] = raw_fd;
        exceptfds.fd_array[1] = tcp_fd;
        let timeout = TIMEVAL {
            tv_sec: (remaining_ms / 1000) as i32,
            tv_usec: ((remaining_ms % 1000) * 1000) as i32,
        };
        let ready = unsafe { select(0, &mut readfds, &mut writefds, &mut exceptfds, &timeout) };
        if ready == SOCKET_ERROR {
            return Err(io::Error::last_os_error());
        }
        if ready == 0 {
            return Ok((false, false));
        }
        let raw_error = fd_set_contains(&exceptfds, raw_fd);
        let tcp_error = fd_set_contains(&exceptfds, tcp_fd);
        Ok((
            readfds.fd_count > 0 || raw_error,
            writefds.fd_count > 0 || tcp_error,
        ))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (raw, tcp);
        std::thread::sleep(timeout);
        Ok((false, false))
    }
}

/// Wait until the raw socket has a message to read, or the timeout expires.
pub(crate) fn poll_read(raw: &Socket, timeout: std::time::Duration) -> io::Result<bool> {
    let remaining_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let mut fd = libc::pollfd {
            fd: raw.as_raw_fd(),
            events: libc::POLLIN | libc::POLLERR,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut fd, 1, remaining_ms) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err(error);
        }
        Ok(ready > 0)
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{select, FD_SET, SOCKET_ERROR, TIMEVAL};
        let raw_fd = raw.as_raw_socket() as usize;
        let mut readfds = FD_SET {
            fd_count: 1,
            ..Default::default()
        };
        readfds.fd_array[0] = raw_fd;
        let mut exceptfds = FD_SET {
            fd_count: 1,
            ..Default::default()
        };
        exceptfds.fd_array[0] = raw_fd;
        let timeout = TIMEVAL {
            tv_sec: (remaining_ms / 1000) as i32,
            tv_usec: ((remaining_ms % 1000) * 1000) as i32,
        };
        let ready = unsafe {
            select(
                0,
                &mut readfds,
                std::ptr::null_mut(),
                &mut exceptfds,
                &timeout,
            )
        };
        if ready == SOCKET_ERROR {
            return Err(io::Error::last_os_error());
        }
        Ok(readfds.fd_count > 0 || fd_set_contains(&exceptfds, raw_fd))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = raw;
        std::thread::sleep(timeout);
        Ok(false)
    }
}

/// Enable Windows promiscuous capture on a raw IPv4 socket.
#[cfg(windows)]
fn enable_rcvall(socket: &Socket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{WSAIoctl, RCVALL_ON, SIO_RCVALL, SOCKET_ERROR};
    let value: i32 = RCVALL_ON;
    let mut bytes = 0u32;
    let rc = unsafe {
        WSAIoctl(
            socket.as_raw_socket() as _,
            SIO_RCVALL,
            &value as *const i32 as *const core::ffi::c_void,
            std::mem::size_of_val(&value) as u32,
            std::ptr::null_mut(),
            0,
            &mut bytes,
            std::ptr::null_mut(),
            None,
        )
    };
    if rc == SOCKET_ERROR {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Whether a Windows `FD_SET` contains a socket after `select`.
#[cfg(windows)]
fn fd_set_contains(set: &windows_sys::Win32::Networking::WinSock::FD_SET, fd: usize) -> bool {
    set.fd_array[..set.fd_count as usize].contains(&fd)
}

/// Build a raw ICMP echo request with a correct checksum.
///
/// Raw sockets do not get the kernel checksum help that a Linux datagram ping
/// socket provides, so IPv4 and IPv6 differ here.
pub(crate) fn echo_request(
    source: IpAddr,
    target: IpAddr,
    ident: u16,
    seq: u16,
    payload: &[u8],
) -> Vec<u8> {
    let is_v6 = target.is_ipv6();
    let msg_type = if is_v6 { 128 } else { 8 };
    let mut buf = Vec::with_capacity(ICMP_HEADER + payload.len());
    buf.push(msg_type);
    buf.push(0);
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&ident.to_be_bytes());
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(payload);
    if is_v6 {
        let checksum = icmpv6_checksum(source, target, &buf);
        buf[2..4].copy_from_slice(&checksum.to_be_bytes());
    } else {
        let checksum = checksum16(&buf);
        buf[2..4].copy_from_slice(&checksum.to_be_bytes());
    }
    buf
}

/// Internet checksum used by ICMPv4.
fn checksum16(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (chunks, remainder) = data.as_chunks::<2>();
    for chunk in chunks {
        sum += u16::from_be_bytes(*chunk) as u32;
    }
    if let [last] = remainder {
        sum += (*last as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// ICMPv6 checksum over the IPv6 pseudo-header.
fn icmpv6_checksum(source: IpAddr, target: IpAddr, packet: &[u8]) -> u16 {
    let (IpAddr::V6(src), IpAddr::V6(dst)) = (source, target) else {
        return checksum16(packet);
    };
    let mut sum: u32 = 0;
    let src_octets = src.octets();
    let dst_octets = dst.octets();
    for chunk in src_octets
        .as_chunks::<2>()
        .0
        .iter()
        .chain(dst_octets.as_chunks::<2>().0.iter())
    {
        sum += u16::from_be_bytes(*chunk) as u32;
    }
    sum += ((packet.len() as u32) >> 16) & 0xffff;
    sum += (packet.len() as u32) & 0xffff;
    sum += 58; // ICMPv6
    let (chunks, remainder) = packet.as_chunks::<2>();
    for chunk in chunks {
        sum += u16::from_be_bytes(*chunk) as u32;
    }
    if let [last] = remainder {
        sum += (*last as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Source address used by an unbound raw socket for a destination.
pub(crate) fn local_addr_for(target: IpAddr, port: u16) -> io::Result<SocketAddr> {
    let bind: SocketAddr = if target.is_ipv6() {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    };
    let socket = Socket::new(
        if target.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        },
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    socket.bind(&SockAddr::from(bind))?;
    socket.connect(&SockAddr::from(SocketAddr::new(target, port)))?;
    socket
        .local_addr()?
        .as_socket()
        .ok_or_else(|| io::Error::other("socket has no socket address"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_time_exceeded_and_quoted_tcp() {
        let mut packet = vec![0u8; 20 + 8 + 20 + 4];
        packet[0] = 0x45;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[20] = 11;
        // Quoted IPv4 + TCP header for 192.0.2.1:40000 -> 192.0.2.2:443.
        let q = 28;
        packet[q] = 0x45;
        packet[q + 9] = 6;
        packet[q + 12..q + 16].copy_from_slice(&[192, 0, 2, 1]);
        packet[q + 16..q + 20].copy_from_slice(&[192, 0, 2, 2]);
        packet[q + 20..q + 22].copy_from_slice(&40000u16.to_be_bytes());
        packet[q + 22..q + 24].copy_from_slice(&443u16.to_be_bytes());
        let msg = parse_message(&packet, false, "10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(msg.kind, MessageKind::TimeExceeded);
        assert_eq!(msg.from, "10.0.0.1".parse::<IpAddr>().unwrap());
        let quoted = msg.quoted.unwrap();
        assert_eq!(quoted.src_port, 40000);
        assert_eq!(quoted.dst_port, 443);
        assert_eq!(quoted.protocol, 6);
    }

    #[test]
    fn parses_ipv6_packet_too_big() {
        let mut packet = vec![0u8; 40 + 8 + 40 + 4];
        packet[0] = 0x60;
        packet[7] = 58;
        packet[8..24].copy_from_slice(&[0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        packet[24..40].copy_from_slice(&[0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        packet[40] = 2;
        let q = 48;
        packet[q] = 0x60;
        packet[q + 6] = 6;
        packet[q + 40..q + 42].copy_from_slice(&12345u16.to_be_bytes());
        packet[q + 42..q + 44].copy_from_slice(&443u16.to_be_bytes());
        let msg = parse_message(&packet, true, "::1".parse().unwrap()).unwrap();
        assert_eq!(msg.kind, MessageKind::PacketTooBig);
        let quoted = msg.quoted.unwrap();
        assert_eq!(quoted.src_port, 12345);
        assert_eq!(quoted.dst_port, 443);
    }

    #[test]
    fn echo_request_checksum_is_valid() {
        let packet = echo_request(
            "192.0.2.10".parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
            1,
            2,
            &[0x41; 8],
        );
        assert_eq!(checksum16(&packet), 0);
    }
}
