//! End-to-end NAT discovery tests against a local STUN server.
//!
//! The mock server binds separate sockets for the alternate address and port,
//! so CHANGE-REQUEST responses really arrive from a different endpoint.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use net_tools_core::config::NatSettings;
use net_tools_core::control::{TaskController, TaskState};
use net_tools_core::model::{IpVersion, NatTestMode, NatType, ProbeEvent};
use net_tools_core::net::stun::{run_query, StunAttribute, StunMessage};
use tokio::net::UdpSocket;

#[derive(Debug, Clone, Copy)]
enum MappingMode {
    /// Echo the observed source endpoint, which makes the mapping look direct.
    Echo,
    /// One mapping for every destination.
    EndpointIndependent,
    /// One mapping per destination address and port.
    AddressAndPortDependent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Primary,
    SameIpAltPort,
    AltIpPrimary,
    AltIpAltPort,
}

impl Role {
    fn index(self) -> u16 {
        match self {
            Role::Primary => 0,
            Role::SameIpAltPort => 1,
            Role::AltIpPrimary => 2,
            Role::AltIpAltPort => 3,
        }
    }
}

struct MockConfig {
    mapping: MappingMode,
    other: SocketAddr,
    respond_change_both: bool,
    respond_change_port: bool,
    classic: bool,
}

struct MockSockets {
    primary: Arc<UdpSocket>,
    same_ip_alt_port: Arc<UdpSocket>,
    alt_ip_primary: Arc<UdpSocket>,
    alt_ip_alt_port: Arc<UdpSocket>,
}

impl MockSockets {
    fn socket_for(&self, role: Role) -> &Arc<UdpSocket> {
        match role {
            Role::Primary => &self.primary,
            Role::SameIpAltPort => &self.same_ip_alt_port,
            Role::AltIpPrimary => &self.alt_ip_primary,
            Role::AltIpAltPort => &self.alt_ip_alt_port,
        }
    }
}

struct MockServer {
    sockets: Arc<MockSockets>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for MockServer {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn start_mock(
    mapping: MappingMode,
    respond_change_both: bool,
    respond_change_port: bool,
    classic: bool,
) -> Option<MockServer> {
    let primary = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let primary_addr = primary.local_addr().unwrap();
    let same_ip_alt_port = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let same_ip_alt_port_addr = same_ip_alt_port.local_addr().unwrap();

    // Linux and Windows accept any address in 127/8, but macOS only assigns
    // 127.0.0.1. The alternate-address tests cannot simulate CHANGE-REQUEST
    // from a second IP there, so report that the scenario is unavailable
    // instead of failing with an environment-specific bind error.
    let alt_ip = Ipv4Addr::new(127, 0, 0, 2);
    let alt_ip_primary = match UdpSocket::bind((alt_ip, primary_addr.port())).await {
        Ok(socket) => Arc::new(socket),
        Err(error) if error.kind() == std::io::ErrorKind::AddrNotAvailable => return None,
        Err(error) => panic!("failed to bind alternate loopback address: {error}"),
    };
    let alt_ip_alt_port = match UdpSocket::bind((alt_ip, same_ip_alt_port_addr.port())).await {
        Ok(socket) => Arc::new(socket),
        Err(error) if error.kind() == std::io::ErrorKind::AddrNotAvailable => return None,
        Err(error) => panic!("failed to bind alternate loopback address: {error}"),
    };

    let sockets = Arc::new(MockSockets {
        primary,
        same_ip_alt_port,
        alt_ip_primary,
        alt_ip_alt_port,
    });
    let config = Arc::new(MockConfig {
        mapping,
        other: sockets.alt_ip_alt_port.local_addr().unwrap(),
        respond_change_both,
        respond_change_port,
        classic,
    });

    let mut tasks = Vec::new();
    for role in [
        Role::Primary,
        Role::SameIpAltPort,
        Role::AltIpPrimary,
        Role::AltIpAltPort,
    ] {
        let sockets = Arc::clone(&sockets);
        let config = Arc::clone(&config);
        let receiver = Arc::clone(sockets.socket_for(role));
        tasks.push(tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            loop {
                let Ok((len, peer)) = receiver.recv_from(&mut buffer).await else {
                    break;
                };
                let Some(request) = StunMessage::decode(&buffer[..len]) else {
                    continue;
                };
                handle_request(&sockets, &config, role, &request, peer).await;
            }
        }));
    }

    Some(MockServer { sockets, tasks })
}

impl MockServer {
    fn primary_addr(&self) -> SocketAddr {
        self.sockets.primary.local_addr().unwrap()
    }
}

async fn handle_request(
    sockets: &MockSockets,
    config: &MockConfig,
    receiver: Role,
    request: &StunMessage,
    peer: SocketAddr,
) {
    let change = request.attributes.iter().find_map(|attr| match attr {
        StunAttribute::ChangeRequest {
            change_ip,
            change_port,
        } => Some((*change_ip, *change_port)),
        _ => None,
    });

    let response_role = match change {
        Some((true, true)) if config.respond_change_both => Role::AltIpAltPort,
        Some((false, true)) if config.respond_change_port => Role::SameIpAltPort,
        Some(_) => return,
        None => receiver,
    };

    let mapping_role = if change.is_some() {
        Role::Primary
    } else {
        receiver
    };
    let mapped = mapped_endpoint(config.mapping, mapping_role, peer);

    let mut attributes = Vec::new();
    if config.classic {
        attributes.push(StunAttribute::MappedAddress(mapped));
        attributes.push(StunAttribute::ChangedAddress(config.other));
    } else {
        attributes.push(StunAttribute::XorMappedAddress(mapped));
        attributes.push(StunAttribute::OtherAddress(config.other));
    }

    let response = StunMessage::binding_success(request.cookie, request.transaction_id, attributes);
    let _ = sockets
        .socket_for(response_role)
        .send_to(&response.encode(), peer)
        .await;
}

fn mapped_endpoint(mode: MappingMode, role: Role, peer: SocketAddr) -> SocketAddr {
    match mode {
        MappingMode::Echo => peer,
        MappingMode::EndpointIndependent => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 50000)
        }
        MappingMode::AddressAndPortDependent => SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            50200 + role.index(),
        ),
    }
}

async fn run(settings: NatSettings) -> Option<net_tools_core::model::NatResult> {
    let runtime = tokio::runtime::Handle::current();
    let mut controller = TaskController::new();
    controller.start(&runtime, move |handle| async move {
        run_query(&handle, &settings).await;
    });

    let mut result = None;
    for _ in 0..400 {
        for event in controller.drain() {
            if let ProbeEvent::Nat(value) = event {
                result = Some(value);
            }
        }
        if controller.state == TaskState::Finished {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(controller.state, TaskState::Finished, "discovery timed out");
    result
}

fn settings(server: SocketAddr, mode: NatTestMode) -> NatSettings {
    NatSettings {
        mode,
        server: server.to_string(),
        ip_version: IpVersion::V4,
        timeout_ms: 80,
        retries: 0,
        local_bind: String::new(),
    }
}

#[tokio::test]
async fn behavior_full_cone() {
    let Some(mock) = start_mock(MappingMode::EndpointIndependent, true, true, false).await else {
        eprintln!("skipping: alternate loopback address is unavailable");
        return;
    };
    let result = run(settings(mock.primary_addr(), NatTestMode::Rfc5780))
        .await
        .expect("result");
    assert_eq!(result.nat_type, NatType::FullCone);
    assert_eq!(
        result.filtering,
        net_tools_core::model::NatFilteringBehavior::EndpointIndependent
    );
    assert_eq!(
        result.mapping,
        net_tools_core::model::NatMappingBehavior::EndpointIndependent
    );
}

#[tokio::test]
async fn behavior_open_internet() {
    let Some(mock) = start_mock(MappingMode::Echo, true, true, false).await else {
        eprintln!("skipping: alternate loopback address is unavailable");
        return;
    };
    let result = run(settings(mock.primary_addr(), NatTestMode::Rfc5780))
        .await
        .expect("result");
    assert_eq!(result.nat_type, NatType::OpenInternet);
    assert_eq!(
        result.mapping,
        net_tools_core::model::NatMappingBehavior::Direct
    );
}

#[tokio::test]
async fn behavior_restricted_and_port_restricted_cone() {
    let Some(mock) = start_mock(MappingMode::EndpointIndependent, false, true, false).await else {
        eprintln!("skipping: alternate loopback address is unavailable");
        return;
    };
    let result = run(settings(mock.primary_addr(), NatTestMode::Rfc5780))
        .await
        .expect("result");
    assert_eq!(result.nat_type, NatType::RestrictedCone);
    drop(mock);

    let Some(mock) = start_mock(MappingMode::EndpointIndependent, false, false, false).await else {
        eprintln!("skipping: alternate loopback address is unavailable");
        return;
    };
    let result = run(settings(mock.primary_addr(), NatTestMode::Rfc5780))
        .await
        .expect("result");
    assert_eq!(result.nat_type, NatType::PortRestrictedCone);
}

#[tokio::test]
async fn behavior_symmetric() {
    let Some(mock) = start_mock(MappingMode::AddressAndPortDependent, false, false, false).await
    else {
        eprintln!("skipping: alternate loopback address is unavailable");
        return;
    };
    let result = run(settings(mock.primary_addr(), NatTestMode::Rfc5780))
        .await
        .expect("result");
    assert_eq!(result.nat_type, NatType::Symmetric);
    assert_eq!(
        result.mapping,
        net_tools_core::model::NatMappingBehavior::AddressAndPortDependent
    );
}

#[tokio::test]
async fn behavior_udp_blocked() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    // Keep the socket open but never answer, so the client times out instead of
    // receiving an ICMP port-unreachable error.
    tokio::spawn(async move {
        let mut buffer = [0u8; 1024];
        loop {
            if socket.recv_from(&mut buffer).await.is_err() {
                break;
            }
        }
    });

    let result = run(settings(addr, NatTestMode::Rfc5780))
        .await
        .expect("result");
    assert_eq!(result.nat_type, NatType::UdpBlocked);
    assert_eq!(
        result.binding,
        net_tools_core::model::NatBindingResult::Failed
    );
}

#[tokio::test]
async fn classic_full_cone_and_symmetric() {
    let Some(mock) = start_mock(MappingMode::EndpointIndependent, true, true, true).await else {
        eprintln!("skipping: alternate loopback address is unavailable");
        return;
    };
    let result = run(settings(mock.primary_addr(), NatTestMode::Rfc3489))
        .await
        .expect("result");
    assert_eq!(result.nat_type, NatType::FullCone);
    drop(mock);

    let Some(mock) = start_mock(MappingMode::AddressAndPortDependent, false, false, true).await
    else {
        eprintln!("skipping: alternate loopback address is unavailable");
        return;
    };
    let result = run(settings(mock.primary_addr(), NatTestMode::Rfc3489))
        .await
        .expect("result");
    assert_eq!(result.nat_type, NatType::Symmetric);
}
