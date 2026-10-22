//! STUN protocol support for NAT behavior discovery.
//!
//! The module is split into a dependency-free wire codec, a UDP transaction
//! layer, and two pure state machines that implement the classic and behavior
//! discovery procedures. Keeping the state machines free of I/O makes every
//! classification branch testable without a network.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::config::NatSettings;
use crate::control::ProbeHandle;
use crate::model::{NatResult, ProbeEvent};

/// Fixed STUN header length: type, length, magic cookie and transaction ID.
const HEADER_LEN: usize = 20;

/// Cookie that identifies modern STUN messages.
const MAGIC_COOKIE: u32 = 0x2112_A442;

/// Length of the transaction ID shared by a request and its responses.
const TRANSACTION_ID_LEN: usize = 12;

/// STUN Binding Request message type.
const BINDING_REQUEST: u16 = 0x0001;

/// STUN Binding Success Response message type.
const BINDING_SUCCESS: u16 = 0x0101;

/// STUN Binding Error Response message type.
const BINDING_ERROR: u16 = 0x0111;

/// MAPPED-ADDRESS attribute (classic STUN).
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;

/// CHANGE-REQUEST attribute requesting a different source endpoint.
const ATTR_CHANGE_REQUEST: u16 = 0x0003;

/// CHANGED-ADDRESS attribute carrying the server's alternate endpoint.
const ATTR_CHANGED_ADDRESS: u16 = 0x0005;

/// ERROR-CODE attribute carrying a numeric error and reason phrase.
const ATTR_ERROR_CODE: u16 = 0x0009;

/// XOR-MAPPED-ADDRESS attribute carrying the reflexive transport address.
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// OTHER-ADDRESS attribute carrying the alternate server endpoint.
const ATTR_OTHER_ADDRESS: u16 = 0x802C;

/// Address family value for IPv4 inside address attributes.
const FAMILY_IPV4: u8 = 0x01;

/// Address family value for IPv6 inside address attributes.
const FAMILY_IPV6: u8 = 0x02;

/// One decoded STUN attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StunAttribute {
    /// Classic reflexive address.
    MappedAddress(SocketAddr),
    /// Server's alternate address used by the classic procedure.
    ChangedAddress(SocketAddr),
    /// Modern reflexive address.
    XorMappedAddress(SocketAddr),
    /// Server's alternate address used by the behavior procedure.
    OtherAddress(SocketAddr),
    /// Requested source change for the response.
    ChangeRequest { change_ip: bool, change_port: bool },
    /// Numeric error code and optional reason phrase.
    ErrorCode { code: u16, reason: String },
    /// Attribute not needed by the discovery procedures.
    Unknown { kind: u16, value: Vec<u8> },
}

impl StunAttribute {
    /// Encode the attribute, including its type, length and padding.
    fn encode(&self, cookie: u32, transaction_id: &[u8; TRANSACTION_ID_LEN], out: &mut Vec<u8>) {
        let mut value = Vec::new();
        let kind = match self {
            StunAttribute::MappedAddress(addr) => {
                encode_address(addr, false, cookie, transaction_id, &mut value);
                ATTR_MAPPED_ADDRESS
            }
            StunAttribute::ChangedAddress(addr) => {
                encode_address(addr, false, cookie, transaction_id, &mut value);
                ATTR_CHANGED_ADDRESS
            }
            StunAttribute::XorMappedAddress(addr) => {
                encode_address(addr, true, cookie, transaction_id, &mut value);
                ATTR_XOR_MAPPED_ADDRESS
            }
            StunAttribute::OtherAddress(addr) => {
                encode_address(addr, false, cookie, transaction_id, &mut value);
                ATTR_OTHER_ADDRESS
            }
            StunAttribute::ChangeRequest {
                change_ip,
                change_port,
            } => {
                let mut flags = 0u32;
                if *change_ip {
                    flags |= 0x04;
                }
                if *change_port {
                    flags |= 0x02;
                }
                value.extend_from_slice(&flags.to_be_bytes());
                ATTR_CHANGE_REQUEST
            }
            StunAttribute::ErrorCode { code, reason } => {
                // The first two bytes are reserved; the class and number share
                // the following two bytes.
                value.push(0);
                value.push(0);
                value.push((code / 100) as u8);
                value.push((code % 100) as u8);
                value.extend_from_slice(reason.as_bytes());
                ATTR_ERROR_CODE
            }
            StunAttribute::Unknown { kind, value: raw } => {
                value.extend_from_slice(raw);
                *kind
            }
        };

        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(&value);
        // Every attribute is padded to a four-byte boundary.
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }
}

/// A decoded STUN message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunMessage {
    /// Raw message type, including class bits.
    pub message_type: u16,
    /// Magic cookie. Classic messages use zero.
    pub cookie: u32,
    /// Transaction identifier shared with the request.
    pub transaction_id: [u8; TRANSACTION_ID_LEN],
    /// Decoded attributes in wire order.
    pub attributes: Vec<StunAttribute>,
}

impl StunMessage {
    /// Build a Binding Request. `change` adds a CHANGE-REQUEST attribute.
    pub fn binding_request(
        cookie: u32,
        transaction_id: [u8; TRANSACTION_ID_LEN],
        change: Option<(bool, bool)>,
    ) -> Self {
        let mut attributes = Vec::new();
        if let Some((change_ip, change_port)) = change {
            attributes.push(StunAttribute::ChangeRequest {
                change_ip,
                change_port,
            });
        }
        Self {
            message_type: BINDING_REQUEST,
            cookie,
            transaction_id,
            attributes,
        }
    }

    /// Build a Binding Success Response. Used by the local test server.
    pub fn binding_success(
        cookie: u32,
        transaction_id: [u8; TRANSACTION_ID_LEN],
        attributes: Vec<StunAttribute>,
    ) -> Self {
        Self {
            message_type: BINDING_SUCCESS,
            cookie,
            transaction_id,
            attributes,
        }
    }

    /// Whether this is a success response.
    pub fn is_success(&self) -> bool {
        self.message_type == BINDING_SUCCESS
    }

    /// Whether this is an error response.
    pub fn is_error(&self) -> bool {
        self.message_type == BINDING_ERROR
    }

    /// Whether this message belongs to the same transaction as the request.
    pub fn matches_transaction(
        &self,
        cookie: u32,
        transaction_id: &[u8; TRANSACTION_ID_LEN],
    ) -> bool {
        self.cookie == cookie && &self.transaction_id == transaction_id
    }

    /// First valid mapped address, preferring the modern XOR attribute.
    pub fn mapped_address(&self) -> Option<SocketAddr> {
        self.address(ATTR_XOR_MAPPED_ADDRESS)
            .or_else(|| self.address(ATTR_MAPPED_ADDRESS))
    }

    /// Classic mapped address only.
    pub fn classic_mapped_address(&self) -> Option<SocketAddr> {
        self.address(ATTR_MAPPED_ADDRESS)
    }

    /// Server's alternate address, accepting either attribute name.
    pub fn other_address(&self) -> Option<SocketAddr> {
        self.address(ATTR_OTHER_ADDRESS)
            .or_else(|| self.address(ATTR_CHANGED_ADDRESS))
    }

    /// Classic CHANGED-ADDRESS attribute only.
    pub fn changed_address(&self) -> Option<SocketAddr> {
        self.address(ATTR_CHANGED_ADDRESS)
    }

    /// Numeric error code and reason phrase, if present.
    pub fn error(&self) -> Option<(u16, String)> {
        self.attributes.iter().find_map(|attr| match attr {
            StunAttribute::ErrorCode { code, reason } => Some((*code, reason.clone())),
            _ => None,
        })
    }

    fn address(&self, kind: u16) -> Option<SocketAddr> {
        self.attributes.iter().find_map(|attr| {
            let matches = matches!(
                (kind, attr),
                (ATTR_MAPPED_ADDRESS, StunAttribute::MappedAddress(_))
                    | (ATTR_CHANGED_ADDRESS, StunAttribute::ChangedAddress(_))
                    | (ATTR_XOR_MAPPED_ADDRESS, StunAttribute::XorMappedAddress(_))
                    | (ATTR_OTHER_ADDRESS, StunAttribute::OtherAddress(_))
            );
            if matches {
                match attr {
                    StunAttribute::MappedAddress(addr)
                    | StunAttribute::ChangedAddress(addr)
                    | StunAttribute::XorMappedAddress(addr)
                    | StunAttribute::OtherAddress(addr) => Some(*addr),
                    _ => None,
                }
            } else {
                None
            }
        })
    }

    /// Serialize the message into a fresh buffer.
    pub fn encode(&self) -> Vec<u8> {
        let mut attributes = Vec::new();
        for attr in &self.attributes {
            attr.encode(self.cookie, &self.transaction_id, &mut attributes);
        }
        let mut out = Vec::with_capacity(HEADER_LEN + attributes.len());
        out.extend_from_slice(&self.message_type.to_be_bytes());
        out.extend_from_slice(&(attributes.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.cookie.to_be_bytes());
        out.extend_from_slice(&self.transaction_id);
        out.extend_from_slice(&attributes);
        out
    }

    /// Decode a message from a datagram.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HEADER_LEN {
            return None;
        }
        let message_type = u16::from_be_bytes([bytes[0], bytes[1]]);
        let length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        if bytes.len() < HEADER_LEN + length {
            return None;
        }
        let cookie = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let mut transaction_id = [0u8; TRANSACTION_ID_LEN];
        transaction_id.copy_from_slice(&bytes[8..HEADER_LEN]);

        let mut attributes = Vec::new();
        let mut offset = HEADER_LEN;
        let end = HEADER_LEN + length;
        while offset + 4 <= end {
            let kind = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            let attr_len = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
            let value_start = offset + 4;
            let value_end = value_start.checked_add(attr_len)?;
            if value_end > end {
                return None;
            }
            let value = &bytes[value_start..value_end];
            attributes.push(decode_attribute(kind, value, cookie, &transaction_id)?);
            // Advance past the value and its padding.
            let padded = (attr_len + 3) & !3;
            offset = value_start.checked_add(padded)?;
        }

        Some(Self {
            message_type,
            cookie,
            transaction_id,
            attributes,
        })
    }
}

fn decode_attribute(
    kind: u16,
    value: &[u8],
    cookie: u32,
    transaction_id: &[u8; TRANSACTION_ID_LEN],
) -> Option<StunAttribute> {
    match kind {
        ATTR_MAPPED_ADDRESS | ATTR_CHANGED_ADDRESS | ATTR_OTHER_ADDRESS => {
            let addr = decode_address(value, false, cookie, transaction_id)?;
            Some(match kind {
                ATTR_MAPPED_ADDRESS => StunAttribute::MappedAddress(addr),
                ATTR_CHANGED_ADDRESS => StunAttribute::ChangedAddress(addr),
                _ => StunAttribute::OtherAddress(addr),
            })
        }
        ATTR_XOR_MAPPED_ADDRESS => {
            let addr = decode_address(value, true, cookie, transaction_id)?;
            Some(StunAttribute::XorMappedAddress(addr))
        }
        ATTR_CHANGE_REQUEST => {
            if value.len() < 4 {
                return None;
            }
            let flags = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
            Some(StunAttribute::ChangeRequest {
                change_ip: flags & 0x04 != 0,
                change_port: flags & 0x02 != 0,
            })
        }
        ATTR_ERROR_CODE => {
            if value.len() < 4 {
                return None;
            }
            let class = value[2] as u16 & 0x07;
            let number = value[3] as u16;
            let reason = String::from_utf8_lossy(&value[4..]).into_owned();
            Some(StunAttribute::ErrorCode {
                code: class * 100 + number,
                reason,
            })
        }
        _ => Some(StunAttribute::Unknown {
            kind,
            value: value.to_vec(),
        }),
    }
}

fn encode_address(
    addr: &SocketAddr,
    xor: bool,
    cookie: u32,
    transaction_id: &[u8; TRANSACTION_ID_LEN],
    out: &mut Vec<u8>,
) {
    out.push(0);
    out.push(match addr {
        SocketAddr::V4(_) => FAMILY_IPV4,
        SocketAddr::V6(_) => FAMILY_IPV6,
    });

    let port = if xor {
        addr.port() ^ (cookie >> 16) as u16
    } else {
        addr.port()
    };
    out.extend_from_slice(&port.to_be_bytes());

    match addr.ip() {
        IpAddr::V4(ip) => {
            let raw = u32::from(ip);
            let value = if xor { raw ^ cookie } else { raw };
            out.extend_from_slice(&value.to_be_bytes());
        }
        IpAddr::V6(ip) => {
            let raw = u128::from(ip);
            let value = if xor {
                let mut mask = [0u8; 16];
                mask[..4].copy_from_slice(&cookie.to_be_bytes());
                mask[4..].copy_from_slice(transaction_id);
                raw ^ u128::from_be_bytes(mask)
            } else {
                raw
            };
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn decode_address(
    value: &[u8],
    xor: bool,
    cookie: u32,
    transaction_id: &[u8; TRANSACTION_ID_LEN],
) -> Option<SocketAddr> {
    if value.len() < 4 {
        return None;
    }
    let family = value[1];
    let port = u16::from_be_bytes([value[2], value[3]]);
    let port = if xor {
        port ^ (cookie >> 16) as u16
    } else {
        port
    };

    match family {
        FAMILY_IPV4 if value.len() >= 8 => {
            let raw = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
            let raw = if xor { raw ^ cookie } else { raw };
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(raw)), port))
        }
        FAMILY_IPV6 if value.len() >= 20 => {
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&value[4..20]);
            let raw = if xor {
                let mut mask = [0u8; 16];
                mask[..4].copy_from_slice(&cookie.to_be_bytes());
                mask[4..].copy_from_slice(transaction_id);
                u128::from_be_bytes(raw) ^ u128::from_be_bytes(mask)
            } else {
                u128::from_be_bytes(raw)
            };
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(raw)), port))
        }
        _ => None,
    }
}

/// One request the discovery state machine wants to send.
#[derive(Debug, Clone)]
pub struct Action {
    /// Request message, including its transaction ID.
    pub message: StunMessage,
    /// Destination endpoint.
    pub send_to: SocketAddr,
    /// Procedure step this request belongs to.
    pub kind: crate::model::NatStepKind,
    /// Whether the request asks the server to change its source IP.
    pub change_ip: bool,
    /// Whether the request asks the server to change its source port.
    pub change_port: bool,
}

/// One observation fed back into the state machine.
#[derive(Debug, Clone)]
pub struct Observation {
    /// Decoded response, or `None` when every attempt timed out.
    pub response: Option<StunMessage>,
    /// Actual source of the response. On timeout, this repeats the target.
    pub source: SocketAddr,
    /// Round-trip time of the successful attempt, in milliseconds.
    pub rtt_ms: f64,
}

/// UDP socket used for a discovery run.
///
/// The socket is intentionally unconnected: a CHANGE-REQUEST response may
/// arrive from a different address or port than the one the request was sent
/// to, and `recv_from` exposes that source.
pub struct StunSocket {
    socket: tokio::net::UdpSocket,
}

impl StunSocket {
    /// Bind a socket matching the target address family.
    ///
    /// `local_bind` may be empty, an IP address, or `IP:port`. An empty value
    /// binds an ephemeral port on the wildcard address.
    pub async fn bind(target: SocketAddr, local_bind: &str) -> Result<Self, String> {
        let bind_addr = parse_local_bind(target, local_bind)?;
        let socket = tokio::net::UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| format!("failed to bind UDP socket {bind_addr}: {e}"))?;
        Ok(Self { socket })
    }

    /// Local endpoint the socket is bound to.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.socket.local_addr().ok()
    }

    /// Send one action and wait for its matching response.
    ///
    /// `retries` counts additional attempts after the first timeout. Responses
    /// with a different transaction ID are ignored so a late reply from an
    /// earlier step cannot be mistaken for the current one.
    pub async fn request(
        &self,
        action: &Action,
        timeout_ms: u64,
        retries: u32,
    ) -> Result<Observation, String> {
        let bytes = action.message.encode();
        let timeout = std::time::Duration::from_millis(timeout_ms.max(1));
        let mut buffer = [0u8; 4096];

        for attempt in 0..=retries {
            let started = std::time::Instant::now();
            self.socket
                .send_to(&bytes, action.send_to)
                .await
                .map_err(|e| format!("failed to send STUN request: {e}"))?;

            let deadline = started + timeout;
            loop {
                let now = std::time::Instant::now();
                if now >= deadline {
                    break;
                }
                let remaining = deadline - now;
                let received =
                    tokio::time::timeout(remaining, self.socket.recv_from(&mut buffer)).await;

                match received {
                    Ok(Ok((len, source))) => {
                        if let Some(message) = StunMessage::decode(&buffer[..len]) {
                            if message.matches_transaction(
                                action.message.cookie,
                                &action.message.transaction_id,
                            ) {
                                return Ok(Observation {
                                    response: Some(message),
                                    source,
                                    rtt_ms: started.elapsed().as_secs_f64() * 1000.0,
                                });
                            }
                        }
                        // Ignore unrelated datagrams and keep waiting within
                        // the remaining time budget.
                    }
                    Ok(Err(e)) => {
                        return Err(format!("failed to receive STUN response: {e}"));
                    }
                    Err(_) => break,
                }
            }

            if attempt < retries {
                // A short pause avoids retrying in a tight loop against a
                // server that is temporarily rate limiting.
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }

        Ok(Observation {
            response: None,
            source: action.send_to,
            rtt_ms: 0.0,
        })
    }
}

/// Shared mutable state produced by both discovery procedures.
#[derive(Debug, Clone)]
pub struct DiscoveryState {
    pub nat_type: crate::model::NatType,
    pub binding: crate::model::NatBindingResult,
    pub mapping: crate::model::NatMappingBehavior,
    pub filtering: crate::model::NatFilteringBehavior,
    pub public_endpoint: Option<SocketAddr>,
    pub other_endpoint: Option<SocketAddr>,
    pub steps: Vec<crate::model::NatStep>,
    pub warning: Option<String>,
    /// Whether the procedure has reached a final classification.
    pub done: bool,
}

impl Default for DiscoveryState {
    fn default() -> Self {
        Self {
            nat_type: crate::model::NatType::Unknown,
            binding: crate::model::NatBindingResult::Unknown,
            mapping: crate::model::NatMappingBehavior::Unknown,
            filtering: crate::model::NatFilteringBehavior::Unknown,
            public_endpoint: None,
            other_endpoint: None,
            steps: Vec::new(),
            warning: None,
            done: false,
        }
    }
}

impl DiscoveryState {
    fn finish(&mut self, nat_type: crate::model::NatType) {
        self.nat_type = nat_type;
        self.done = true;
    }

    fn record(&mut self, action: &Action, observation: &Observation, outcome: &str) {
        let mapped = observation
            .response
            .as_ref()
            .and_then(StunMessage::mapped_address);
        let other = observation
            .response
            .as_ref()
            .and_then(StunMessage::other_address);
        self.steps.push(crate::model::NatStep {
            index: self.steps.len() as u32 + 1,
            kind: action.kind,
            target: action.send_to.to_string(),
            change_ip: action.change_ip,
            change_port: action.change_port,
            responded: observation.response.is_some(),
            response_from: observation
                .response
                .as_ref()
                .map(|_| observation.source.to_string()),
            mapped_endpoint: mapped.map(|addr| addr.to_string()),
            changed_endpoint: other.map(|addr| addr.to_string()),
            rtt_ms: observation.response.as_ref().map(|_| observation.rtt_ms),
            outcome: outcome.to_string(),
        });
    }
}

/// Classic RFC 3489 combined NAT type discovery.
pub struct Rfc3489Discovery {
    /// Server endpoint the procedure starts with.
    server: SocketAddr,
    phase: Rfc3489Phase,
    /// Endpoint the server used for the first binding response.
    test1_source: Option<SocketAddr>,
    /// First reflexive address.
    mapped1: Option<SocketAddr>,
    /// Server's alternate endpoint from CHANGED-ADDRESS.
    changed: Option<SocketAddr>,
    /// State visible to the runner and UI.
    pub state: DiscoveryState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rfc3489Phase {
    Test1,
    Test2,
    Test1Second,
    Test3,
}

impl Rfc3489Discovery {
    /// Start a classic discovery run.
    pub fn new(server: SocketAddr) -> Self {
        Self {
            server,
            phase: Rfc3489Phase::Test1,
            test1_source: None,
            mapped1: None,
            changed: None,
            state: DiscoveryState::default(),
        }
    }

    /// First request to send.
    pub fn start(&mut self) -> Action {
        self.action(false, false)
    }

    /// Feed one observation and return the next request, if any.
    pub fn observe(
        &mut self,
        action: &Action,
        observation: Observation,
        local: SocketAddr,
    ) -> Option<Action> {
        match self.phase {
            Rfc3489Phase::Test1 => self.handle_test1(action, observation),
            Rfc3489Phase::Test2 => self.handle_test2(action, observation, local),
            Rfc3489Phase::Test1Second => self.handle_test1_second(action, observation),
            Rfc3489Phase::Test3 => self.handle_test3(action, observation),
        }
    }

    fn handle_test1(&mut self, action: &Action, observation: Observation) -> Option<Action> {
        let Some(response) = observation.response.as_ref() else {
            self.state.record(action, &observation, "no-response");
            self.state.finish(crate::model::NatType::UdpBlocked);
            return None;
        };
        let mapped = response.classic_mapped_address();
        let changed = response.changed_address();
        self.test1_source = Some(observation.source);
        self.mapped1 = mapped;
        self.changed = changed;
        self.state.public_endpoint = mapped;
        self.state.other_endpoint = changed;
        self.state.binding = crate::model::NatBindingResult::Success;

        // Without both attributes, or when the alternate endpoint is not
        // actually different, the server cannot support the classic procedure.
        let unsupported = mapped.is_none()
            || changed.is_none()
            || changed.is_some_and(|addr| {
                addr.ip() == observation.source.ip() || addr.port() == observation.source.port()
            });
        if unsupported {
            self.state
                .record(action, &observation, "unsupported-server");
            self.state.warning = Some("alternate-endpoint".into());
            self.state.finish(crate::model::NatType::UnsupportedServer);
            return None;
        }

        self.state.record(action, &observation, "mapped");
        self.phase = Rfc3489Phase::Test2;
        Some(self.action(true, true))
    }

    fn handle_test2(
        &mut self,
        action: &Action,
        observation: Observation,
        local: SocketAddr,
    ) -> Option<Action> {
        let public = self.mapped1;
        if observation.response.is_some() {
            // A response from the original endpoint means the server ignored
            // CHANGE-REQUEST, so the result would be misleading.
            if self.test1_source.is_some_and(|source| {
                source.ip() == observation.source.ip() || source.port() == observation.source.port()
            }) {
                self.state
                    .record(action, &observation, "unsupported-server");
                self.state.warning = Some("source-change".into());
                self.state.finish(crate::model::NatType::UnsupportedServer);
                return None;
            }

            self.state.record(action, &observation, "responded");
            let mapped = observation
                .response
                .as_ref()
                .and_then(StunMessage::classic_mapped_address);
            self.state.public_endpoint = mapped.or(public);
            if public == Some(local) {
                self.state.finish(crate::model::NatType::OpenInternet);
            } else {
                self.state.finish(crate::model::NatType::FullCone);
            }
            return None;
        }

        self.state.record(action, &observation, "no-response");
        if public == Some(local) {
            self.state
                .finish(crate::model::NatType::SymmetricUdpFirewall);
            return None;
        }

        // A timeout means the mapping is not endpoint-independent. Repeat the
        // binding test against the alternate endpoint to detect symmetric NAT.
        self.phase = Rfc3489Phase::Test1Second;
        Some(self.action_to(
            self.changed?,
            crate::model::NatStepKind::Rfc3489Test1Second,
            false,
            false,
        ))
    }

    fn handle_test1_second(&mut self, action: &Action, observation: Observation) -> Option<Action> {
        let mapped = observation
            .response
            .as_ref()
            .and_then(StunMessage::classic_mapped_address);
        if mapped.is_none() {
            self.state.record(action, &observation, "no-mapped-address");
            self.state.finish(crate::model::NatType::Unknown);
            return None;
        }

        if mapped != self.mapped1 {
            self.state.record(action, &observation, "mapping-changed");
            self.state.public_endpoint = mapped;
            self.state.finish(crate::model::NatType::Symmetric);
            return None;
        }

        self.state.record(action, &observation, "mapping-unchanged");
        self.phase = Rfc3489Phase::Test3;
        Some(self.action(false, true))
    }

    fn handle_test3(&mut self, action: &Action, observation: Observation) -> Option<Action> {
        let mapped = observation
            .response
            .as_ref()
            .and_then(StunMessage::classic_mapped_address);
        let restricted = mapped.is_some()
            && self.test1_source.is_some_and(|source| {
                observation.source.ip() == source.ip() && observation.source.port() != source.port()
            });
        if restricted {
            self.state
                .record(action, &observation, "alternate-port-response");
            if let Some(mapped) = mapped {
                self.state.public_endpoint = Some(mapped);
            }
            self.state.finish(crate::model::NatType::RestrictedCone);
        } else {
            self.state
                .record(action, &observation, "no-alternate-port-response");
            self.state.finish(crate::model::NatType::PortRestrictedCone);
        }
        None
    }

    fn action(&self, change_ip: bool, change_port: bool) -> Action {
        let kind = match self.phase {
            Rfc3489Phase::Test1 => crate::model::NatStepKind::Rfc3489Test1,
            Rfc3489Phase::Test2 => crate::model::NatStepKind::Rfc3489Test2,
            Rfc3489Phase::Test1Second => crate::model::NatStepKind::Rfc3489Test1Second,
            Rfc3489Phase::Test3 => crate::model::NatStepKind::Rfc3489Test3,
        };
        self.action_to(self.server, kind, change_ip, change_port)
    }

    fn action_to(
        &self,
        target: SocketAddr,
        kind: crate::model::NatStepKind,
        change_ip: bool,
        change_port: bool,
    ) -> Action {
        let change = (change_ip || change_port).then_some((change_ip, change_port));
        let transaction_id = new_transaction_id();
        Action {
            message: StunMessage::binding_request(0, transaction_id, change),
            send_to: target,
            kind,
            change_ip,
            change_port,
        }
    }
}

/// RFC 5780 mapping and filtering behavior discovery.
pub struct Rfc5780Discovery {
    /// Server endpoint the procedure starts with.
    server: SocketAddr,
    phase: Rfc5780Phase,
    /// Reflexive address from the binding test.
    mapped1: Option<SocketAddr>,
    /// Alternate server endpoint from OTHER-ADDRESS.
    other: Option<SocketAddr>,
    /// Local endpoint captured during the binding test.
    local: Option<SocketAddr>,
    /// Reflexive address from mapping test II.
    mapped2: Option<SocketAddr>,
    /// State visible to the runner and UI.
    pub state: DiscoveryState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rfc5780Phase {
    Binding,
    FilteringTest2,
    FilteringTest3,
    MappingTest2,
    MappingTest3,
}

impl Rfc5780Discovery {
    /// Start a behavior discovery run.
    pub fn new(server: SocketAddr) -> Self {
        Self {
            server,
            phase: Rfc5780Phase::Binding,
            mapped1: None,
            other: None,
            local: None,
            mapped2: None,
            state: DiscoveryState::default(),
        }
    }

    /// First request to send.
    pub fn start(&mut self) -> Action {
        self.action_to(
            self.server,
            crate::model::NatStepKind::Binding,
            false,
            false,
        )
    }

    /// Feed one observation and return the next request, if any.
    pub fn observe(
        &mut self,
        action: &Action,
        observation: Observation,
        local: SocketAddr,
    ) -> Option<Action> {
        match self.phase {
            Rfc5780Phase::Binding => self.handle_binding(action, observation, local),
            Rfc5780Phase::FilteringTest2 => self.handle_filtering_test2(action, observation),
            Rfc5780Phase::FilteringTest3 => self.handle_filtering_test3(action, observation),
            Rfc5780Phase::MappingTest2 => self.handle_mapping_test2(action, observation),
            Rfc5780Phase::MappingTest3 => self.handle_mapping_test3(action, observation),
        }
    }

    fn handle_binding(
        &mut self,
        action: &Action,
        observation: Observation,
        local: SocketAddr,
    ) -> Option<Action> {
        self.local = Some(local);
        let Some(response) = observation.response.as_ref() else {
            self.state.record(action, &observation, "no-response");
            self.state.binding = crate::model::NatBindingResult::Failed;
            self.state.finish(crate::model::NatType::UdpBlocked);
            return None;
        };

        let mapped = response.mapped_address();
        let other = response.other_address();
        self.mapped1 = mapped;
        self.other = other;
        self.state.public_endpoint = mapped;
        self.state.other_endpoint = other;

        if mapped.is_none() {
            self.state
                .record(action, &observation, "unsupported-server");
            self.state.binding = crate::model::NatBindingResult::UnsupportedServer;
            self.state.warning = Some("no-mapped".into());
            self.state.finish(crate::model::NatType::UnsupportedServer);
            return None;
        }

        self.state.binding = crate::model::NatBindingResult::Success;
        let valid_other = other
            .is_some_and(|addr| addr.ip() != self.server.ip() && addr.port() != self.server.port());
        if !valid_other {
            self.state
                .record(action, &observation, "unsupported-server");
            self.state.warning = Some("alternate-endpoint".into());
            self.state.finish(crate::model::NatType::Unknown);
            return None;
        }

        self.state.record(action, &observation, "mapped");
        self.phase = Rfc5780Phase::FilteringTest2;
        Some(self.action_to(
            self.server,
            crate::model::NatStepKind::FilteringTest2,
            true,
            true,
        ))
    }

    fn handle_filtering_test2(
        &mut self,
        action: &Action,
        observation: Observation,
    ) -> Option<Action> {
        if observation.response.is_some() {
            if self.other == Some(observation.source) {
                self.state.filtering = crate::model::NatFilteringBehavior::EndpointIndependent;
                self.state
                    .record(action, &observation, "alternate-endpoint-response");
            } else {
                self.state.filtering = crate::model::NatFilteringBehavior::UnsupportedServer;
                self.state.record(action, &observation, "unexpected-source");
                self.state.warning = Some("ignored-source-change".into());
                self.state.finish(crate::model::NatType::Unknown);
                return None;
            }
            return self.transition_to_mapping();
        }

        self.state.record(action, &observation, "no-response");
        self.phase = Rfc5780Phase::FilteringTest3;
        Some(self.action_to(
            self.server,
            crate::model::NatStepKind::FilteringTest3,
            false,
            true,
        ))
    }

    fn handle_filtering_test3(
        &mut self,
        action: &Action,
        observation: Observation,
    ) -> Option<Action> {
        if observation.response.is_none() {
            self.state.filtering = crate::model::NatFilteringBehavior::AddressAndPortDependent;
            self.state.record(action, &observation, "no-response");
        } else if observation.source.ip() == self.server.ip()
            && observation.source.port() != self.server.port()
        {
            self.state.filtering = crate::model::NatFilteringBehavior::AddressDependent;
            self.state
                .record(action, &observation, "alternate-port-response");
        } else {
            self.state.filtering = crate::model::NatFilteringBehavior::UnsupportedServer;
            self.state.record(action, &observation, "unexpected-source");
            self.state.warning = Some("ignored-port-change".into());
            self.state.finish(crate::model::NatType::Unknown);
            return None;
        }

        self.transition_to_mapping()
    }

    fn transition_to_mapping(&mut self) -> Option<Action> {
        let local = self.local?;
        if self.mapped1 == Some(local) {
            self.state.mapping = crate::model::NatMappingBehavior::Direct;
            self.finish_with_derived_type();
            return None;
        }

        let Some(other) = self.other else {
            self.state.mapping = crate::model::NatMappingBehavior::UnsupportedServer;
            self.state.finish(crate::model::NatType::Unknown);
            return None;
        };

        self.phase = Rfc5780Phase::MappingTest2;
        let target = SocketAddr::new(other.ip(), self.server.port());
        Some(self.action_to(
            target,
            crate::model::NatStepKind::MappingTest2,
            false,
            false,
        ))
    }

    fn handle_mapping_test2(
        &mut self,
        action: &Action,
        observation: Observation,
    ) -> Option<Action> {
        let mapped = observation
            .response
            .as_ref()
            .and_then(StunMessage::mapped_address);
        let Some(mapped) = mapped else {
            self.state.record(action, &observation, "no-mapped-address");
            self.state.mapping = crate::model::NatMappingBehavior::Failed;
            self.finish_with_derived_type();
            return None;
        };

        if Some(mapped) == self.mapped1 {
            self.state.record(action, &observation, "mapping-unchanged");
            self.state.mapping = crate::model::NatMappingBehavior::EndpointIndependent;
            self.finish_with_derived_type();
            return None;
        }

        self.state.record(action, &observation, "mapping-changed");
        self.mapped2 = Some(mapped);
        let Some(other) = self.other else {
            self.state.mapping = crate::model::NatMappingBehavior::Failed;
            self.finish_with_derived_type();
            return None;
        };

        self.phase = Rfc5780Phase::MappingTest3;
        Some(self.action_to(other, crate::model::NatStepKind::MappingTest3, false, false))
    }

    fn handle_mapping_test3(
        &mut self,
        action: &Action,
        observation: Observation,
    ) -> Option<Action> {
        let mapped = observation
            .response
            .as_ref()
            .and_then(StunMessage::mapped_address);
        match mapped {
            None => {
                self.state.record(action, &observation, "no-mapped-address");
                self.state.mapping = crate::model::NatMappingBehavior::Failed;
            }
            Some(mapped) if Some(mapped) == self.mapped2 => {
                self.state.record(action, &observation, "mapping-unchanged");
                self.state.mapping = crate::model::NatMappingBehavior::AddressDependent;
            }
            Some(_) => {
                self.state
                    .record(action, &observation, "mapping-changed-again");
                self.state.mapping = crate::model::NatMappingBehavior::AddressAndPortDependent;
            }
        }
        self.finish_with_derived_type();
        None
    }

    fn finish_with_derived_type(&mut self) {
        let nat_type = derive_nat_type(self.state.mapping, self.state.filtering);
        self.state.finish(nat_type);
    }

    fn action_to(
        &self,
        target: SocketAddr,
        kind: crate::model::NatStepKind,
        change_ip: bool,
        change_port: bool,
    ) -> Action {
        let change = (change_ip || change_port).then_some((change_ip, change_port));
        Action {
            message: StunMessage::binding_request(MAGIC_COOKIE, new_transaction_id(), change),
            send_to: target,
            kind,
            change_ip,
            change_port,
        }
    }
}

/// Combine mapping and filtering behavior into a user-facing NAT type.
pub fn derive_nat_type(
    mapping: crate::model::NatMappingBehavior,
    filtering: crate::model::NatFilteringBehavior,
) -> crate::model::NatType {
    use crate::model::{NatFilteringBehavior as F, NatMappingBehavior as M, NatType};
    match (mapping, filtering) {
        (M::Direct, F::EndpointIndependent) => NatType::OpenInternet,
        (M::Direct, F::AddressDependent | F::AddressAndPortDependent) => {
            NatType::SymmetricUdpFirewall
        }
        (M::EndpointIndependent, F::EndpointIndependent) => NatType::FullCone,
        (M::EndpointIndependent, F::AddressDependent) => NatType::RestrictedCone,
        (M::EndpointIndependent, F::AddressAndPortDependent) => NatType::PortRestrictedCone,
        (M::AddressDependent | M::AddressAndPortDependent, _) => NatType::Symmetric,
        _ => NatType::Unknown,
    }
}

/// Build a random transaction ID.
pub fn new_transaction_id() -> [u8; TRANSACTION_ID_LEN] {
    let mut id = [0u8; TRANSACTION_ID_LEN];
    if getrandom::fill(&mut id).is_ok() {
        return id;
    }

    // The OS random source is expected to work on supported platforms. The
    // fallback still keeps transactions distinct enough for a retry loop.
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    id[..8].copy_from_slice(&nanos.to_be_bytes());
    id[8..].copy_from_slice(&counter.to_be_bytes());
    id
}

/// Resolve the local bind string against the target address family.
fn parse_local_bind(target: SocketAddr, local_bind: &str) -> Result<SocketAddr, String> {
    let text = local_bind.trim();
    if text.is_empty() {
        return Ok(match target {
            SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
            SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
        });
    }

    let addr = if let Ok(addr) = text.parse::<SocketAddr>() {
        addr
    } else if let Ok(ip) = text.trim_matches(['[', ']']).parse::<IpAddr>() {
        SocketAddr::new(ip, 0)
    } else {
        return Err(format!("invalid local bind address: {text}"));
    };

    if addr.is_ipv4() != target.is_ipv4() {
        return Err("local bind address does not match the target address family".into());
    }
    Ok(addr)
}

/// Unified interface over the two discovery procedures.
enum Discovery {
    Classic(Rfc3489Discovery),
    Behavior(Rfc5780Discovery),
}

impl Discovery {
    fn start(&mut self) -> Action {
        match self {
            Discovery::Classic(discovery) => discovery.start(),
            Discovery::Behavior(discovery) => discovery.start(),
        }
    }

    fn observe(
        &mut self,
        action: &Action,
        observation: Observation,
        local: SocketAddr,
    ) -> Option<Action> {
        match self {
            Discovery::Classic(discovery) => discovery.observe(action, observation, local),
            Discovery::Behavior(discovery) => discovery.observe(action, observation, local),
        }
    }

    fn state(&self) -> &DiscoveryState {
        match self {
            Discovery::Classic(discovery) => &discovery.state,
            Discovery::Behavior(discovery) => &discovery.state,
        }
    }
}

/// Run a complete NAT discovery and stream steps and the final result.
pub async fn run_query(handle: &ProbeHandle<ProbeEvent>, settings: &NatSettings) {
    let started = std::time::Instant::now();
    let server_text = settings.server.trim().to_string();

    let (host, port) = match parse_server(&server_text) {
        Ok(parsed) => parsed,
        Err(message) => {
            handle.send(ProbeEvent::Error {
                message,
                hint: Some("use a host name, address, or host:port".into()),
            });
            handle.send(ProbeEvent::Finished);
            return;
        }
    };

    let ip = match crate::net::icmp::resolve_target(&host, settings.ip_version).await {
        Ok(ip) => ip,
        Err(message) => {
            handle.send(ProbeEvent::Error {
                message: format!("failed to resolve {host}: {message}"),
                hint: Some("check the server name and the selected IP version".into()),
            });
            handle.send(ProbeEvent::Finished);
            return;
        }
    };

    let target = SocketAddr::new(ip, port);
    let socket = match StunSocket::bind(target, &settings.local_bind).await {
        Ok(socket) => socket,
        Err(message) => {
            handle.send(ProbeEvent::Error {
                message,
                hint: Some("check the local bind address in the advanced settings".into()),
            });
            handle.send(ProbeEvent::Finished);
            return;
        }
    };
    // A wildcard bind reports an unspecified address, which is never equal to
    // the observed public endpoint even on a directly connected host. Replace
    // it with the target's address while keeping the ephemeral port.
    let mut local = socket.local_addr().unwrap_or_else(|| match target {
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
    });
    if local.ip().is_unspecified() {
        local.set_ip(target.ip());
    }

    let mut discovery = match settings.mode {
        crate::model::NatTestMode::Rfc3489 => Discovery::Classic(Rfc3489Discovery::new(target)),
        crate::model::NatTestMode::Rfc5780 => Discovery::Behavior(Rfc5780Discovery::new(target)),
    };
    let mut action = discovery.start();

    loop {
        if handle.is_cancelled() {
            break;
        }

        let request = socket.request(&action, settings.timeout_ms, settings.retries);
        let observation = tokio::select! {
            _ = handle.cancelled() => break,
            result = request => result,
        };

        let observation = match observation {
            Ok(observation) => observation,
            Err(message) => {
                handle.send(ProbeEvent::Error {
                    message,
                    hint: Some("check the local firewall and the selected IP version".into()),
                });
                handle.send(ProbeEvent::Finished);
                return;
            }
        };

        let next = discovery.observe(&action, observation, local);

        // The state machine records the step before deciding the next action,
        // so the latest entry can be streamed immediately.
        if let Some(step) = discovery.state().steps.last().cloned() {
            handle.send(ProbeEvent::NatStep(step));
        }

        match next {
            Some(next) => action = next,
            None => break,
        }
    }

    let state = discovery.state();
    if state.done {
        handle.send(ProbeEvent::Nat(NatResult {
            mode: settings.mode,
            server: server_text,
            local_endpoint: local.to_string(),
            public_endpoint: state.public_endpoint.map(|addr| addr.to_string()),
            other_endpoint: state.other_endpoint.map(|addr| addr.to_string()),
            nat_type: state.nat_type,
            binding: state.binding,
            mapping: state.mapping,
            filtering: state.filtering,
            steps: state.steps.clone(),
            elapsed_ms: started.elapsed().as_millis() as u64,
            warning: state.warning.clone(),
        }));
    }

    handle.send(ProbeEvent::Finished);
}

/// Parse `host`, `host:port`, `[IPv6]` or `[IPv6]:port` into a host and port.
fn parse_server(text: &str) -> Result<(String, u16), String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("STUN server is empty".into());
    }

    if let Some(rest) = text.strip_prefix('[') {
        let Some((host, after)) = rest.split_once(']') else {
            return Err(format!("invalid IPv6 STUN server: {text}"));
        };
        if host.parse::<Ipv6Addr>().is_err() {
            return Err(format!("invalid IPv6 STUN server: {text}"));
        }
        let port = if after.is_empty() {
            3478
        } else if let Some(port) = after.strip_prefix(':') {
            port.parse::<u16>()
                .map_err(|_| format!("invalid STUN server port: {text}"))?
        } else {
            return Err(format!("invalid STUN server: {text}"));
        };
        return Ok((host.to_string(), port));
    }

    // A single colon separates host and port. Multiple colons without brackets
    // are treated as a bare IPv6 address using the default port.
    if text.matches(':').count() == 1 {
        if let Some((host, port)) = text.rsplit_once(':') {
            if let Ok(port) = port.parse::<u16>() {
                if host.is_empty() {
                    return Err(format!("invalid STUN server: {text}"));
                }
                return Ok((host.to_string(), port));
            }
        }
    }

    if text.parse::<Ipv6Addr>().is_ok() || !text.contains(':') {
        return Ok((text.to_string(), 3478));
    }

    Err(format!("invalid STUN server: {text}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn txid() -> [u8; TRANSACTION_ID_LEN] {
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ]
    }

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 10], port))
    }

    fn v6(port: u16) -> SocketAddr {
        SocketAddr::from((
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            port,
        ))
    }

    #[test]
    fn binding_request_has_expected_header_and_change_request() {
        let message = StunMessage::binding_request(MAGIC_COOKIE, txid(), Some((true, true)));
        let bytes = message.encode();
        assert_eq!(&bytes[..2], &BINDING_REQUEST.to_be_bytes());
        assert_eq!(
            u16::from_be_bytes([bytes[2], bytes[3]]) as usize,
            bytes.len() - HEADER_LEN
        );
        assert_eq!(&bytes[4..8], &MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&bytes[8..20], &txid());

        let decoded = StunMessage::decode(&bytes).expect("decode request");
        assert_eq!(decoded, message);
        assert_eq!(
            decoded.attributes,
            vec![StunAttribute::ChangeRequest {
                change_ip: true,
                change_port: true
            }]
        );
    }

    #[test]
    fn xor_mapped_address_roundtrip_ipv4_and_ipv6() {
        for addr in [v4(12345), v6(54321)] {
            let message = StunMessage {
                message_type: BINDING_SUCCESS,
                cookie: MAGIC_COOKIE,
                transaction_id: txid(),
                attributes: vec![
                    StunAttribute::XorMappedAddress(addr),
                    StunAttribute::OtherAddress(v4(3479)),
                ],
            };
            let decoded = StunMessage::decode(&message.encode()).expect("decode response");
            assert_eq!(decoded.mapped_address(), Some(addr));
            assert_eq!(decoded.other_address(), Some(v4(3479)));
        }
    }

    #[test]
    fn classic_addresses_and_error_code_roundtrip() {
        let message = StunMessage {
            message_type: BINDING_SUCCESS,
            cookie: 0,
            transaction_id: txid(),
            attributes: vec![
                StunAttribute::MappedAddress(v4(1111)),
                StunAttribute::ChangedAddress(v6(2222)),
                StunAttribute::ErrorCode {
                    code: 401,
                    reason: "Unauthorized".into(),
                },
            ],
        };
        let decoded = StunMessage::decode(&message.encode()).expect("decode classic");
        assert_eq!(decoded.classic_mapped_address(), Some(v4(1111)));
        assert_eq!(decoded.changed_address(), Some(v6(2222)));
        assert_eq!(decoded.error(), Some((401, "Unauthorized".into())));
    }

    #[test]
    fn unknown_attributes_are_preserved_and_padding_is_skipped() {
        let message = StunMessage {
            message_type: BINDING_SUCCESS,
            cookie: MAGIC_COOKIE,
            transaction_id: txid(),
            attributes: vec![
                StunAttribute::Unknown {
                    kind: 0x8022,
                    value: b"agent".to_vec(),
                },
                StunAttribute::Unknown {
                    kind: 0x8028,
                    value: vec![1, 2, 3, 4],
                },
                StunAttribute::XorMappedAddress(v4(3478)),
            ],
        };
        let decoded = StunMessage::decode(&message.encode()).expect("decode unknown attrs");
        assert_eq!(decoded.attributes, message.attributes);
        assert_eq!(decoded.mapped_address(), Some(v4(3478)));
    }

    #[test]
    fn truncated_messages_are_rejected() {
        assert!(StunMessage::decode(&[0u8; HEADER_LEN - 1]).is_none());

        let message = StunMessage::binding_request(MAGIC_COOKIE, txid(), None);
        let mut bytes = message.encode();
        bytes.truncate(HEADER_LEN - 1);
        assert!(StunMessage::decode(&bytes).is_none());

        let mut bytes = message.encode();
        // Claim more bytes than the datagram actually carries.
        bytes[2..4].copy_from_slice(&100u16.to_be_bytes());
        assert!(StunMessage::decode(&bytes).is_none());
    }

    #[test]
    fn transaction_matching_compares_cookie_and_id() {
        let message = StunMessage::binding_request(MAGIC_COOKIE, txid(), None);
        assert!(message.matches_transaction(MAGIC_COOKIE, &txid()));
        assert!(!message.matches_transaction(0, &txid()));
        let mut other = txid();
        other[0] ^= 0xff;
        assert!(!message.matches_transaction(MAGIC_COOKIE, &other));
    }
    #[tokio::test]
    async fn udp_transaction_returns_matching_response() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = StunSocket::bind(server_addr, "").await.unwrap();

        let request = StunMessage::binding_request(MAGIC_COOKIE, txid(), None);
        let response = StunMessage::binding_success(
            MAGIC_COOKIE,
            txid(),
            vec![StunAttribute::XorMappedAddress(v4(5000))],
        );
        let response_bytes = response.encode();

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (_, peer) = server.recv_from(&mut buf).await.unwrap();
            server.send_to(&response_bytes, peer).await.unwrap();
        });

        let action = Action {
            message: request,
            send_to: server_addr,
            kind: crate::model::NatStepKind::Binding,
            change_ip: false,
            change_port: false,
        };
        let observation = client.request(&action, 1000, 1).await.unwrap();
        server_task.await.unwrap();
        assert_eq!(observation.source, server_addr);
        assert_eq!(
            observation.response.unwrap().mapped_address(),
            Some(v4(5000))
        );
        assert!(observation.rtt_ms >= 0.0);
    }

    #[tokio::test]
    async fn udp_transaction_ignores_wrong_transaction_and_times_out() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = StunSocket::bind(server_addr, "").await.unwrap();

        let request = StunMessage::binding_request(MAGIC_COOKIE, txid(), None);
        let mut wrong_id = txid();
        wrong_id[0] ^= 0xff;
        let wrong = StunMessage::binding_success(
            MAGIC_COOKIE,
            wrong_id,
            vec![StunAttribute::XorMappedAddress(v4(5000))],
        )
        .encode();

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (_, peer) = server.recv_from(&mut buf).await.unwrap();
            server.send_to(&wrong, peer).await.unwrap();
        });

        let action = Action {
            message: request,
            send_to: server_addr,
            kind: crate::model::NatStepKind::Binding,
            change_ip: false,
            change_port: false,
        };
        let observation = client.request(&action, 30, 0).await.unwrap();
        server_task.await.unwrap();
        assert!(observation.response.is_none());
        assert_eq!(observation.source, server_addr);
    }

    #[tokio::test]
    async fn local_bind_validation_matches_family() {
        let v4_target = SocketAddr::from(([127, 0, 0, 1], 3478));
        assert_eq!(
            parse_local_bind(v4_target, "").unwrap(),
            SocketAddr::from(([0, 0, 0, 0], 0))
        );
        assert_eq!(
            parse_local_bind(v4_target, "127.0.0.1:1234").unwrap(),
            SocketAddr::from(([127, 0, 0, 1], 1234))
        );
        assert!(parse_local_bind(v4_target, "[::1]:0").is_err());
        assert!(parse_local_bind(v4_target, "not-an-address").is_err());
    }

    fn classic_response(mapped: Option<SocketAddr>, changed: Option<SocketAddr>) -> StunMessage {
        let mut attrs = Vec::new();
        if let Some(mapped) = mapped {
            attrs.push(StunAttribute::MappedAddress(mapped));
        }
        if let Some(changed) = changed {
            attrs.push(StunAttribute::ChangedAddress(changed));
        }
        StunMessage::binding_success(0, txid(), attrs)
    }

    fn observation(response: Option<StunMessage>, source: SocketAddr) -> Observation {
        Observation {
            response,
            source,
            rtt_ms: 1.0,
        }
    }

    fn classic_server() -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 1], 3478))
    }

    fn classic_changed() -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 2], 3479))
    }

    fn classic_local() -> SocketAddr {
        SocketAddr::from(([10, 0, 0, 10], 40000))
    }

    #[test]
    fn classic_detects_udp_blocked_and_unsupported_server() {
        let mut discovery = Rfc3489Discovery::new(classic_server());
        let action = discovery.start();
        assert!(discovery
            .observe(
                &action,
                observation(None, classic_server()),
                classic_local()
            )
            .is_none());
        assert_eq!(discovery.state.nat_type, crate::model::NatType::UdpBlocked);

        let mut discovery = Rfc3489Discovery::new(classic_server());
        let action = discovery.start();
        let response = classic_response(Some(classic_local()), None);
        assert!(discovery
            .observe(
                &action,
                observation(Some(response), classic_server()),
                classic_local()
            )
            .is_none());
        assert_eq!(
            discovery.state.nat_type,
            crate::model::NatType::UnsupportedServer
        );
    }

    #[test]
    fn classic_detects_open_internet_and_full_cone() {
        for (local, expected) in [
            (classic_local(), crate::model::NatType::OpenInternet),
            (
                SocketAddr::from(([10, 0, 0, 11], 40000)),
                crate::model::NatType::FullCone,
            ),
        ] {
            let mut discovery = Rfc3489Discovery::new(classic_server());
            // For Open Internet the reported mapping equals the local endpoint;
            // for Full Cone it differs, so the same first response is used with
            // a different local address.
            let action = discovery.start();
            let mapped = if expected == crate::model::NatType::OpenInternet {
                local
            } else {
                SocketAddr::from(([203, 0, 113, 5], 50000))
            };
            let response = classic_response(Some(mapped), Some(classic_changed()));
            let action = discovery
                .observe(
                    &action,
                    observation(Some(response), classic_server()),
                    local,
                )
                .expect("test 2 action");
            let response = classic_response(Some(mapped), None);
            discovery.observe(
                &action,
                observation(Some(response), classic_changed()),
                local,
            );
            assert_eq!(discovery.state.nat_type, expected);
        }
    }

    #[test]
    fn classic_detects_symmetric_udp_firewall_and_symmetric() {
        // Public mapping equals the local endpoint but the alternate endpoint
        // does not answer: the host is directly reachable but filtered.
        let mut discovery = Rfc3489Discovery::new(classic_server());
        let local = classic_local();
        let action = discovery.start();
        let response = classic_response(Some(local), Some(classic_changed()));
        let action = discovery
            .observe(
                &action,
                observation(Some(response), classic_server()),
                local,
            )
            .unwrap();
        assert!(discovery
            .observe(&action, observation(None, classic_changed()), local)
            .is_none());
        assert_eq!(
            discovery.state.nat_type,
            crate::model::NatType::SymmetricUdpFirewall
        );

        // A different mapping when the destination changes indicates a
        // symmetric NAT.
        let mut discovery = Rfc3489Discovery::new(classic_server());
        let action = discovery.start();
        let mapped = SocketAddr::from(([203, 0, 113, 5], 50000));
        let response = classic_response(Some(mapped), Some(classic_changed()));
        let action = discovery
            .observe(
                &action,
                observation(Some(response), classic_server()),
                local,
            )
            .unwrap();
        let action = discovery
            .observe(&action, observation(None, classic_changed()), local)
            .expect("test 1 second action");
        let other = SocketAddr::from(([203, 0, 113, 5], 50001));
        let response = classic_response(Some(other), None);
        assert!(discovery
            .observe(
                &action,
                observation(Some(response), classic_changed()),
                local
            )
            .is_none());
        assert_eq!(discovery.state.nat_type, crate::model::NatType::Symmetric);
    }

    #[test]
    fn classic_detects_restricted_and_port_restricted_cone() {
        let local = classic_local();
        let mapped = SocketAddr::from(([203, 0, 113, 5], 50000));

        let run_to_test3 = || {
            let mut discovery = Rfc3489Discovery::new(classic_server());
            let action = discovery.start();
            let response = classic_response(Some(mapped), Some(classic_changed()));
            let action = discovery
                .observe(
                    &action,
                    observation(Some(response), classic_server()),
                    local,
                )
                .unwrap();
            let action = discovery
                .observe(&action, observation(None, classic_changed()), local)
                .expect("test 1 second action");
            let response = classic_response(Some(mapped), None);
            let action = discovery
                .observe(
                    &action,
                    observation(Some(response), classic_changed()),
                    local,
                )
                .expect("test 3 action");
            (discovery, action)
        };

        let (mut discovery, action) = run_to_test3();
        let response = classic_response(Some(mapped), None);
        let source = SocketAddr::from(([192, 0, 2, 1], 3479));
        discovery.observe(&action, observation(Some(response), source), local);
        assert_eq!(
            discovery.state.nat_type,
            crate::model::NatType::RestrictedCone
        );

        let (mut discovery, action) = run_to_test3();
        discovery.observe(&action, observation(None, classic_server()), local);
        assert_eq!(
            discovery.state.nat_type,
            crate::model::NatType::PortRestrictedCone
        );
    }

    #[test]
    fn classic_reports_unknown_when_alternate_server_returns_no_mapping() {
        let local = classic_local();
        let mapped = SocketAddr::from(([203, 0, 113, 5], 50000));
        let mut discovery = Rfc3489Discovery::new(classic_server());
        let action = discovery.start();
        let response = classic_response(Some(mapped), Some(classic_changed()));
        let action = discovery
            .observe(
                &action,
                observation(Some(response), classic_server()),
                local,
            )
            .unwrap();
        let action = discovery
            .observe(&action, observation(None, classic_changed()), local)
            .expect("test 1 second action");
        let response = classic_response(None, None);
        discovery.observe(
            &action,
            observation(Some(response), classic_changed()),
            local,
        );
        assert_eq!(discovery.state.nat_type, crate::model::NatType::Unknown);
    }

    fn behavior_response(mapped: Option<SocketAddr>, other: Option<SocketAddr>) -> StunMessage {
        let mut attrs = Vec::new();
        if let Some(mapped) = mapped {
            attrs.push(StunAttribute::XorMappedAddress(mapped));
        }
        if let Some(other) = other {
            attrs.push(StunAttribute::OtherAddress(other));
        }
        StunMessage::binding_success(MAGIC_COOKIE, txid(), attrs)
    }

    fn behavior_server() -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 1], 3478))
    }

    fn behavior_other() -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 2], 3479))
    }

    fn behavior_local() -> SocketAddr {
        SocketAddr::from(([10, 0, 0, 10], 40000))
    }

    fn behavior_public() -> SocketAddr {
        SocketAddr::from(([203, 0, 113, 5], 50000))
    }

    fn start_behavior(local: SocketAddr) -> (Rfc5780Discovery, Action) {
        let mut discovery = Rfc5780Discovery::new(behavior_server());
        let action = discovery.start();
        let response = behavior_response(Some(behavior_public()), Some(behavior_other()));
        let action = discovery
            .observe(
                &action,
                observation(Some(response), behavior_server()),
                local,
            )
            .expect("filtering test II action");
        (discovery, action)
    }

    #[test]
    fn behavior_detects_endpoint_independent_filtering_and_mapping() {
        let local = behavior_local();
        let (mut discovery, action) = start_behavior(local);
        let response = behavior_response(Some(behavior_public()), None);
        let action = discovery
            .observe(
                &action,
                observation(Some(response), behavior_other()),
                local,
            )
            .expect("mapping test II action");
        assert_eq!(
            discovery.state.filtering,
            crate::model::NatFilteringBehavior::EndpointIndependent
        );

        let response = behavior_response(Some(behavior_public()), None);
        discovery.observe(
            &action,
            observation(Some(response), behavior_other()),
            local,
        );
        assert_eq!(
            discovery.state.mapping,
            crate::model::NatMappingBehavior::EndpointIndependent
        );
        assert_eq!(discovery.state.nat_type, crate::model::NatType::FullCone);
    }

    #[test]
    fn behavior_detects_address_dependent_and_port_dependent_filtering() {
        let local = behavior_local();

        let (mut discovery, action) = start_behavior(local);
        // Filtering test II times out; test III is answered from another port
        // on the same server address.
        let action = discovery
            .observe(&action, observation(None, behavior_server()), local)
            .expect("filtering test III action");
        let response = behavior_response(Some(behavior_public()), None);
        let action = discovery
            .observe(
                &action,
                observation(Some(response), SocketAddr::from(([192, 0, 2, 1], 3479))),
                local,
            )
            .expect("mapping test II action");
        assert_eq!(
            discovery.state.filtering,
            crate::model::NatFilteringBehavior::AddressDependent
        );
        let response = behavior_response(Some(behavior_public()), None);
        discovery.observe(
            &action,
            observation(Some(response), behavior_other()),
            local,
        );
        assert_eq!(
            discovery.state.nat_type,
            crate::model::NatType::RestrictedCone
        );

        let (mut discovery, action) = start_behavior(local);
        let action = discovery
            .observe(&action, observation(None, behavior_server()), local)
            .expect("filtering test III action");
        let action = discovery
            .observe(&action, observation(None, behavior_server()), local)
            .expect("mapping test II action");
        assert_eq!(
            discovery.state.filtering,
            crate::model::NatFilteringBehavior::AddressAndPortDependent
        );
        let response = behavior_response(Some(behavior_public()), None);
        discovery.observe(
            &action,
            observation(Some(response), behavior_other()),
            local,
        );
        assert_eq!(
            discovery.state.nat_type,
            crate::model::NatType::PortRestrictedCone
        );
    }

    #[test]
    fn behavior_detects_symmetric_mapping() {
        let local = behavior_local();
        let (mut discovery, action) = start_behavior(local);
        let action = discovery
            .observe(&action, observation(None, behavior_server()), local)
            .expect("filtering test III action");
        let action = discovery
            .observe(&action, observation(None, behavior_server()), local)
            .expect("mapping test II action");
        let mapped2 = SocketAddr::from(([203, 0, 113, 5], 50001));
        let response = behavior_response(Some(mapped2), None);
        let action = discovery
            .observe(
                &action,
                observation(Some(response), behavior_other()),
                local,
            )
            .expect("mapping test III action");

        // A different mapping for the full alternate endpoint indicates
        // address and port-dependent mapping.
        let mapped3 = SocketAddr::from(([203, 0, 113, 5], 50002));
        let response = behavior_response(Some(mapped3), None);
        discovery.observe(
            &action,
            observation(Some(response), behavior_other()),
            local,
        );
        assert_eq!(
            discovery.state.mapping,
            crate::model::NatMappingBehavior::AddressAndPortDependent
        );
        assert_eq!(discovery.state.nat_type, crate::model::NatType::Symmetric);

        // The same mapping for both alternate targets indicates address-
        // dependent mapping.
        let (mut discovery, action) = start_behavior(local);
        let action = discovery
            .observe(&action, observation(None, behavior_server()), local)
            .expect("filtering test III action");
        let action = discovery
            .observe(&action, observation(None, behavior_server()), local)
            .expect("mapping test II action");
        let response = behavior_response(Some(mapped2), None);
        let action = discovery
            .observe(
                &action,
                observation(Some(response), behavior_other()),
                local,
            )
            .expect("mapping test III action");
        let response = behavior_response(Some(mapped2), None);
        discovery.observe(
            &action,
            observation(Some(response), behavior_other()),
            local,
        );
        assert_eq!(
            discovery.state.mapping,
            crate::model::NatMappingBehavior::AddressDependent
        );
        assert_eq!(discovery.state.nat_type, crate::model::NatType::Symmetric);
    }

    #[test]
    fn behavior_detects_direct_mapping_and_firewall() {
        // Direct mapping + endpoint-independent filtering is an open internet
        // connection.
        let local = behavior_local();
        let mut discovery = Rfc5780Discovery::new(behavior_server());
        let action = discovery.start();
        let response = behavior_response(Some(local), Some(behavior_other()));
        let action = discovery
            .observe(
                &action,
                observation(Some(response), behavior_server()),
                local,
            )
            .expect("filtering test II action");
        let response = behavior_response(Some(local), None);
        discovery.observe(
            &action,
            observation(Some(response), behavior_other()),
            local,
        );
        assert_eq!(
            discovery.state.mapping,
            crate::model::NatMappingBehavior::Direct
        );
        assert_eq!(
            discovery.state.nat_type,
            crate::model::NatType::OpenInternet
        );

        // Direct mapping with address and port-dependent filtering is a host
        // behind a firewall rather than a NAT.
        let mut discovery = Rfc5780Discovery::new(behavior_server());
        let action = discovery.start();
        let response = behavior_response(Some(local), Some(behavior_other()));
        let action = discovery
            .observe(
                &action,
                observation(Some(response), behavior_server()),
                local,
            )
            .expect("filtering test II action");
        let action = discovery
            .observe(&action, observation(None, behavior_server()), local)
            .expect("filtering test III action");
        discovery.observe(&action, observation(None, behavior_server()), local);
        assert_eq!(
            discovery.state.nat_type,
            crate::model::NatType::SymmetricUdpFirewall
        );
    }

    #[test]
    fn behavior_handles_binding_failures_and_unsupported_servers() {
        let local = behavior_local();
        let mut discovery = Rfc5780Discovery::new(behavior_server());
        let action = discovery.start();
        discovery.observe(&action, observation(None, behavior_server()), local);
        assert_eq!(
            discovery.state.binding,
            crate::model::NatBindingResult::Failed
        );
        assert_eq!(discovery.state.nat_type, crate::model::NatType::UdpBlocked);

        let mut discovery = Rfc5780Discovery::new(behavior_server());
        let action = discovery.start();
        let response = behavior_response(None, Some(behavior_other()));
        discovery.observe(
            &action,
            observation(Some(response), behavior_server()),
            local,
        );
        assert_eq!(
            discovery.state.binding,
            crate::model::NatBindingResult::UnsupportedServer
        );
        assert_eq!(
            discovery.state.nat_type,
            crate::model::NatType::UnsupportedServer
        );

        // A server advertising the same address or port is not usable for the
        // behavior procedure.
        let mut discovery = Rfc5780Discovery::new(behavior_server());
        let action = discovery.start();
        let response = behavior_response(
            Some(behavior_public()),
            Some(SocketAddr::from(([192, 0, 2, 1], 3479))),
        );
        discovery.observe(
            &action,
            observation(Some(response), behavior_server()),
            local,
        );
        assert_eq!(discovery.state.nat_type, crate::model::NatType::Unknown);
        assert!(discovery.state.warning.is_some());

        // Filtering test II answered from an unexpected source is unsupported.
        let (mut discovery, action) = start_behavior(local);
        let response = behavior_response(Some(behavior_public()), None);
        let source = SocketAddr::from(([198, 51, 100, 1], 3478));
        discovery.observe(&action, observation(Some(response), source), local);
        assert_eq!(
            discovery.state.filtering,
            crate::model::NatFilteringBehavior::UnsupportedServer
        );
        assert_eq!(discovery.state.nat_type, crate::model::NatType::Unknown);
    }

    #[test]
    fn behavior_mapping_failure_is_reported_as_unknown() {
        let local = behavior_local();
        let (mut discovery, action) = start_behavior(local);
        let action = discovery
            .observe(&action, observation(None, behavior_server()), local)
            .expect("filtering test III action");
        let action = discovery
            .observe(&action, observation(None, behavior_server()), local)
            .expect("mapping test II action");
        discovery.observe(&action, observation(None, behavior_other()), local);
        assert_eq!(
            discovery.state.mapping,
            crate::model::NatMappingBehavior::Failed
        );
        assert_eq!(discovery.state.nat_type, crate::model::NatType::Unknown);
    }

    #[test]
    fn nat_type_derivation_covers_all_behavior_combinations() {
        use crate::model::{NatFilteringBehavior as F, NatMappingBehavior as M, NatType};
        let cases = [
            ((M::Direct, F::EndpointIndependent), NatType::OpenInternet),
            (
                (M::Direct, F::AddressDependent),
                NatType::SymmetricUdpFirewall,
            ),
            (
                (M::Direct, F::AddressAndPortDependent),
                NatType::SymmetricUdpFirewall,
            ),
            (
                (M::EndpointIndependent, F::EndpointIndependent),
                NatType::FullCone,
            ),
            (
                (M::EndpointIndependent, F::AddressDependent),
                NatType::RestrictedCone,
            ),
            (
                (M::EndpointIndependent, F::AddressAndPortDependent),
                NatType::PortRestrictedCone,
            ),
            (
                (M::AddressDependent, F::EndpointIndependent),
                NatType::Symmetric,
            ),
            (
                (M::AddressAndPortDependent, F::EndpointIndependent),
                NatType::Symmetric,
            ),
            ((M::Unknown, F::Unknown), NatType::Unknown),
            ((M::Failed, F::EndpointIndependent), NatType::Unknown),
            (
                (M::EndpointIndependent, F::UnsupportedServer),
                NatType::Unknown,
            ),
        ];
        for ((mapping, filtering), expected) in cases {
            assert_eq!(derive_nat_type(mapping, filtering), expected);
        }
    }

    #[test]
    fn server_parsing_handles_hosts_and_ipv6() {
        assert_eq!(
            parse_server("stun.example.org").unwrap(),
            ("stun.example.org".to_string(), 3478)
        );
        assert_eq!(
            parse_server("stun.example.org:1234").unwrap(),
            ("stun.example.org".to_string(), 1234)
        );
        assert_eq!(
            parse_server("192.0.2.1:3479").unwrap(),
            ("192.0.2.1".to_string(), 3479)
        );
        assert_eq!(
            parse_server("[2001:db8::1]:3478").unwrap(),
            ("2001:db8::1".to_string(), 3478)
        );
        assert_eq!(
            parse_server("2001:db8::1").unwrap(),
            ("2001:db8::1".to_string(), 3478)
        );
        assert!(parse_server("").is_err());
        assert!(parse_server("[::1").is_err());
        assert!(parse_server("host:not-a-port").is_err());
    }
}
