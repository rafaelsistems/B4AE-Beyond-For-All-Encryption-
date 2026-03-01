//! Protocol state machine for B4AE v2.0
//!
//! This module implements the protocol state machine that enforces correct
//! message ordering and prevents invalid state transitions.
//!
//! ## States
//!
//! 1. **INIT**: Initial state before any messages
//! 2. **MODE_NEGOTIATION**: After ModeNegotiation sent/received
//! 3. **COOKIE_CHALLENGE**: After CookieChallenge sent/received
//! 4. **HANDSHAKE**: During HandshakeInit/Response/Complete exchange
//! 5. **ESTABLISHED**: After successful handshake, ready for encrypted communication
//! 6. **TERMINATED**: Session ended
//!
//! ## State Transitions
//!
//! ```text
//! INIT -> MODE_NEGOTIATION -> COOKIE_CHALLENGE -> HANDSHAKE -> ESTABLISHED -> TERMINATED
//! ```
//!
//! ## Security Properties
//!
//! - Enforces correct message ordering
//! - Rejects messages in invalid states
//! - Provides clear error messages for debugging
//! - Supports both client and server perspectives
//!
//! **Requirement**: REQ-47 (Protocol State Machine Requirements)

use std::fmt;

/// Protocol state for B4AE v2.0 handshake
///
/// The state machine enforces the correct ordering of protocol messages
/// and prevents invalid state transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolState {
    /// Initial state before any messages
    ///
    /// **Valid transitions**:
    /// - Client: Send ModeNegotiation -> MODE_NEGOTIATION
    /// - Server: Receive ModeNegotiation -> MODE_NEGOTIATION
    Init,

    /// Mode negotiation in progress
    ///
    /// **Valid transitions**:
    /// - Client: Receive ModeSelection -> COOKIE_CHALLENGE (send ClientHello)
    /// - Server: Send ModeSelection -> COOKIE_CHALLENGE (wait for ClientHello)
    ModeNegotiation,

    /// Cookie challenge in progress
    ///
    /// **Valid transitions**:
    /// - Client: Receive CookieChallenge -> COOKIE_CHALLENGE (send ClientHelloWithCookie)
    /// - Server: Send CookieChallenge -> COOKIE_CHALLENGE (wait for ClientHelloWithCookie)
    /// - Client: Send ClientHelloWithCookie -> HANDSHAKE
    /// - Server: Receive ClientHelloWithCookie -> HANDSHAKE
    CookieChallenge,

    /// Handshake in progress
    ///
    /// **Valid transitions**:
    /// - Client: Send HandshakeInit -> HANDSHAKE (wait for HandshakeResponse)
    /// - Server: Receive HandshakeInit -> HANDSHAKE (send HandshakeResponse)
    /// - Client: Receive HandshakeResponse -> HANDSHAKE (send HandshakeComplete)
    /// - Server: Send HandshakeResponse -> HANDSHAKE (wait for HandshakeComplete)
    /// - Server: Receive HandshakeComplete -> ESTABLISHED
    /// - Client: Send HandshakeComplete -> ESTABLISHED
    Handshake,

    /// Session established, ready for encrypted communication
    ///
    /// **Valid transitions**:
    /// - Both: Send/receive encrypted messages -> ESTABLISHED
    /// - Both: Terminate session -> TERMINATED
    Established,

    /// Session terminated
    ///
    /// **Valid transitions**: None (terminal state)
    Terminated,
}

impl ProtocolState {
    /// Returns true if this is a terminal state (no further transitions allowed)
    pub fn is_terminal(&self) -> bool {
        matches!(self, ProtocolState::Terminated)
    }

    /// Returns true if this state allows encrypted message exchange
    pub fn allows_encrypted_messages(&self) -> bool {
        matches!(self, ProtocolState::Established)
    }

    /// Returns a human-readable description of this state
    pub fn description(&self) -> &'static str {
        match self {
            ProtocolState::Init => "Initial state, waiting for mode negotiation",
            ProtocolState::ModeNegotiation => "Mode negotiation in progress",
            ProtocolState::CookieChallenge => "Cookie challenge in progress",
            ProtocolState::Handshake => "Handshake in progress",
            ProtocolState::Established => "Session established, ready for encrypted communication",
            ProtocolState::Terminated => "Session terminated",
        }
    }
}

impl fmt::Display for ProtocolState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolState::Init => write!(f, "INIT"),
            ProtocolState::ModeNegotiation => write!(f, "MODE_NEGOTIATION"),
            ProtocolState::CookieChallenge => write!(f, "COOKIE_CHALLENGE"),
            ProtocolState::Handshake => write!(f, "HANDSHAKE"),
            ProtocolState::Established => write!(f, "ESTABLISHED"),
            ProtocolState::Terminated => write!(f, "TERMINATED"),
        }
    }
}

/// Message type for state machine validation
///
/// Represents the different types of messages that can be sent/received
/// during the protocol handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// Mode negotiation message (client -> server)
    ModeNegotiation,
    
    /// Mode selection message (server -> client)
    ModeSelection,
    
    /// Client hello message (client -> server)
    ClientHello,
    
    /// Cookie challenge message (server -> client)
    CookieChallenge,
    
    /// Client hello with cookie message (client -> server)
    ClientHelloWithCookie,
    
    /// Handshake init message (client -> server)
    HandshakeInit,
    
    /// Handshake response message (server -> client)
    HandshakeResponse,
    
    /// Handshake complete message (client -> server)
    HandshakeComplete,
    
    /// Encrypted message (bidirectional)
    EncryptedMessage,
    
    /// Session termination message (bidirectional)
    Terminate,
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageType::ModeNegotiation => write!(f, "ModeNegotiation"),
            MessageType::ModeSelection => write!(f, "ModeSelection"),
            MessageType::ClientHello => write!(f, "ClientHello"),
            MessageType::CookieChallenge => write!(f, "CookieChallenge"),
            MessageType::ClientHelloWithCookie => write!(f, "ClientHelloWithCookie"),
            MessageType::HandshakeInit => write!(f, "HandshakeInit"),
            MessageType::HandshakeResponse => write!(f, "HandshakeResponse"),
            MessageType::HandshakeComplete => write!(f, "HandshakeComplete"),
            MessageType::EncryptedMessage => write!(f, "EncryptedMessage"),
            MessageType::Terminate => write!(f, "Terminate"),
        }
    }
}

/// Role in the protocol (client or server)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Client (initiator)
    Client,
    
    /// Server (responder)
    Server,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::Client => write!(f, "Client"),
            Role::Server => write!(f, "Server"),
        }
    }
}

/// State machine error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateMachineError {
    /// Message received in invalid state
    InvalidStateForMessage {
        current_state: ProtocolState,
        message_type: MessageType,
        role: Role,
    },
    
    /// Attempted to send message in invalid state
    InvalidStateForSend {
        current_state: ProtocolState,
        message_type: MessageType,
        role: Role,
    },
    
    /// State transition not allowed
    InvalidTransition {
        from_state: ProtocolState,
        to_state: ProtocolState,
        role: Role,
    },
    
    /// Session already terminated
    SessionTerminated,
    
    /// State machine invariant violated
    InvariantViolation {
        description: String,
    },
}

impl fmt::Display for StateMachineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StateMachineError::InvalidStateForMessage { current_state, message_type, role } => {
                write!(
                    f,
                    "{} cannot receive {} in state {}",
                    role, message_type, current_state
                )
            }
            StateMachineError::InvalidStateForSend { current_state, message_type, role } => {
                write!(
                    f,
                    "{} cannot send {} in state {}",
                    role, message_type, current_state
                )
            }
            StateMachineError::InvalidTransition { from_state, to_state, role } => {
                write!(
                    f,
                    "{} cannot transition from {} to {}",
                    role, from_state, to_state
                )
            }
            StateMachineError::SessionTerminated => {
                write!(f, "Session is terminated, no further operations allowed")
            }
            StateMachineError::InvariantViolation { description } => {
                write!(f, "State machine invariant violated: {}", description)
            }
        }
    }
}

impl std::error::Error for StateMachineError {}

/// Protocol state machine
///
/// Manages protocol state and enforces valid state transitions.
///
/// ## Example
///
/// ```rust,ignore
/// use b4ae::protocol::v2::state_machine::{StateMachine, Role, MessageType};
///
/// // Create client state machine
/// let mut client = StateMachine::new(Role::Client);
///
/// // Client sends mode negotiation
/// client.on_send(MessageType::ModeNegotiation).unwrap();
///
/// // Client receives mode selection
/// client.on_receive(MessageType::ModeSelection).unwrap();
///
/// // Continue handshake...
/// ```
#[derive(Debug, Clone)]
pub struct StateMachine {
    /// Current protocol state
    state: ProtocolState,
    
    /// Role (client or server)
    role: Role,
    
    /// Number of state transitions (for debugging)
    transition_count: u64,
}

impl StateMachine {
    /// Creates a new state machine in INIT state
    pub fn new(role: Role) -> Self {
        StateMachine {
            state: ProtocolState::Init,
            role,
            transition_count: 0,
        }
    }

    /// Returns the current protocol state
    pub fn state(&self) -> ProtocolState {
        self.state
    }

    /// Returns the role (client or server)
    pub fn role(&self) -> Role {
        self.role
    }

    /// Returns the number of state transitions
    pub fn transition_count(&self) -> u64 {
        self.transition_count
    }

    /// Checks if a message can be received in the current state
    pub fn can_receive(&self, message_type: MessageType) -> bool {
        self.validate_receive(message_type).is_ok()
    }

    /// Checks if a message can be sent in the current state
    pub fn can_send(&self, message_type: MessageType) -> bool {
        self.validate_send(message_type).is_ok()
    }

    /// Validates that a message can be received in the current state
    pub fn validate_receive(&self, message_type: MessageType) -> Result<(), StateMachineError> {
        if self.state.is_terminal() {
            return Err(StateMachineError::SessionTerminated);
        }

        match (self.role, self.state, message_type) {
            // INIT state
            (Role::Server, ProtocolState::Init, MessageType::ModeNegotiation) => Ok(()),
            
            // MODE_NEGOTIATION state
            (Role::Client, ProtocolState::ModeNegotiation, MessageType::ModeSelection) => Ok(()),
            
            // COOKIE_CHALLENGE state
            (Role::Client, ProtocolState::CookieChallenge, MessageType::CookieChallenge) => Ok(()),
            (Role::Server, ProtocolState::CookieChallenge, MessageType::ClientHelloWithCookie) => Ok(()),
            
            // HANDSHAKE state
            (Role::Server, ProtocolState::Handshake, MessageType::HandshakeInit) => Ok(()),
            (Role::Client, ProtocolState::Handshake, MessageType::HandshakeResponse) => Ok(()),
            (Role::Server, ProtocolState::Handshake, MessageType::HandshakeComplete) => Ok(()),
            
            // ESTABLISHED state
            (_, ProtocolState::Established, MessageType::EncryptedMessage) => Ok(()),
            (_, ProtocolState::Established, MessageType::Terminate) => Ok(()),
            
            // Invalid combinations
            _ => Err(StateMachineError::InvalidStateForMessage {
                current_state: self.state,
                message_type,
                role: self.role,
            }),
        }
    }

    /// Validates that a message can be sent in the current state
    pub fn validate_send(&self, message_type: MessageType) -> Result<(), StateMachineError> {
        if self.state.is_terminal() {
            return Err(StateMachineError::SessionTerminated);
        }

        match (self.role, self.state, message_type) {
            // INIT state
            (Role::Client, ProtocolState::Init, MessageType::ModeNegotiation) => Ok(()),
            
            // MODE_NEGOTIATION state
            (Role::Server, ProtocolState::ModeNegotiation, MessageType::ModeSelection) => Ok(()),
            (Role::Client, ProtocolState::ModeNegotiation, MessageType::ClientHello) => Ok(()),
            
            // COOKIE_CHALLENGE state
            (Role::Server, ProtocolState::CookieChallenge, MessageType::CookieChallenge) => Ok(()),
            (Role::Client, ProtocolState::CookieChallenge, MessageType::ClientHelloWithCookie) => Ok(()),
            
            // HANDSHAKE state
            (Role::Client, ProtocolState::Handshake, MessageType::HandshakeInit) => Ok(()),
            (Role::Server, ProtocolState::Handshake, MessageType::HandshakeResponse) => Ok(()),
            (Role::Client, ProtocolState::Handshake, MessageType::HandshakeComplete) => Ok(()),
            
            // ESTABLISHED state
            (_, ProtocolState::Established, MessageType::EncryptedMessage) => Ok(()),
            (_, ProtocolState::Established, MessageType::Terminate) => Ok(()),
            
            // Invalid combinations
            _ => Err(StateMachineError::InvalidStateForSend {
                current_state: self.state,
                message_type,
                role: self.role,
            }),
        }
    }

    /// Handles receiving a message and transitions state if valid
    pub fn on_receive(&mut self, message_type: MessageType) -> Result<(), StateMachineError> {
        self.validate_receive(message_type)?;
        
        let new_state = self.compute_next_state_on_receive(message_type)?;
        self.transition_to(new_state)?;
        
        Ok(())
    }

    /// Handles sending a message and transitions state if valid
    pub fn on_send(&mut self, message_type: MessageType) -> Result<(), StateMachineError> {
        self.validate_send(message_type)?;
        
        let new_state = self.compute_next_state_on_send(message_type)?;
        self.transition_to(new_state)?;
        
        Ok(())
    }

    /// Computes the next state after receiving a message
    fn compute_next_state_on_receive(&self, message_type: MessageType) -> Result<ProtocolState, StateMachineError> {
        match (self.role, self.state, message_type) {
            // Server receives ModeNegotiation in INIT -> MODE_NEGOTIATION
            (Role::Server, ProtocolState::Init, MessageType::ModeNegotiation) => {
                Ok(ProtocolState::ModeNegotiation)
            }
            
            // Client receives ModeSelection in MODE_NEGOTIATION -> COOKIE_CHALLENGE
            (Role::Client, ProtocolState::ModeNegotiation, MessageType::ModeSelection) => {
                Ok(ProtocolState::CookieChallenge)
            }
            
            // Client receives CookieChallenge in COOKIE_CHALLENGE -> stay in COOKIE_CHALLENGE
            (Role::Client, ProtocolState::CookieChallenge, MessageType::CookieChallenge) => {
                Ok(ProtocolState::CookieChallenge)
            }
            
            // Server receives ClientHelloWithCookie in COOKIE_CHALLENGE -> HANDSHAKE
            (Role::Server, ProtocolState::CookieChallenge, MessageType::ClientHelloWithCookie) => {
                Ok(ProtocolState::Handshake)
            }
            
            // Server receives HandshakeInit in HANDSHAKE -> stay in HANDSHAKE
            (Role::Server, ProtocolState::Handshake, MessageType::HandshakeInit) => {
                Ok(ProtocolState::Handshake)
            }
            
            // Client receives HandshakeResponse in HANDSHAKE -> stay in HANDSHAKE
            (Role::Client, ProtocolState::Handshake, MessageType::HandshakeResponse) => {
                Ok(ProtocolState::Handshake)
            }
            
            // Server receives HandshakeComplete in HANDSHAKE -> ESTABLISHED
            (Role::Server, ProtocolState::Handshake, MessageType::HandshakeComplete) => {
                Ok(ProtocolState::Established)
            }
            
            // Encrypted messages in ESTABLISHED -> stay in ESTABLISHED
            (_, ProtocolState::Established, MessageType::EncryptedMessage) => {
                Ok(ProtocolState::Established)
            }
            
            // Terminate in ESTABLISHED -> TERMINATED
            (_, ProtocolState::Established, MessageType::Terminate) => {
                Ok(ProtocolState::Terminated)
            }
            
            _ => Err(StateMachineError::InvalidStateForMessage {
                current_state: self.state,
                message_type,
                role: self.role,
            }),
        }
    }

    /// Computes the next state after sending a message
    fn compute_next_state_on_send(&self, message_type: MessageType) -> Result<ProtocolState, StateMachineError> {
        match (self.role, self.state, message_type) {
            // Client sends ModeNegotiation in INIT -> MODE_NEGOTIATION
            (Role::Client, ProtocolState::Init, MessageType::ModeNegotiation) => {
                Ok(ProtocolState::ModeNegotiation)
            }
            
            // Server sends ModeSelection in MODE_NEGOTIATION -> COOKIE_CHALLENGE
            (Role::Server, ProtocolState::ModeNegotiation, MessageType::ModeSelection) => {
                Ok(ProtocolState::CookieChallenge)
            }
            
            // Client sends ClientHello in MODE_NEGOTIATION -> COOKIE_CHALLENGE
            (Role::Client, ProtocolState::ModeNegotiation, MessageType::ClientHello) => {
                Ok(ProtocolState::CookieChallenge)
            }
            
            // Server sends CookieChallenge in COOKIE_CHALLENGE -> stay in COOKIE_CHALLENGE
            (Role::Server, ProtocolState::CookieChallenge, MessageType::CookieChallenge) => {
                Ok(ProtocolState::CookieChallenge)
            }
            
            // Client sends ClientHelloWithCookie in COOKIE_CHALLENGE -> HANDSHAKE
            (Role::Client, ProtocolState::CookieChallenge, MessageType::ClientHelloWithCookie) => {
                Ok(ProtocolState::Handshake)
            }
            
            // Client sends HandshakeInit in HANDSHAKE -> stay in HANDSHAKE
            (Role::Client, ProtocolState::Handshake, MessageType::HandshakeInit) => {
                Ok(ProtocolState::Handshake)
            }
            
            // Server sends HandshakeResponse in HANDSHAKE -> stay in HANDSHAKE
            (Role::Server, ProtocolState::Handshake, MessageType::HandshakeResponse) => {
                Ok(ProtocolState::Handshake)
            }
            
            // Client sends HandshakeComplete in HANDSHAKE -> ESTABLISHED
            (Role::Client, ProtocolState::Handshake, MessageType::HandshakeComplete) => {
                Ok(ProtocolState::Established)
            }
            
            // Encrypted messages in ESTABLISHED -> stay in ESTABLISHED
            (_, ProtocolState::Established, MessageType::EncryptedMessage) => {
                Ok(ProtocolState::Established)
            }
            
            // Terminate in ESTABLISHED -> TERMINATED
            (_, ProtocolState::Established, MessageType::Terminate) => {
                Ok(ProtocolState::Terminated)
            }
            
            _ => Err(StateMachineError::InvalidStateForSend {
                current_state: self.state,
                message_type,
                role: self.role,
            }),
        }
    }

    /// Transitions to a new state
    fn transition_to(&mut self, new_state: ProtocolState) -> Result<(), StateMachineError> {
        // Validate transition is allowed
        if !self.is_valid_transition(new_state) {
            return Err(StateMachineError::InvalidTransition {
                from_state: self.state,
                to_state: new_state,
                role: self.role,
            });
        }

        self.state = new_state;
        self.transition_count += 1;
        
        Ok(())
    }

    /// Checks if a state transition is valid
    fn is_valid_transition(&self, new_state: ProtocolState) -> bool {
        // Allow staying in same state
        if self.state == new_state {
            return true;
        }

        // Cannot transition from terminal state
        if self.state.is_terminal() {
            return false;
        }

        // Valid forward transitions
        match (self.state, new_state) {
            (ProtocolState::Init, ProtocolState::ModeNegotiation) => true,
            (ProtocolState::ModeNegotiation, ProtocolState::CookieChallenge) => true,
            (ProtocolState::CookieChallenge, ProtocolState::Handshake) => true,
            (ProtocolState::Handshake, ProtocolState::Established) => true,
            (ProtocolState::Established, ProtocolState::Terminated) => true,
            _ => false,
        }
    }

    /// Checks state machine invariants
    ///
    /// Verifies that the state machine is in a consistent state.
    /// This should be called periodically during development/testing.
    pub fn check_invariants(&self) -> Result<(), StateMachineError> {
        // Invariant 1: Terminal state should not allow any operations
        if self.state.is_terminal() && self.state != ProtocolState::Terminated {
            return Err(StateMachineError::InvariantViolation {
                description: format!("State {} is terminal but not TERMINATED", self.state),
            });
        }

        // Invariant 2: Transition count should be reasonable
        if self.transition_count > 1000 {
            return Err(StateMachineError::InvariantViolation {
                description: format!(
                    "Transition count {} exceeds reasonable limit (possible infinite loop)",
                    self.transition_count
                ),
            });
        }

        Ok(())
    }

    /// Resets the state machine to INIT state
    ///
    /// This is primarily useful for testing. In production, create a new
    /// state machine instead of resetting.
    #[cfg(test)]
    pub fn reset(&mut self) {
        self.state = ProtocolState::Init;
        self.transition_count = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_state_properties() {
        assert!(!ProtocolState::Init.is_terminal());
        assert!(!ProtocolState::ModeNegotiation.is_terminal());
        assert!(!ProtocolState::CookieChallenge.is_terminal());
        assert!(!ProtocolState::Handshake.is_terminal());
        assert!(!ProtocolState::Established.is_terminal());
        assert!(ProtocolState::Terminated.is_terminal());

        assert!(!ProtocolState::Init.allows_encrypted_messages());
        assert!(!ProtocolState::ModeNegotiation.allows_encrypted_messages());
        assert!(!ProtocolState::CookieChallenge.allows_encrypted_messages());
        assert!(!ProtocolState::Handshake.allows_encrypted_messages());
        assert!(ProtocolState::Established.allows_encrypted_messages());
        assert!(!ProtocolState::Terminated.allows_encrypted_messages());
    }

    #[test]
    fn test_protocol_state_display() {
        assert_eq!(ProtocolState::Init.to_string(), "INIT");
        assert_eq!(ProtocolState::ModeNegotiation.to_string(), "MODE_NEGOTIATION");
        assert_eq!(ProtocolState::CookieChallenge.to_string(), "COOKIE_CHALLENGE");
        assert_eq!(ProtocolState::Handshake.to_string(), "HANDSHAKE");
        assert_eq!(ProtocolState::Established.to_string(), "ESTABLISHED");
        assert_eq!(ProtocolState::Terminated.to_string(), "TERMINATED");
    }

    #[test]
    fn test_client_handshake_flow() {
        let mut client = StateMachine::new(Role::Client);
        
        // Initial state
        assert_eq!(client.state(), ProtocolState::Init);
        
        // Client sends ModeNegotiation
        assert!(client.can_send(MessageType::ModeNegotiation));
        client.on_send(MessageType::ModeNegotiation).unwrap();
        assert_eq!(client.state(), ProtocolState::ModeNegotiation);
        
        // Client receives ModeSelection
        assert!(client.can_receive(MessageType::ModeSelection));
        client.on_receive(MessageType::ModeSelection).unwrap();
        assert_eq!(client.state(), ProtocolState::CookieChallenge);
        
        // Client receives CookieChallenge
        assert!(client.can_receive(MessageType::CookieChallenge));
        client.on_receive(MessageType::CookieChallenge).unwrap();
        assert_eq!(client.state(), ProtocolState::CookieChallenge);
        
        // Client sends ClientHelloWithCookie
        assert!(client.can_send(MessageType::ClientHelloWithCookie));
        client.on_send(MessageType::ClientHelloWithCookie).unwrap();
        assert_eq!(client.state(), ProtocolState::Handshake);
        
        // Client sends HandshakeInit
        assert!(client.can_send(MessageType::HandshakeInit));
        client.on_send(MessageType::HandshakeInit).unwrap();
        assert_eq!(client.state(), ProtocolState::Handshake);
        
        // Client receives HandshakeResponse
        assert!(client.can_receive(MessageType::HandshakeResponse));
        client.on_receive(MessageType::HandshakeResponse).unwrap();
        assert_eq!(client.state(), ProtocolState::Handshake);
        
        // Client sends HandshakeComplete
        assert!(client.can_send(MessageType::HandshakeComplete));
        client.on_send(MessageType::HandshakeComplete).unwrap();
        assert_eq!(client.state(), ProtocolState::Established);
        
        // Client can now send/receive encrypted messages
        assert!(client.can_send(MessageType::EncryptedMessage));
        assert!(client.can_receive(MessageType::EncryptedMessage));
        client.on_send(MessageType::EncryptedMessage).unwrap();
        assert_eq!(client.state(), ProtocolState::Established);
        
        // Client terminates session
        assert!(client.can_send(MessageType::Terminate));
        client.on_send(MessageType::Terminate).unwrap();
        assert_eq!(client.state(), ProtocolState::Terminated);
        
        // No further operations allowed
        assert!(!client.can_send(MessageType::EncryptedMessage));
        assert!(!client.can_receive(MessageType::EncryptedMessage));
    }

    #[test]
    fn test_server_handshake_flow() {
        let mut server = StateMachine::new(Role::Server);
        
        // Initial state
        assert_eq!(server.state(), ProtocolState::Init);
        
        // Server receives ModeNegotiation
        assert!(server.can_receive(MessageType::ModeNegotiation));
        server.on_receive(MessageType::ModeNegotiation).unwrap();
        assert_eq!(server.state(), ProtocolState::ModeNegotiation);
        
        // Server sends ModeSelection
        assert!(server.can_send(MessageType::ModeSelection));
        server.on_send(MessageType::ModeSelection).unwrap();
        assert_eq!(server.state(), ProtocolState::CookieChallenge);
        
        // Server sends CookieChallenge
        assert!(server.can_send(MessageType::CookieChallenge));
        server.on_send(MessageType::CookieChallenge).unwrap();
        assert_eq!(server.state(), ProtocolState::CookieChallenge);
        
        // Server receives ClientHelloWithCookie
        assert!(server.can_receive(MessageType::ClientHelloWithCookie));
        server.on_receive(MessageType::ClientHelloWithCookie).unwrap();
        assert_eq!(server.state(), ProtocolState::Handshake);
        
        // Server receives HandshakeInit
        assert!(server.can_receive(MessageType::HandshakeInit));
        server.on_receive(MessageType::HandshakeInit).unwrap();
        assert_eq!(server.state(), ProtocolState::Handshake);
        
        // Server sends HandshakeResponse
        assert!(server.can_send(MessageType::HandshakeResponse));
        server.on_send(MessageType::HandshakeResponse).unwrap();
        assert_eq!(server.state(), ProtocolState::Handshake);
        
        // Server receives HandshakeComplete
        assert!(server.can_receive(MessageType::HandshakeComplete));
        server.on_receive(MessageType::HandshakeComplete).unwrap();
        assert_eq!(server.state(), ProtocolState::Established);
        
        // Server can now send/receive encrypted messages
        assert!(server.can_send(MessageType::EncryptedMessage));
        assert!(server.can_receive(MessageType::EncryptedMessage));
        server.on_receive(MessageType::EncryptedMessage).unwrap();
        assert_eq!(server.state(), ProtocolState::Established);
        
        // Server terminates session
        assert!(server.can_receive(MessageType::Terminate));
        server.on_receive(MessageType::Terminate).unwrap();
        assert_eq!(server.state(), ProtocolState::Terminated);
    }

    #[test]
    fn test_invalid_message_in_init_state() {
        let mut client = StateMachine::new(Role::Client);
        
        // Client cannot receive ModeSelection in INIT state
        assert!(!client.can_receive(MessageType::ModeSelection));
        let result = client.on_receive(MessageType::ModeSelection);
        assert!(matches!(result, Err(StateMachineError::InvalidStateForMessage { .. })));
        
        // Client cannot send HandshakeInit in INIT state
        assert!(!client.can_send(MessageType::HandshakeInit));
        let result = client.on_send(MessageType::HandshakeInit);
        assert!(matches!(result, Err(StateMachineError::InvalidStateForSend { .. })));
    }

    #[test]
    fn test_invalid_message_in_established_state() {
        let mut client = StateMachine::new(Role::Client);
        
        // Fast-forward to ESTABLISHED state
        client.on_send(MessageType::ModeNegotiation).unwrap();
        client.on_receive(MessageType::ModeSelection).unwrap();
        client.on_receive(MessageType::CookieChallenge).unwrap();
        client.on_send(MessageType::ClientHelloWithCookie).unwrap();
        client.on_send(MessageType::HandshakeInit).unwrap();
        client.on_receive(MessageType::HandshakeResponse).unwrap();
        client.on_send(MessageType::HandshakeComplete).unwrap();
        assert_eq!(client.state(), ProtocolState::Established);
        
        // Cannot send handshake messages in ESTABLISHED state
        assert!(!client.can_send(MessageType::ModeNegotiation));
        assert!(!client.can_send(MessageType::HandshakeInit));
        
        let result = client.on_send(MessageType::ModeNegotiation);
        assert!(matches!(result, Err(StateMachineError::InvalidStateForSend { .. })));
    }

    #[test]
    fn test_terminated_state_rejects_all_operations() {
        let mut client = StateMachine::new(Role::Client);
        
        // Fast-forward to ESTABLISHED and terminate
        client.on_send(MessageType::ModeNegotiation).unwrap();
        client.on_receive(MessageType::ModeSelection).unwrap();
        client.on_receive(MessageType::CookieChallenge).unwrap();
        client.on_send(MessageType::ClientHelloWithCookie).unwrap();
        client.on_send(MessageType::HandshakeInit).unwrap();
        client.on_receive(MessageType::HandshakeResponse).unwrap();
        client.on_send(MessageType::HandshakeComplete).unwrap();
        client.on_send(MessageType::Terminate).unwrap();
        assert_eq!(client.state(), ProtocolState::Terminated);
        
        // All operations should fail
        assert!(!client.can_send(MessageType::EncryptedMessage));
        assert!(!client.can_receive(MessageType::EncryptedMessage));
        
        let result = client.on_send(MessageType::EncryptedMessage);
        assert!(matches!(result, Err(StateMachineError::SessionTerminated)));
        
        let result = client.on_receive(MessageType::EncryptedMessage);
        assert!(matches!(result, Err(StateMachineError::SessionTerminated)));
    }

    #[test]
    fn test_role_specific_restrictions() {
        let mut client = StateMachine::new(Role::Client);
        let mut server = StateMachine::new(Role::Server);
        
        // Client cannot receive ModeNegotiation
        assert!(!client.can_receive(MessageType::ModeNegotiation));
        
        // Server cannot send ModeNegotiation
        assert!(!server.can_send(MessageType::ModeNegotiation));
        
        // Client cannot send ModeSelection
        client.on_send(MessageType::ModeNegotiation).unwrap();
        assert!(!client.can_send(MessageType::ModeSelection));
        
        // Server cannot receive ModeSelection
        server.on_receive(MessageType::ModeNegotiation).unwrap();
        assert!(!server.can_receive(MessageType::ModeSelection));
    }

    #[test]
    fn test_transition_count() {
        let mut client = StateMachine::new(Role::Client);
        assert_eq!(client.transition_count(), 0);
        
        client.on_send(MessageType::ModeNegotiation).unwrap();
        assert_eq!(client.transition_count(), 1);
        
        client.on_receive(MessageType::ModeSelection).unwrap();
        assert_eq!(client.transition_count(), 2);
        
        // Staying in same state still counts as transition
        client.on_receive(MessageType::CookieChallenge).unwrap();
        assert_eq!(client.transition_count(), 2); // No transition, stayed in COOKIE_CHALLENGE
    }

    #[test]
    fn test_check_invariants() {
        let client = StateMachine::new(Role::Client);
        assert!(client.check_invariants().is_ok());
        
        let mut client_terminated = StateMachine::new(Role::Client);
        client_terminated.on_send(MessageType::ModeNegotiation).unwrap();
        client_terminated.on_receive(MessageType::ModeSelection).unwrap();
        client_terminated.on_receive(MessageType::CookieChallenge).unwrap();
        client_terminated.on_send(MessageType::ClientHelloWithCookie).unwrap();
        client_terminated.on_send(MessageType::HandshakeInit).unwrap();
        client_terminated.on_receive(MessageType::HandshakeResponse).unwrap();
        client_terminated.on_send(MessageType::HandshakeComplete).unwrap();
        client_terminated.on_send(MessageType::Terminate).unwrap();
        assert!(client_terminated.check_invariants().is_ok());
    }

    #[test]
    fn test_error_display() {
        let error = StateMachineError::InvalidStateForMessage {
            current_state: ProtocolState::Init,
            message_type: MessageType::HandshakeInit,
            role: Role::Client,
        };
        assert!(error.to_string().contains("Client"));
        assert!(error.to_string().contains("HandshakeInit"));
        assert!(error.to_string().contains("INIT"));
        
        let error = StateMachineError::SessionTerminated;
        assert!(error.to_string().contains("terminated"));
        
        let error = StateMachineError::InvariantViolation {
            description: "Test violation".to_string(),
        };
        assert!(error.to_string().contains("Test violation"));
    }

    #[test]
    fn test_message_type_display() {
        assert_eq!(MessageType::ModeNegotiation.to_string(), "ModeNegotiation");
        assert_eq!(MessageType::HandshakeInit.to_string(), "HandshakeInit");
        assert_eq!(MessageType::EncryptedMessage.to_string(), "EncryptedMessage");
    }

    #[test]
    fn test_role_display() {
        assert_eq!(Role::Client.to_string(), "Client");
        assert_eq!(Role::Server.to_string(), "Server");
    }
}
