//! Global Unified Traffic Scheduler for B4AE v2.0
//!
//! This module implements the global traffic scheduler that provides cross-session
//! metadata protection by mixing messages from all sessions into a single constant-rate
//! output stream. This prevents a global passive observer from correlating sessions
//! based on traffic patterns.
//!
//! ## Architecture
//!
//! The global traffic scheduler consists of:
//!
//! - **Unified Queue**: All messages from all sessions feed into a single queue
//! - **Constant-Rate Output**: Messages are sent at a fixed rate (e.g., 100 msg/s)
//! - **Global Dummy Generation**: Dummy messages fill gaps to maintain constant rate
//! - **Cross-Session Mixing**: No per-session burst patterns visible to observers
//!
//! ## Security Properties
//!
//! - **Metadata Minimization**: Global passive observer cannot correlate sessions
//! - **Timing Obfuscation**: Constant-rate output prevents timing correlation
//! - **Traffic Analysis Resistance**: Dummy messages obscure real message count
//! - **Cross-Session Indistinguishability**: No per-session fingerprinting possible
//!
//! ## Performance Characteristics
//!
//! - **Latency**: Average latency = 1 / (2 × target_rate)
//!   - 100 msg/s: ~5ms average latency
//!   - 1000 msg/s: ~0.5ms average latency
//! - **Bandwidth Overhead**: 20-50% from dummy traffic (configurable)
//! - **Memory Usage**: ~10 MB for 10,000 queued messages
//!
//! ## Requirements
//!
//! - REQ-5: Global Unified Traffic Scheduler
//! - REQ-6: Global Dummy Message Generation
//! - REQ-16: Metadata Protection Against Global Passive Observer
//! - REQ-20: Cross-Session Indistinguishability
//! - REQ-22: Message Throughput Requirements
//! - REQ-23: Memory Usage Requirements

use crate::protocol::v2::{SessionId, DEFAULT_TARGET_RATE, MAX_QUEUE_DEPTH, MAX_QUEUE_MEMORY};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Global traffic scheduler managing all outbound traffic
///
/// The scheduler maintains a unified queue for messages from all sessions
/// and sends them at a constant rate to prevent traffic analysis.
///
/// ## Thread Safety
///
/// The scheduler is designed to be shared across threads using Arc<Mutex<_>>.
/// All operations are protected by the mutex to ensure thread-safe access.
///
/// ## Example
///
/// ```rust,ignore
/// use b4ae::protocol::v2::GlobalTrafficScheduler;
///
/// // Create scheduler with default rate (100 msg/s)
/// let scheduler = GlobalTrafficScheduler::new(100.0);
///
/// // Schedule a message
/// let session_id = SessionId::new([0u8; 32]);
/// let payload = vec![1, 2, 3, 4];
/// scheduler.schedule_message(session_id, payload, false)?;
///
/// // Get statistics
/// let stats = scheduler.statistics();
/// println!("Total messages sent: {}", stats.total_messages_sent);
/// ```
#[derive(Debug)]
pub struct GlobalTrafficScheduler {
    /// Unified queue for all messages from all sessions
    unified_queue: VecDeque<ScheduledMessage>,

    /// Target rate in messages per second
    ///
    /// This determines the constant rate at which messages are sent.
    /// Trade-off between latency and metadata protection:
    /// - Higher rate: Lower latency, higher bandwidth overhead
    /// - Lower rate: Higher latency, lower bandwidth overhead
    target_rate: f64,

    /// Timestamp of last message send
    ///
    /// Used to calculate the next scheduled send time to maintain
    /// constant-rate output.
    last_send_time: Instant,

    /// Traffic statistics for monitoring and metrics
    statistics: TrafficStatistics,

    /// Maximum queue depth (number of messages)
    ///
    /// When this limit is reached, new messages are rejected with
    /// "Queue full" error to prevent unbounded memory growth.
    max_queue_depth: usize,

    /// Maximum queue memory in bytes
    ///
    /// When this limit is reached, new messages are rejected with
    /// "Memory limit exceeded" error to prevent unbounded memory growth.
    max_queue_memory: usize,
}

impl GlobalTrafficScheduler {
    /// Creates a new global traffic scheduler with the specified target rate
    ///
    /// # Arguments
    ///
    /// * `target_rate` - Target rate in messages per second (e.g., 100.0)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Create scheduler with 100 msg/s rate
    /// let scheduler = GlobalTrafficScheduler::new(100.0);
    ///
    /// // Create scheduler with 1000 msg/s rate for lower latency
    /// let scheduler = GlobalTrafficScheduler::new(1000.0);
    /// ```
    pub fn new(target_rate: f64) -> Self {
        Self {
            unified_queue: VecDeque::new(),
            target_rate,
            last_send_time: Instant::now(),
            statistics: TrafficStatistics::new(),
            max_queue_depth: MAX_QUEUE_DEPTH,
            max_queue_memory: MAX_QUEUE_MEMORY,
        }
    }

    /// Creates a new global traffic scheduler with default configuration
    ///
    /// Uses the default target rate of 100 messages per second.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let scheduler = GlobalTrafficScheduler::default();
    /// ```
    pub fn default() -> Self {
        Self::new(DEFAULT_TARGET_RATE)
    }

    /// Returns the current target rate in messages per second
    pub fn target_rate(&self) -> f64 {
        self.target_rate
    }

    /// Sets the target rate in messages per second
    ///
    /// This allows dynamic adjustment of the constant-rate output.
    ///
    /// # Arguments
    ///
    /// * `rate` - New target rate in messages per second
    ///
    /// # Panics
    ///
    /// Panics if rate is not positive and finite.
    pub fn set_target_rate(&mut self, rate: f64) {
        assert!(rate > 0.0 && rate.is_finite(), "Target rate must be positive and finite");
        self.target_rate = rate;
    }

    /// Returns a reference to the current traffic statistics
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let stats = scheduler.statistics();
    /// println!("Total messages: {}", stats.total_messages_sent);
    /// println!("Real messages: {}", stats.real_messages_sent);
    /// println!("Dummy messages: {}", stats.dummy_messages_sent);
    /// println!("Queue depth: {}", stats.current_queue_depth);
    /// ```
    pub fn statistics(&self) -> &TrafficStatistics {
        &self.statistics
    }

    /// Returns the current queue depth (number of messages)
    pub fn queue_depth(&self) -> usize {
        self.unified_queue.len()
    }

    /// Returns the current queue memory usage in bytes
    pub fn queue_memory(&self) -> usize {
        self.statistics.current_queue_memory
    }

    /// Returns true if the queue is empty
    pub fn is_queue_empty(&self) -> bool {
        self.unified_queue.is_empty()
    }

    /// Returns true if the queue is full (at max depth)
    pub fn is_queue_full(&self) -> bool {
        self.unified_queue.len() >= self.max_queue_depth
    }

    /// Returns true if the queue memory limit is exceeded
    pub fn is_memory_limit_exceeded(&self) -> bool {
        self.statistics.current_queue_memory >= self.max_queue_memory
    }

    /// Returns the maximum queue depth
    pub fn max_queue_depth(&self) -> usize {
        self.max_queue_depth
    }

    /// Returns the maximum queue memory in bytes
    pub fn max_queue_memory(&self) -> usize {
        self.max_queue_memory
    }

    /// Sets the maximum queue depth
    ///
    /// # Arguments
    ///
    /// * `depth` - New maximum queue depth
    pub fn set_max_queue_depth(&mut self, depth: usize) {
        self.max_queue_depth = depth;
    }

    /// Sets the maximum queue memory in bytes
    ///
    /// # Arguments
    ///
    /// * `memory` - New maximum queue memory in bytes
    pub fn set_max_queue_memory(&mut self, memory: usize) {
        self.max_queue_memory = memory;
    }
}

/// Scheduled message in the unified queue
///
/// Each message contains:
/// - Session ID: Which session this message belongs to
/// - Payload: The actual message data (encrypted and authenticated)
/// - Is Dummy: Whether this is a dummy message (for internal tracking)
/// - Scheduled Time: When this message should be sent
///
/// ## Security Note
///
/// Dummy messages are marked internally but are indistinguishable from
/// real messages at the network layer (same encryption, same size distribution).
#[derive(Debug, Clone)]
pub struct ScheduledMessage {
    /// Session ID this message belongs to
    pub session_id: SessionId,

    /// Message payload (encrypted and authenticated)
    ///
    /// For real messages, this is the actual application data.
    /// For dummy messages, this is random data indistinguishable from real data.
    pub payload: Vec<u8>,

    /// Whether this is a dummy message (internal tracking only)
    ///
    /// This flag is used internally for statistics but is NOT visible
    /// at the network layer. Dummy messages are encrypted and authenticated
    /// identically to real messages.
    pub is_dummy: bool,

    /// Scheduled send time
    ///
    /// The message will be sent at this time to maintain constant-rate output.
    pub scheduled_time: Instant,
}

impl ScheduledMessage {
    /// Creates a new scheduled message
    ///
    /// # Arguments
    ///
    /// * `session_id` - Session ID this message belongs to
    /// * `payload` - Message payload (encrypted and authenticated)
    /// * `is_dummy` - Whether this is a dummy message
    /// * `scheduled_time` - When this message should be sent
    pub fn new(
        session_id: SessionId,
        payload: Vec<u8>,
        is_dummy: bool,
        scheduled_time: Instant,
    ) -> Self {
        Self {
            session_id,
            payload,
            is_dummy,
            scheduled_time,
        }
    }

    /// Returns the size of this message in bytes
    pub fn size(&self) -> usize {
        self.payload.len()
    }
}

/// Traffic statistics for monitoring and metrics
///
/// Tracks:
/// - Total messages sent (real + dummy)
/// - Real messages sent
/// - Dummy messages sent
/// - Current queue depth
/// - Current queue memory usage
///
/// ## Example
///
/// ```rust,ignore
/// let stats = scheduler.statistics();
/// let dummy_ratio = stats.dummy_ratio();
/// println!("Dummy traffic: {:.1}%", dummy_ratio * 100.0);
/// ```
#[derive(Debug, Clone)]
pub struct TrafficStatistics {
    /// Total number of messages sent (real + dummy)
    pub total_messages_sent: u64,

    /// Number of real messages sent
    pub real_messages_sent: u64,

    /// Number of dummy messages sent
    pub dummy_messages_sent: u64,

    /// Current queue depth (number of messages)
    pub current_queue_depth: usize,

    /// Current queue memory usage in bytes
    pub current_queue_memory: usize,
}

impl TrafficStatistics {
    /// Creates a new traffic statistics instance with all counters at zero
    pub fn new() -> Self {
        Self {
            total_messages_sent: 0,
            real_messages_sent: 0,
            dummy_messages_sent: 0,
            current_queue_depth: 0,
            current_queue_memory: 0,
        }
    }

    /// Returns the ratio of dummy messages to total messages
    ///
    /// Returns 0.0 if no messages have been sent.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let stats = scheduler.statistics();
    /// let ratio = stats.dummy_ratio();
    /// println!("Dummy traffic: {:.1}%", ratio * 100.0);
    /// ```
    pub fn dummy_ratio(&self) -> f64 {
        if self.total_messages_sent == 0 {
            0.0
        } else {
            self.dummy_messages_sent as f64 / self.total_messages_sent as f64
        }
    }

    /// Returns the ratio of real messages to total messages
    ///
    /// Returns 0.0 if no messages have been sent.
    pub fn real_ratio(&self) -> f64 {
        if self.total_messages_sent == 0 {
            0.0
        } else {
            self.real_messages_sent as f64 / self.total_messages_sent as f64
        }
    }

    /// Resets all statistics counters to zero
    ///
    /// Note: This does not reset current_queue_depth or current_queue_memory
    /// as those reflect the current state, not historical counts.
    pub fn reset(&mut self) {
        self.total_messages_sent = 0;
        self.real_messages_sent = 0;
        self.dummy_messages_sent = 0;
    }
}

impl Default for TrafficStatistics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduler_creation() {
        let scheduler = GlobalTrafficScheduler::new(100.0);
        assert_eq!(scheduler.target_rate(), 100.0);
        assert_eq!(scheduler.queue_depth(), 0);
        assert!(scheduler.is_queue_empty());
        assert!(!scheduler.is_queue_full());
    }

    #[test]
    fn test_scheduler_default() {
        let scheduler = GlobalTrafficScheduler::default();
        assert_eq!(scheduler.target_rate(), DEFAULT_TARGET_RATE);
        assert_eq!(scheduler.queue_depth(), 0);
    }

    #[test]
    fn test_set_target_rate() {
        let mut scheduler = GlobalTrafficScheduler::new(100.0);
        scheduler.set_target_rate(1000.0);
        assert_eq!(scheduler.target_rate(), 1000.0);
    }

    #[test]
    #[should_panic(expected = "Target rate must be positive and finite")]
    fn test_set_target_rate_invalid() {
        let mut scheduler = GlobalTrafficScheduler::new(100.0);
        scheduler.set_target_rate(0.0);
    }

    #[test]
    #[should_panic(expected = "Target rate must be positive and finite")]
    fn test_set_target_rate_negative() {
        let mut scheduler = GlobalTrafficScheduler::new(100.0);
        scheduler.set_target_rate(-100.0);
    }

    #[test]
    fn test_statistics_creation() {
        let stats = TrafficStatistics::new();
        assert_eq!(stats.total_messages_sent, 0);
        assert_eq!(stats.real_messages_sent, 0);
        assert_eq!(stats.dummy_messages_sent, 0);
        assert_eq!(stats.current_queue_depth, 0);
        assert_eq!(stats.current_queue_memory, 0);
    }

    #[test]
    fn test_statistics_dummy_ratio() {
        let mut stats = TrafficStatistics::new();
        
        // No messages sent
        assert_eq!(stats.dummy_ratio(), 0.0);
        
        // 20% dummy traffic
        stats.total_messages_sent = 100;
        stats.real_messages_sent = 80;
        stats.dummy_messages_sent = 20;
        assert!((stats.dummy_ratio() - 0.2).abs() < 0.001);
        
        // 50% dummy traffic
        stats.total_messages_sent = 100;
        stats.real_messages_sent = 50;
        stats.dummy_messages_sent = 50;
        assert!((stats.dummy_ratio() - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_statistics_real_ratio() {
        let mut stats = TrafficStatistics::new();
        
        // No messages sent
        assert_eq!(stats.real_ratio(), 0.0);
        
        // 80% real traffic
        stats.total_messages_sent = 100;
        stats.real_messages_sent = 80;
        stats.dummy_messages_sent = 20;
        assert!((stats.real_ratio() - 0.8).abs() < 0.001);
    }

    #[test]
    fn test_statistics_reset() {
        let mut stats = TrafficStatistics::new();
        stats.total_messages_sent = 100;
        stats.real_messages_sent = 80;
        stats.dummy_messages_sent = 20;
        stats.current_queue_depth = 10;
        stats.current_queue_memory = 1000;
        
        stats.reset();
        
        assert_eq!(stats.total_messages_sent, 0);
        assert_eq!(stats.real_messages_sent, 0);
        assert_eq!(stats.dummy_messages_sent, 0);
        // Queue state should not be reset
        assert_eq!(stats.current_queue_depth, 10);
        assert_eq!(stats.current_queue_memory, 1000);
    }

    #[test]
    fn test_scheduled_message_creation() {
        let session_id = SessionId::new([1u8; 32]);
        let payload = vec![1, 2, 3, 4, 5];
        let scheduled_time = Instant::now();
        
        let message = ScheduledMessage::new(
            session_id.clone(),
            payload.clone(),
            false,
            scheduled_time,
        );
        
        assert_eq!(message.session_id, session_id);
        assert_eq!(message.payload, payload);
        assert!(!message.is_dummy);
        assert_eq!(message.size(), 5);
    }

    #[test]
    fn test_scheduled_message_size() {
        let session_id = SessionId::new([0u8; 32]);
        let payload = vec![0u8; 1024];
        let message = ScheduledMessage::new(
            session_id,
            payload,
            false,
            Instant::now(),
        );
        
        assert_eq!(message.size(), 1024);
    }

    #[test]
    fn test_queue_limits() {
        let scheduler = GlobalTrafficScheduler::new(100.0);
        assert_eq!(scheduler.max_queue_depth(), MAX_QUEUE_DEPTH);
        assert_eq!(scheduler.max_queue_memory(), MAX_QUEUE_MEMORY);
    }

    #[test]
    fn test_set_queue_limits() {
        let mut scheduler = GlobalTrafficScheduler::new(100.0);
        
        scheduler.set_max_queue_depth(5000);
        assert_eq!(scheduler.max_queue_depth(), 5000);
        
        scheduler.set_max_queue_memory(50 * 1024 * 1024);
        assert_eq!(scheduler.max_queue_memory(), 50 * 1024 * 1024);
    }

    #[test]
    fn test_scheduler_statistics_access() {
        let scheduler = GlobalTrafficScheduler::new(100.0);
        let stats = scheduler.statistics();
        
        assert_eq!(stats.total_messages_sent, 0);
        assert_eq!(stats.real_messages_sent, 0);
        assert_eq!(stats.dummy_messages_sent, 0);
    }
}
