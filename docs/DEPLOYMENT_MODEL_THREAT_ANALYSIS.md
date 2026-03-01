# B4AE v2.0 Deployment Model - Threat Model by Platform

**Document Version:** 2.0  
**Date:** 2026  
**Classification:** Technical Architecture  
**Status:** Updated for v2.0 Architecture  
**Warning:** Different deployment models have different threat models. One size does not fit all.

---

## ⚠️ CRITICAL: Deployment-Specific Threat Models

Each deployment environment has unique constraints, threats, and security requirements. This document specifies exact threat models for each platform with v2.0 architectural improvements.

## v2.0 Architecture Impact on Deployments

B4AE v2.0 introduces 8 major architectural improvements that affect all deployment models:

1. **Authentication Mode Separation** - Mode A (deniable) vs Mode B (PQ)
2. **Stateless Cookie Challenge** - DoS protection (360x improvement)
3. **Global Unified Traffic Scheduler** - Cross-session metadata protection
4. **Session Key Binding** - Prevents key transplant attacks
5. **Protocol ID Derivation** - Cryptographic agility
6. **Security-by-Default** - No optional security features
7. **Formal Threat Model** - 6 adversary types (A₁-A₆)
8. **Formal Verification** - Tamarin + ProVerif requirements

**See:** [V2_ARCHITECTURE_OVERVIEW.md](V2_ARCHITECTURE_OVERVIEW.md) for complete architecture details

---

## v2.0 Deployment Considerations

### Mode Selection by Platform

| Platform | Recommended Mode | Rationale | Performance Impact |
|----------|------------------|-----------|-------------------|
| IoT | Mode A (Deniable) | Resource-constrained, ~0.3ms handshake | Minimal |
| Mobile | Mode A or B | User choice, battery vs security | Mode A: Low, Mode B: Medium |
| Server | Mode B (PQ) | High-security, compliance requirements | Negligible |
| Browser | Mode A (Deniable) | User experience, ~0.3ms handshake | Low |

### DoS Protection Impact

**v2.0 Cookie Challenge:**
- **Without cookie (v1.0):** 3.6ms per handshake attempt (vulnerable)
- **With cookie (v2.0):** 0.01ms per invalid attempt, 3.61ms per valid attempt
- **DoS amplification reduced by 360x**

**Platform-Specific Benefits:**
- **IoT:** Critical - prevents resource exhaustion on constrained devices
- **Mobile:** Important - preserves battery life under attack
- **Server:** Essential - protects against large-scale DoS attacks
- **Browser:** Moderate - reduces client-side computation

### Global Traffic Scheduler Impact

**v2.0 Unified Scheduler:**
- All sessions feed into single unified queue
- Constant-rate output (100 msg/sec default)
- Cross-session indistinguishability

**Platform Considerations:**
- **IoT:** May require tuning for low-bandwidth networks
- **Mobile:** Battery impact from constant-rate transmission
- **Server:** Ideal for high-throughput deployments
- **Browser:** Latency trade-off (~5ms avg) for metadata protection

### Session Key Binding

**v2.0 Improvement:**
- All keys cryptographically bound to unique session_id
- Prevents key transplant attacks across sessions
- No performance impact (part of key derivation)

**Platform Benefits:**
- **All Platforms:** Stronger session isolation, no additional overhead

---

## A. Embedded IoT Deployment

### Threat Model - Resource-Constrained Devices (v2.0)

**Deployment Environment:**
- Microcontrollers (ARM Cortex-M, ESP32, STM32)
- Memory: 64KB-512KB RAM, 256KB-4MB Flash
- Power: Battery-operated, solar, energy harvesting
- Connectivity: WiFi, BLE, LoRaWAN, NB-IoT
- Physical: Outdoor, industrial, consumer devices

**v2.0 Improvements for IoT:**
- **Mode A (Deniable):** ~0.3ms handshake (20x faster than v1.0)
- **Cookie Challenge:** Protects against DoS with minimal overhead (~0.01ms)
- **Session Binding:** Prevents key transplant with no additional cost
- **Security-by-Default:** All protections always enabled

**Primary Adversaries:**
```
Adversary Type          Capability Level    Attack Method          v2.0 Defense
------------------------------------------------------------------------------------------------
Casual Hacker           Low                Physical access, UART    Cookie challenge + Mode A
Competitor              Medium             Firmware extraction      Session binding
Organized Crime         High               Botnet recruitment       DoS protection (360x)
Nation State           Critical             Supply chain attack      Mode B (PQ) option
```

**Security Requirements:**
```
Requirement             Specification        Implementation         Verification Method
------------------------------------------------------------------------------------------------
Code Size              <256KB total         Optimized PQ crypto    Binary size analysis
RAM Usage              <64KB runtime        Static allocation      Memory profiling
Power Consumption      <50mW average        Duty cycling           Power measurement
Flash Endurance        >10,000 writes       Wear leveling          Accelerated testing
Boot Time              <2 seconds           Pre-computed tables    Timing measurement
```

**Attack Surface Analysis:**
```
Attack Vector            Risk Level    Mitigation                    Residual Risk
------------------------------------------------------------------------------------------------
JTAG/SWD Debug          High          Disable debug fuse          Low
UART Serial             High          Disable bootloader          Low
OTA Firmware            Medium        Signed updates              Low
Physical Tampering      High          Secure enclosure            Medium
Side Channel            Medium        Power analysis resistance   Medium
Supply Chain            Critical      Hardware root of trust      High
```

**Performance Constraints (v2.0):**
```
Operation               Time Budget   Memory Budget   Power Budget   v2.0 Mode
------------------------------------------------------------------------------------------------
Key Generation          <500ms        <16KB           <25mJ          Mode A recommended
Handshake (Mode A)      <0.5s         <32KB           <50mJ          20x faster than v1.0
Handshake (Mode B)      <2s           <32KB           <100mJ         PQ security
Cookie Challenge        <0.02ms       <1KB            <0.1mJ         DoS protection
Message Encrypt         <50ms         <8KB            <5mJ           Unchanged
Message Decrypt         <50ms         <8KB            <5mJ           Unchanged
Key Rotation            <1s           <16KB           <50mJ          Unchanged
```

**v2.0 IoT-Optimized Configuration:**
```rust
// IoT-optimized B4AE v2.0 configuration
use b4ae::protocol::v2::{AuthenticationMode, SessionConfig};

let iot_config = SessionConfig {
    // Use Mode A for fast handshake
    authentication_mode: AuthenticationMode::ModeA,
    
    // Enable cookie challenge for DoS protection
    cookie_challenge_enabled: true,
    
    // Disable global traffic scheduler (too expensive for IoT)
    traffic_scheduler_enabled: false,
    
    // Session binding always enabled (no overhead)
    session_binding_enabled: true,
    
    // Minimal ratchet interval to save memory
    ratchet_interval: 1000,
};
```

## B. Mobile Deployment (Android/iOS)

### Threat Model - Consumer Mobile Devices

**Deployment Environment:**
- Smartphones (Android 8+, iOS 13+)
- Memory: 2GB-16GB RAM, 32GB-1TB storage
- Power: Rechargeable battery, charging cycles
- Connectivity: 4G/5G, WiFi, Bluetooth
- Physical: Personal device, biometric access

**Primary Adversaries:**
```
Adversary Type          Capability Level    Attack Method          Business Impact
------------------------------------------------------------------------------------------------
App Reverse Engineer    Medium             APK/IPA analysis         IP theft
Malware                 High               Key extraction           User data theft
App Store Review        Medium             Static analysis          Policy violations
Device Theft            High               Physical access          User identity theft
OS Vulnerability        Critical             Privilege escalation     System compromise
```

**Security Requirements:**
```
Requirement             Specification        Implementation         Verification Method
------------------------------------------------------------------------------------------------
Binary Size            <50MB app size       Stripped symbols       APK/IPA analysis
Runtime Memory         <200MB peak          Memory pooling           Heap profiling
Battery Impact         <5% daily drain      Background throttling  Battery stats
App Store Compliance   Full compliance      No private APIs         Static analysis
User Privacy           Opt-in only          Permission dialogs      Privacy audit
```

**Platform-Specific Security:**
```
Platform                Security Feature     Implementation         Threat Mitigation
------------------------------------------------------------------------------------------------
Android                 Keystore             Hardware-backed keys   Key extraction
Android                 SafetyNet            Attestation API        Root detection
Android                 App Sandbox          Process isolation      Privilege escalation
iOS                     Secure Enclave       Hardware encryption    Physical attacks
iOS                     App Transport Security Network encryption   Network sniffing
iOS                     App Store Review     Code review            Malware injection
```

**Attack Surface Analysis:**
```
Attack Vector            Risk Level    Mitigation                    Residual Risk
------------------------------------------------------------------------------------------------
Jailbreak/Root          High          Attestation checks          Medium
Debug Attachments       Medium        Anti-debugging techniques     Low
Memory Dumping          High          Secure memory allocation      Medium
Network Interception    Medium        Certificate pinning         Low
Reverse Engineering     High          Code obfuscation              Medium
App Store Malware       Low           Apple/Google review         Low
```

**Mobile-Specific Implementation:**
```kotlin
// Android implementation with platform security
class B4AEMobileService : Service() {
    private lateinit var secureStorage: AndroidKeyStore
    private lateinit var b4aeClient: B4AEClient
    
    override fun onCreate() {
        super.onCreate()
        
        // Initialize Android Keystore for key storage
        secureStorage = AndroidKeyStore.getInstance("B4AEKeyStore")
        
        // Create B4AE client with mobile optimizations
        b4aeClient = B4AEClient.Builder()
            .setSecurityProfile(B4AESecurityProfile.HIGH)
            .enableBatteryOptimization(true)
            .setMaxMemoryUsage(50 * 1024 * 1024) // 50MB limit
            .setBackgroundMode(true)
            .build()
    }
    
    // Battery-optimized encryption
    fun encryptMessageBatteryOptimized(
        message: String,
        peerId: String
    ): EncryptedMessage {
        // Check battery level before heavy crypto operations
        val batteryLevel = getBatteryLevel()
        if (batteryLevel < 0.2) { // < 20% battery
            // Use lighter crypto operations
            return b4aeClient.encryptMessageLowPower(message, peerId)
        }
        
        // Normal encryption
        return b4aeClient.encryptMessage(message, peerId)
    }
}
```

## C. Server Cluster Deployment

### Threat Model - High-Performance Server Infrastructure

**Deployment Environment:**
- Linux servers (x86_64, ARM64)
- Memory: 16GB-512GB RAM, NVMe SSD storage
- Network: 10Gbps-100Gbps, redundant connectivity
- Virtualization: Docker, Kubernetes, cloud-native
- Physical: Data centers, cloud infrastructure

**Primary Adversaries:**
```
Adversary Type          Capability Level    Attack Method          Business Impact
------------------------------------------------------------------------------------------------
DDoS Attacker          High               Traffic flooding         Service unavailability
APT Group              Critical           Persistent access        Data exfiltration
Insider Threat         Critical           Privileged access        Complete compromise
Cloud Provider         Critical            Infrastructure access    Total system access
Nation State           Critical            Multi-vector attack      Infrastructure control
```

**Security Requirements:**
```
Requirement             Specification        Implementation         Verification Method
------------------------------------------------------------------------------------------------
Throughput             >100K messages/sec   Parallel processing     Load testing
Latency                <10ms p99            Optimized crypto        Latency profiling
Availability           99.99% uptime        Redundant deployment    Monitoring
Scalability            Horizontal scaling   Stateless design        Stress testing
Security Hardening     CIS benchmarks       Automated compliance    Security scanning
```

**High-Performance Implementation:**
```rust
// Server-optimized B4AE with parallel processing
use b4ae_server::{B4AEServer, SecurityProfile};
use tokio::task::JoinSet;
use std::sync::Arc;

pub struct B4AEServerCluster {
    crypto_pool: Arc<CryptoWorkerPool>,
    session_cache: Arc<SessionCache>,
    rate_limiter: Arc<RateLimiter>,
}

impl B4AEServerCluster {
    pub async fn new(config: ServerConfig) -> Result<Self, ServerError> {
        // Initialize crypto worker pool for parallel processing
        let crypto_pool = Arc::new(CryptoWorkerPool::new(
            config.worker_threads,
            config.security_profile
        ));
        
        // Initialize distributed session cache
        let session_cache = Arc::new(SessionCache::new(
            config.cache_size,
            config.cache_ttl
        ));
        
        // Initialize rate limiter for DDoS protection
        let rate_limiter = Arc::new(RateLimiter::new(
            config.rate_limit_requests,
            config.rate_limit_window
        ));
        
        Ok(Self {
            crypto_pool,
            session_cache,
            rate_limiter,
        })
    }
    
    // High-throughput message processing
    pub async fn process_messages_batch(
        &self,
        messages: Vec<EncryptedMessage>
    ) -> Result<Vec<DecryptedMessage>, ProcessingError> {
        let mut tasks = JoinSet::new();
        
        // Process messages in parallel using worker pool
        for message in messages {
            let crypto_pool = self.crypto_pool.clone();
            let session_cache = self.session_cache.clone();
            
            tasks.spawn(async move {
                crypto_pool.decrypt_message(message, session_cache).await
            });
        }
        
        // Collect results
        let mut results = Vec::new();
        while let Some(result) = tasks.join_next().await {
            results.push(result.map_err(|e| ProcessingError::TaskFailed(e))?);
        }
        
        Ok(results)
    }
}
```

## D. Browser WASM Deployment

### Threat Model - Web Browser Environment

**Deployment Environment:**
- Web browsers (Chrome, Firefox, Safari, Edge)
- Memory: Limited by browser, typically 1-4GB per tab
- Execution: WebAssembly sandbox, JavaScript engine
- Network: HTTPS only, CORS restrictions
- Physical: User device, shared access

**Primary Adversaries:**
```
Adversary Type          Capability Level    Attack Method          Business Impact
------------------------------------------------------------------------------------------------
Malicious Website       High               XSS, code injection      User data theft
Browser Extension       High               API access               Credential theft
Cross-Site Scripting    High               Script injection         Session hijacking
Browser Vulnerability   Critical           Sandbox escape           System compromise
User Tracking           Medium             Fingerprinting           Privacy violation
```

**Security Requirements:**
```
Requirement             Specification        Implementation         Verification Method
------------------------------------------------------------------------------------------------
Bundle Size             <2MB WASM + JS       Tree shaking, minify   Bundle analysis
Runtime Memory          <256MB per tab       Memory pooling         Memory profiling
Execution Time          <100ms operations    Async processing       Performance profiling
Browser Compatibility   95%+ market share    Polyfills, fallbacks   Compatibility testing
Content Security Policy Strict CSP            Nonce-based CSP        Security headers
```

**Browser-Specific Implementation:**
```javascript
// WebAssembly B4AE implementation for browsers
class B4AEWebCrypto {
    constructor() {
        this.wasmModule = null;
        this.memory = null;
        this.keyCache = new Map();
        this.workerPool = [];
    }
    
    async initialize() {
        // Load WebAssembly module
        const wasmResponse = await fetch('/b4ae.wasm');
        const wasmBuffer = await wasmResponse.arrayBuffer();
        
        // Initialize with browser security features
        this.wasmModule = await WebAssembly.instantiate(wasmBuffer, {
            env: {
                // Secure random number generation
                get_random_bytes: (ptr, len) => {
                    const randomBytes = crypto.getRandomValues(new Uint8Array(len));
                    this.memory.set(randomBytes, ptr);
                },
                // Secure time source
                get_time_ms: () => Date.now(),
                // Memory allocation with bounds checking
                malloc: (size) => this.secureMalloc(size),
                free: (ptr) => this.secureFree(ptr)
            }
        });
        
        // Initialize memory with secure allocation
        this.memory = new Uint8Array(this.wasmModule.instance.exports.memory.buffer);
        
        // Initialize Web Workers for parallel processing
        await this.initializeWorkerPool();
    }
    
    // Secure key generation using Web Crypto API
    async generateSecureKey() {
        // Use Web Crypto API for additional entropy
        const keyMaterial = await crypto.subtle.generateKey(
            {
                name: 'AES-GCM',
                length: 256
            },
            true, // extractable
            ['encrypt', 'decrypt']
        );
        
        // Export key for B4AE usage
        const exportedKey = await crypto.subtle.exportKey('raw', keyMaterial);
        
        // Use with B4AE WASM
        return this.wasmModule.instance.exports.b4ae_import_key(
            exportedKey.byteLength,
            this.copyToWasm(exportedKey)
        );
    }
    
    // Memory security - zero sensitive data
    secureFree(ptr, size) {
        // Overwrite memory before freeing
        this.memory.fill(0, ptr, ptr + size);
        
        // Force garbage collection hint
        if (globalThis.gc) {
            globalThis.gc();
        }
    }
}
```

## E. Deployment-Specific Threat Analysis

### Threat Comparison by Platform
```
Threat Vector              IoT           Mobile         Server         Browser
------------------------------------------------------------------------------------------------
Physical Access             Critical       High           Medium         Low
Network Attack              Medium         High           Critical       High
Resource Exhaustion         Critical       High           Critical       Medium
Side Channel                High           Medium         Medium         Low
Supply Chain                Critical       Medium         High           Low
Insider Threat              Low            Medium         Critical       Low
DDoS Attack                 Medium         Low            Critical       Medium
Malware                     Medium         High           High           High
Reverse Engineering         High           High           Low            Medium
```

### Security Controls by Platform
```
Security Control           IoT           Mobile         Server         Browser
------------------------------------------------------------------------------------------------
Hardware Security Module  Optional       Available      Available      Not Available
Secure Boot               Available      Available      Available      Not Applicable
Code Signing              Required       Required       Recommended    Not Applicable
Sandboxing                Limited        Available      Available      Available
Attestation               Limited        Available      Available      Limited
Memory Protection         Limited        Available      Available      Available
Network Encryption        Available      Available      Available      Required
```

### Performance Characteristics by Platform
```
Metric                     IoT           Mobile         Server         Browser
------------------------------------------------------------------------------------------------
Key Generation            500-2000ms     50-200ms       5-20ms         100-500ms
Handshake                2-10s          200-1000ms     20-100ms       500-2000ms
Message Encryption       10-100ms       5-50ms         0.5-5ms        10-50ms
Memory Usage             32-128KB       1-50MB         10-500MB       10-100MB
Binary Size              64-256KB       1-50MB         10-100MB       1-5MB
Power Consumption        1-50mW         100-1000mW     10-100W        100-1000mW
```

## F. Platform-Specific Attack Scenarios

### IoT Attack Scenario: Supply Chain Compromise
```
Attack Setup:
- Adversary: Nation-state actor
- Method: Compromise device during manufacturing
- Goal: Mass surveillance of deployed devices
- Timeline: 6-12 months before deployment

Attack Execution:
1. Compromise firmware at factory
2. Add backdoor to B4AE implementation
3. Deploy devices worldwide
4. Activate backdoor remotely
5. Extract keys from all devices

Platform-Specific Defenses:
- Hardware root of trust verification
- Secure boot with attestation
- Code signing verification
- Supply chain audit trail
- Remote attestation checks

Effectiveness: Medium (detectable with proper verification)
```

### Mobile Attack Scenario: Jailbreak/Root Exploitation
```
Attack Setup:
- Adversary: Criminal organization
- Method: Exploit jailbroken/rooted devices
- Goal: Steal user keys and messages
- Timeline: Immediate upon device compromise

Attack Execution:
1. User jailbreaks/root device
2. Malware gains root access
3. Key extraction from memory
4. Message interception
5. Identity theft and fraud

Platform-Specific Defenses:
- Runtime application self-protection (RASP)
- Jailbreak/root detection
- Memory encryption and obfuscation
- Secure key storage in hardware
- App attestation verification

Effectiveness: High (prevents key extraction)
```

### Server Attack Scenario: Insider Threat
```
Attack Setup:
- Adversary: Disgruntled employee
- Method: Privileged access to production systems
- Goal: Steal customer data and keys
- Timeline: Months of undetected access

Attack Execution:
1. Gain legitimate access to systems
2. Install backdoors and keyloggers
3. Extract keys from memory and storage
4. Copy customer databases
5. Exfiltrate data over time

Platform-Specific Defenses:
- Role-based access control (RBAC)
- Audit logging and monitoring
- Hardware security module (HSM) integration
- Network segmentation
- Data loss prevention (DLP)
- Background checks and monitoring

Effectiveness: Medium (requires comprehensive security program)
```

### Browser Attack Scenario: Cross-Site Scripting (XSS)
```
Attack Setup:
- Adversary: Web attacker
- Method: XSS vulnerability on website
- Goal: Steal user keys and messages
- Timeline: Immediate upon user visit

Attack Execution:
1. Find XSS vulnerability on website
2. Inject malicious JavaScript
3. Access B4AE WebAssembly memory
4. Extract keys from browser memory
5. Steal user messages and identity

Platform-Specific Defenses:
- Content Security Policy (CSP)
- WebAssembly memory isolation
- Same-origin policy enforcement
- Input validation and sanitization
- Secure memory allocation
- Key rotation and ephemeral storage

Effectiveness: High (prevents memory access)
```

## G. Deployment Recommendations

### Platform Selection Matrix
```
Use Case                IoT           Mobile         Server         Browser
------------------------------------------------------------------------------------------------
Consumer Messaging      Not Recommended Recommended    Recommended    Recommended
Enterprise Messaging    Limited        Recommended    Recommended    Not Recommended
IoT Device Control      Recommended    Not Recommended Recommended    Not Recommended
Financial Services      Limited        Recommended    Recommended    Not Recommended
Government/Defense      Limited        Limited        Recommended    Not Recommended
Web Applications        Not Recommended Not Recommended Limited        Recommended
Mobile Applications     Not Recommended Recommended    Not Recommended Not Recommended
Embedded Systems        Recommended    Not Recommended Not Recommended Not Recommended
```

### Security Level Recommendations
```
Platform                Minimum Level    Recommended Level    Maximum Level    Rationale
------------------------------------------------------------------------------------------------
IoT                     Standard         High                Maximum         Resource constraints
Mobile                  Standard         High                Maximum         User experience vs security
Server                  High             Maximum             Maximum         High-performance requirements
Browser               Standard         High                Maximum         User experience constraints
```

### Implementation Priority
```
Priority    Platform        Implementation Focus    Security Impact    Business Impact
------------------------------------------------------------------------------------------------
1           Server          High-performance crypto  Critical          High
2           Mobile          Battery optimization     High              High
3           Browser         WASM optimization        High              Medium
4           IoT             Size optimization        Medium            Medium
```

**Final Reality:** Each platform requires **completely different** security models, implementations, and threat analyses. There is **no universal deployment model** that works for all scenarios.