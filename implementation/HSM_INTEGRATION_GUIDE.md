# B4AE Hardware Security Module (HSM) Integration Guide

**Version:** 1.0  
**Date:** February 2025  

## 🎯 Overview

B4AE supports Hardware Security Module (HSM) integration for enterprise-grade key management and cryptographic operations. This guide covers setup, configuration, and best practices for HSM integration.

## 🔧 Supported HSM Backends

### 1. PKCS#11 Backend (Recommended)
- **SoftHSM2** (Development/Testing)
- **Nitrokey HSM** (Small-scale deployment)
- **YubiHSM 2** (Enterprise)
- **Thales Luna** (Enterprise)
- **Utimaco Se** (Enterprise)

### 2. Cloud HSM Support
- AWS CloudHSM
- Azure Dedicated HSM
- Google Cloud HSM

## 📋 Prerequisites

### Software Requirements
- Rust 1.75+ with Cargo
- PKCS#11 library for your HSM
- B4AE with HSM features enabled

### HSM Requirements
- PKCS#11 compliant device
- Administrator access for initialization
- User PIN for authentication

## 🔨 Installation and Setup

### Step 1: Install HSM Software

#### SoftHVM2 (Development)
```bash
# Ubuntu/Debian
sudo apt install libsofthsm2

# macOS
brew install softhsm

# Create token directory
mkdir -p /tmp/tokens
export SOFTHSM2_CONF=/tmp/softhsm2.conf
```

#### Nitrokey HSM
```bash
# Install OpenSC for PKCS#11 support
sudo apt install opensc-pkcs11

# Or build from source
git clone https://github.com/OpenSC/OpenSC.git
cd OpenSC
./bootstrap
./configure --enable-pkcs11
make && sudo make install
```

### Step 2: Configure B4AE with HSM Support

Add to your `Cargo.toml`:
```toml
[dependencies]
b4ae = { version = "1.0", features = ["hsm", "hsm-pkcs11"] }
```

### Step 3: Initialize HSM

#### SoftHSM2 Initialization
```bash
# Create configuration
echo "directories.tokendir = /tmp/tokens" > /tmp/softhsm2.conf
echo "objectstore.backend = file" >> /tmp/softhsm2.conf

# Initialize token
softhsm2-util --init-token --slot 0 --label "B4AE-Token" --pin 1234 --so-pin 0000

# Verify setup
softhsm2-util --show-slots
```

#### Nitrokey HSM Initialization
```bash
# Initialize device (requires admin PIN)
nitropy hsm init

# Create DKEK (Device Key Encryption Key)
nitropy hsm create-dkek-share dkek-share.pbe

# Import DKEK
nitropy hsm import-dkek-share dkek-share.pbe
```

## 💻 Code Integration

### Basic HSM Integration

```rust
use b4ae::hsm::pkcs11_enhanced::Pkcs11HsmEnhanced;
use b4ae::hsm::HsmBackend;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize HSM backend
    let hsm = Pkcs11HsmEnhanced::new(
        "/usr/lib/softhsm/libsofthsm2.so", // PKCS#11 library path
        0,                                    // Slot ID
        Some("1234")                          // User PIN
    )?;

    // Generate keypair in HSM
    let public_key = hsm.generate_keypair("b4ae-master-key")?;
    println!("Generated keypair with public key: {:?}", public_key);

    // Sign data using HSM
    let data = b"message to sign";
    let signature = hsm.sign("b4ae-master-key", data)?;
    println!("Signature: {:?}", signature);

    // Verify signature
    let is_valid = hsm.verify("b4ae-master-key", data, &signature)?;
    println!("Signature valid: {}", is_valid);

    Ok(())
}
```

### B4AE Client with HSM Integration

```rust
use b4ae::{B4aeClient, SecurityProfile, B4aeConfig};
use b4ae::hsm::pkcs11_enhanced::Pkcs11HsmEnhanced;

fn setup_hsm_client() -> Result<B4aeClient, Box<dyn std::error::Error>> {
    // Initialize HSM
    let hsm = Pkcs11HsmEnhanced::new(
        "/usr/lib/softhsm/libsofthsm2.so",
        0,
        Some("1234")
    )?;

    // Create configuration with HSM
    let mut config = B4aeConfig::from_profile(SecurityProfile::Enterprise);
    config.hsm_backend = Some(Box::new(hsm));

    // Create client with HSM support
    let client = B4aeClient::with_config(config)?;
    
    Ok(client)
}
```

## 🔐 Security Best Practices

### Key Management
1. **Key Hierarchy**: Use B4AE's MIK→DMK→STK hierarchy with HSM-protected root keys
2. **Key Rotation**: Implement regular key rotation policies
3. **Backup Strategy**: Secure backup of encrypted keys outside HSM
4. **Access Control**: Implement role-based access to HSM operations

### HSM Configuration
1. **Strong PINs**: Use complex PINs (minimum 8 characters)
2. **Authentication**: Enable multi-factor authentication where available
3. **Audit Logging**: Enable comprehensive audit logging
4. **Network Security**: Secure HSM network communications

### Operational Security
1. **Physical Security**: Secure HSM hardware location
2. **Environmental Controls**: Temperature, humidity monitoring
3. **Access Monitoring**: Log all HSM access attempts
4. **Incident Response**: Plan for HSM failure/compromise scenarios

## 📊 Performance Considerations

### HSM Performance Characteristics
- **Key Generation**: 10-100ms depending on algorithm
- **Signing Operations**: 1-10ms for Ed25519, 50-200ms for Dilithium5
- **Encryption/Decryption**: 0.5-5ms for AES operations
- **Network Latency**: Add 1-50ms for network-attached HSMs

### Optimization Strategies
1. **Session Caching**: Reuse HSM sessions when possible
2. **Batch Operations**: Group multiple operations
3. **Local Caching**: Cache frequently accessed keys
4. **Load Balancing**: Distribute across multiple HSMs

## 🚨 Troubleshooting

### Common Issues

#### PKCS#11 Library Not Found
```bash
# Find PKCS#11 libraries
find /usr -name "*.so" | grep pkcs11
find /usr/local -name "*.so" | grep pkcs11

# Set library path
export PKCS11_LIBRARY_PATH=/path/to/library.so
```

#### Authentication Failures
```bash
# Check slot configuration
softhsm2-util --show-slots

# Verify PIN
softhsm2-util --login --slot 0 --pin 1234
```

#### Performance Issues
- Check HSM connection type (USB vs Network)
- Verify session caching is enabled
- Monitor HSM resource utilization
- Consider load balancing across multiple HSMs

### Debug Tools
```bash
# PKCS#11 spy tool (debugging)
pkcs11-spy /usr/lib/softhsm/libsofthsm2.so

# OpenSC tools
pkcs11-tool --list-slots
pkcs11-tool --list-objects
pkcs11-tool --test
```

## 📈 Monitoring and Maintenance

### Health Monitoring
- HSM temperature and environmental conditions
- Authentication attempt logs
- Cryptographic operation performance
- Key usage statistics
- Error rate monitoring

### Maintenance Tasks
- Regular firmware updates
- Backup verification
- Key rotation execution
- Security audit logs review
- Performance optimization

## 🔗 Integration Examples

### Enterprise Deployment
```rust
// Production HSM configuration
let hsm = Pkcs11HsmEnhanced::new(
    "/usr/lib/nitrokey/opensc-pkcs11.so",
    0,
    Some(std::env::var("HSM_PIN")?)
)?;

// Key hierarchy setup
hsm.store_key("MIK", KeyType::GENERIC_SECRET, &master_key)?;
hsm.store_key("DMK", KeyType::GENERIC_SECRET, &device_key)?;
hsm.store_key("STK", KeyType::AES, &storage_key)?;
```

### High-Availability Setup
```rust
// Multiple HSM configuration for redundancy
let hsm_primary = Pkcs11HsmEnhanced::new(
    "/usr/lib/hsm1/libpkcs11.so", 0, Some("pin1")
)?;

let hsm_backup = Pkcs11HsmEnhanced::new(
    "/usr/lib/hsm2/libpkcs11.so", 0, Some("pin2")
)?;

// Implement failover logic
let hsm_backend = if hsm_primary.is_available() {
    Box::new(hsm_primary) as Box<dyn HsmBackend>
} else {
    Box::new(hsm_backup) as Box<dyn HsmBackend>
};
```

## 📚 References

- [PKCS#11 Specification](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html)
- [NIST HSM Guidelines](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [OpenSC Documentation](https://github.com/OpenSC/OpenSC/wiki)
- [SoftHSM2 Documentation](https://github.com/opendnssec/SoftHSMv2)

---

**Support:** For HSM integration support, contact rafaelsistems@gmail.com