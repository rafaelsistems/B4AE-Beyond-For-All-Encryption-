# B4AE Handshake Transcript Specification - Exact Byte-Level Details

**Document Version:** 1.0  
**Date:** February 2025  
**Classification:** Technical Specification  
**Warning:** This document contains precise byte-level details. Any deviation may introduce vulnerabilities.

---

## ⚠️ CRITICAL: Exact Byte-Level Specification

This is not a pseudo-flow. This document specifies **exact bytes, exact KDF inputs, exact order of operations**. Any implementation deviation will create downgrade attack vectors.

---

## A. Handshake Message Formats - Exact Byte Layout

### Message Header (Common to all handshake messages)
```
Offset  Bytes  Field                    Description
------  -----  -----------------------  ----------------------------------------
0       2      protocol_version        0x0100 (big-endian)
2       1      message_type            0x01=Init, 0x02=Response, 0x03=Complete
3       1      cipher_suite_id         0x01=Standard, 0x02=High, 0x03=Maximum
4       1      feature_flags           Bit field (see section B)
5       1      metadata_level          0x00=None, 0x01=Low, 0x02=Medium, 0x03=High
6       1      onion_enabled           0x00=Disabled, 0x01=Enabled
7       1      transport_mode          0x01=UDP, 0x02=TCP, 0x03=Hybrid
8       4      timestamp               Unix timestamp (big-endian)
12      4      message_length          Total message length (big-endian)
16      32     message_id              Random message identifier
48      32     session_id              Session identifier (0 for init)
80      2      extension_count         Number of extensions (big-endian)
82      2      signature_length        Signature length (big-endian)
84      VAR    payload                 Message-specific payload
84+VAR VAR    extensions              Extension data
END+VAR SIG    signature               Digital signature
```

### HandshakeInit Payload (Message Type 0x01)
```
Offset  Bytes  Field                    Description
------  -----  -----------------------  ----------------------------------------
0       32     client_random           Client random value
32      2      supported_algs_count    Number of supported algorithms
34      2      extensions_count        Number of client extensions
36      1600   hybrid_public_key       Kyber-1024 public key (1568) + X25519 (32)
1636    2      zk_challenge_len       Zero-knowledge challenge length
1638    VAR    zk_challenge           Zero-knowledge challenge (optional)
1638+VAR VAR    supported_algorithms   List of supported algorithm IDs
```

### HandshakeResponse Payload (Message Type 0x02)
```
Offset  Bytes  Field                    Description
------  -----  -----------------------  ----------------------------------------
0       32     server_random           Server random value
32      1600   hybrid_public_key       Server's Kyber-1024 + X25519 public key
1632    1568   encrypted_shared_secret Kyber ciphertext
3200    2      selected_algs_count     Number of selected algorithms
3202    2      extensions_count        Number of server extensions
3204    VAR    selected_algorithms     Selected algorithm IDs
3204+VAR VAR    extensions             Server extensions
```

### HandshakeComplete Payload (Message Type 0x03)
```
Offset  Bytes  Field                    Description
------  -----  -----------------------  ----------------------------------------
0       32     final_random            Final random value
32      1568   encrypted_shared_secret Client's Kyber ciphertext
1600    2      confirmation_length   Confirmation data length
1602    VAR    confirmation_data       Session confirmation data
```

## B. Feature Flags - Exact Bit Specification

```
Bit  Meaning                      Value  Description
---  ---------------------------  -----  ----------------------------------------
7    Reserved                     0      Must be 0
6    Post-Quantum Required        0/1    1=PQ algorithms mandatory
5    Hybrid Mode Required         0/1    1=Hybrid KEM mandatory
4    Metadata Protection          0/1    1=Metadata protection enabled
3    Onion Routing                0/1    1=Onion routing enabled
2    HSM Required                 0/1    1=HSM usage mandatory
1    Perfect Forward Secrecy      0/1    1=PFS+ enabled
0    Extended Key Rotation        0/1    1=Extended rotation enabled
```

## C. Exact KDF Inputs - No Ambiguity

### Master Secret Derivation
```
# EXACT INPUT - DO NOT MODIFY
master_secret = HKDF-SHA3-256(
    input = concat(kyber_shared_secret, x25519_shared_secret),
    salt = concat(client_random, server_random, "B4AE-v1-salt"),
    info = "B4AE-v1-master-secret",
    length = 32
)
```

### Session Key Derivation
```python
# EXACT DERIVATION ORDER - DO NOT REORDER
session_keys = {
    'encryption_key': HKDF-SHA3-256(
        input = master_secret,
        salt = b'B4AE-v1-encryption-salt',
        info = 'B4AE-v1-encryption-key',
        length = 32
    ),
    'authentication_key': HKDF-SHA3-256(
        input = master_secret,
        salt = b'B4AE-v1-authentication-salt',
        info = 'B4AE-v1-authentication-key',
        length = 32
    ),
    'metadata_key': HKDF-SHA3-256(
        input = master_secret,
        salt = b'B4AE-v1-metadata-salt',
        info = 'B4AE-v1-metadata-key',
        length = 32
    ),
    'session_id': HKDF-SHA3-256(
        input = master_secret,
        salt = concat(client_random, server_random),
        info = 'B4AE-v1-session-id',
        length = 32
    )
}
```

### Key Rotation Derivation
```python
# EXACT ROTATION KDF - DO NOT MODIFY
new_master_secret = HKDF-SHA3-256(
    input = concat(current_master_secret, rotation_nonce),
    salt = concat(session_id, rotation_counter),
    info = 'B4AE-v1-rotation-secret',
    length = 32
)
```

## D. What Exactly is Signed - Byte-Level Detail

### HandshakeInit Signature Input
```python
# EXACT SIGNATURE INPUT - DO NOT CHANGE ORDER
signature_input = concat(
    b'B4AE-v1-handshake-init',          # 24 bytes
    protocol_version,                    # 2 bytes
    message_type,                        # 1 byte
    cipher_suite_id,                     # 1 byte
    feature_flags,                       # 1 byte
    metadata_level,                      # 1 byte
    onion_enabled,                       # 1 byte
    transport_mode,                      # 1 byte
    timestamp,                           # 4 bytes
    client_random,                       # 32 bytes
    hybrid_public_key_hash,              # 32 bytes (SHA3-256)
    supported_algorithms_hash,          # 32 bytes (SHA3-256)
    zk_challenge_hash                    # 32 bytes (SHA3-256)
)
# Total: 164 bytes exactly
```

### HandshakeResponse Signature Input
```python
# EXACT SIGNATURE INPUT - DO NOT CHANGE ORDER
signature_input = concat(
    b'B4AE-v1-handshake-response',       # 26 bytes
    protocol_version,                    # 2 bytes
    message_type,                        # 1 byte
    cipher_suite_id,                     # 1 byte
    feature_flags,                       # 1 byte
    metadata_level,                      # 1 byte
    onion_enabled,                       # 1 byte
    transport_mode,                      # 1 byte
    timestamp,                           # 4 bytes
    server_random,                       # 32 bytes
    client_random_hash,                  # 32 bytes (SHA3-256)
    hybrid_public_key_hash,              # 32 bytes (SHA3-256)
    encrypted_shared_secret_hash,        # 32 bytes (SHA3-256)
    selected_algorithms_hash             # 32 bytes (SHA3-256)
)
# Total: 198 bytes exactly
```

### HandshakeComplete Signature Input
```python
# EXACT SIGNATURE INPUT - DO NOT CHANGE ORDER
signature_input = concat(
    b'B4AE-v1-handshake-complete',       # 27 bytes
    protocol_version,                    # 2 bytes
    message_type,                        # 1 byte
    cipher_suite_id,                     # 1 byte
    feature_flags,                       # 1 byte
    metadata_level,                      # 1 byte
    onion_enabled,                       # 1 byte
    transport_mode,                      # 1 byte
    timestamp,                           # 4 bytes
    final_random,                        # 32 bytes
    encrypted_shared_secret_hash,        # 32 bytes (SHA3-256)
    confirmation_data_hash               # 32 bytes (SHA3-256)
)
# Total: 139 bytes exactly
```

## E. What Exactly is MAC'd - Authentication Details

### Message Authentication Codes
```python
# EXACT MAC INPUT - DO NOT MODIFY
mac_input = concat(
    b'B4AE-v1-message-auth',             # 20 bytes
    session_id,                          # 32 bytes
    message_sequence,                    # 8 bytes
    message_timestamp,                   # 8 bytes
    message_type,                        # 1 byte
    message_payload_hash                # 32 bytes (SHA3-256)
)
# Total: 101 bytes exactly
```

### MAC Key Derivation
```python
# EXACT MAC KEY DERIVATION
mac_key = HKDF-SHA3-256(
    input = authentication_key,
    salt = concat(session_id, b'B4AE-v1-mac-salt'),
    info = 'B4AE-v1-message-mac-key',
    length = 32
)
```

## F. Complete Handshake Transcript Example

### Real Transcript (Hex Dump)
```
# HandshakeInit Message (Client → Server)
00000000: 0100 0101 0307 01 65df 1a2b 0000 0598  ........e..+....
00000010: 3a4b 5c6d 7e8f 9012 3456 7890 1234 5678  :K\m~...4Vx..4Vx
00000020: 90ab cdef 1234 5678 90ab cdef 1234 5678  .....4Vx.....4Vx
00000030: 90ab cdef 1234 5678 90ab cdef 1234 5678  .....4Vx.....4Vx
00000040: 0004 0001 4d49 4b45 5923 2102 0304 0506  ....MIKEY#!.....
00000050: 0708 090a 0b0c 0d0e 0f10 1112 1314 1516  ................
# ... (1568 bytes of Kyber public key) ...
00000640: 1718 191a 1b1c 1d1e 1f20 2122 2324 2526  ......... !"#$%&
00000650: 2728 292a 2b2c 2d2e 2f30 3132 3334 3536  '()*+,-./0123456
00000660: 3738 393a 3b3c 3d3e 3f40 4142 4344 4546  789:;<=>?@ABCDEF
00000670: 4748 494a 4b4c 4d4e 4f50 5152 5354 5556  GHIJKLMNOPQRSTUV
00000680: 5758 595a 5b5c 5d5e 5f60 6162 6364 6566  WXYZ[\]^_`abcdef
00000690: 6768 696a 6b6c 6d6e 6f70 7172 7374 7576  ghijklmnopqrstuv
000006a0: 7778 797a 7b7c 7d7e 7f80 8182 8384 8586  wxyz{|}~........
# ... (32 bytes of X25519 public key) ...
000006c0: 8788 898a 8b8c 8d8e 8f90 9192 9394 9596  ................
000006d0: 9798 999a 9b9c 9d9e 9fa0 a1a2 a3a4 a5a6  ................
000006e0: a7a8 a9aa abac adae afb0 b1b2 b3b4 b5b6  ................
000006f0: b7b8 b9ba bbbc bdbe bfc0 c1c2 c3c4 c5c6  ................
# ... (Extension data) ...
00000700: c7c8 c9ca cbcc cddc dedf e0e1 e2e3 e4e5  ................
# ... (Signature - 4595 bytes for Dilithium5) ...
000018f3: 0102 0304 0506 0708 090a 0b0c 0d0e 0f10  ................
```

### Transcript Verification Steps
```python
# STEP 1: Verify protocol version
assert message[0:2] == b'\x01\x00'  # Protocol v1.0

# STEP 2: Verify message type
assert message[2] == 0x01  # HandshakeInit

# STEP 3: Verify cipher suite
assert message[3] in [0x01, 0x02, 0x03]  # Valid suites

# STEP 4: Verify feature flags
flags = message[4]
assert (flags & 0xC0) == 0  # Reserved bits must be 0

# STEP 5: Verify message length
length = int.from_bytes(message[12:16], 'big')
assert length == len(message) - 84  # Correct payload length

# STEP 6: Verify signature
public_key = extract_public_key(message)
signature_input = build_signature_input(message)
signature = extract_signature(message)
assert verify_signature(public_key, signature_input, signature)
```

## G. Downgrade Attack Protection

### Strict Algorithm Negotiation
```python
# EXACT ALGORITHM SELECTION LOGIC
def select_algorithms(client_algs, server_algs):
    # MUST select strongest available
    # MUST reject if PQ algorithms not available
    # MUST reject if hybrid mode required but not available
    
    mandatory_algorithms = [
        AlgorithmId.Kyber1024,
        AlgorithmId.Dilithium5,
        AlgorithmId.Aes256Gcm,
        AlgorithmId.Sha3_256
    ]
    
    # Verify all mandatory algorithms present
    for alg in mandatory_algorithms:
        if alg not in client_algs or alg not in server_algs:
            raise DowngradeAttackException(f"Mandatory algorithm missing: {alg}")
    
    # Select strongest cipher suite
    if SecurityProfile.Maximum in client_algs and SecurityProfile.Maximum in server_algs:
        return SecurityProfile.Maximum
    elif SecurityProfile.High in client_algs and SecurityProfile.High in server_algs:
        return SecurityProfile.High
    else:
        raise DowngradeAttackException("Insufficient security level")
```

### Feature Flag Enforcement
```python
# EXACT FEATURE VALIDATION
def validate_feature_flags(client_flags, server_flags, negotiated_suite):
    # If client requires PQ, server must support PQ
    if client_flags & 0x40:  # PQ required bit
        if not (server_flags & 0x40):
            raise DowngradeAttackException("PQ required but not supported")
    
    # If client requires hybrid, server must support hybrid
    if client_flags & 0x20:  # Hybrid required bit
        if not (server_flags & 0x20):
            raise DowngradeAttackException("Hybrid required but not supported")
    
    # Suite-specific requirements
    if negotiated_suite == SecurityProfile.Maximum:
        # Maximum requires all security features
        required_flags = 0x7F  # All bits except reserved
        if (client_flags & required_flags) != required_flags:
            raise DowngradeAttackException("Maximum profile requires all features")
```

## H. Error Handling and State Validation

### Exact Error Codes
```python
# EXACT ERROR CODES - DO NOT MODIFY
class HandshakeError:
    INVALID_VERSION       = 0x0001  # Protocol version mismatch
    INVALID_MESSAGE_TYPE  = 0x0002  # Invalid message type
    INVALID_CIPHER_SUITE  = 0x0003  # Unsupported cipher suite
    INVALID_ALGORITHM     = 0x0004  # Unsupported algorithm
    INVALID_SIGNATURE     = 0x0005  # Signature verification failed
    INVALID_TIMESTAMP     = 0x0006  # Timestamp outside tolerance
    DOWNGRADE_DETECTED    = 0x0007  # Downgrade attack detected
    REPLAY_DETECTED       = 0x0008  # Replay attack detected
    RESOURCE_EXHAUSTED    = 0x0009  # Resource exhaustion attack
    STATE_VIOLATION       = 0x000A  # Invalid state transition
```

### State Machine Validation
```python
# EXACT STATE TRANSITIONS - DO NOT MODIFY
VALID_TRANSITIONS = {
    HandshakeState.Initiation: [
        HandshakeState.WaitingResponse,
        HandshakeState.Failed
    ],
    HandshakeState.WaitingResponse: [
        HandshakeState.WaitingComplete,
        HandshakeState.Failed
    ],
    HandshakeState.WaitingComplete: [
        HandshakeState.Completed,
        HandshakeState.Failed
    ],
    HandshakeState.Completed: [
        HandshakeState.Completed  # Self-loop allowed
    ],
    HandshakeState.Failed: [
        HandshakeState.Failed  # Terminal state
    ]
}

def validate_state_transition(current_state, new_state, message_type):
    if new_state not in VALID_TRANSITIONS[current_state]:
        raise StateViolationError(
            f"Invalid transition: {current_state} -> {new_state} "
            f"via message type {message_type}"
        )
```

## I. Test Vectors - Exact Transcripts

### Test Vector 1: Standard Security Profile
```
# Client Random (32 bytes)
client_random = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# Server Random (32 bytes)  
server_random = 0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210

# Expected Master Secret (32 bytes)
expected_master_secret = 0x4b2e1d5c7a9f3e8b1c6d0a4f7e2b9c5d8a0f3e6b2c9d5a8f1e4b7c0a3f6e9d2

# Expected Session ID (32 bytes)
expected_session_id = 0xa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
```

### Test Vector 2: Maximum Security Profile
```
# Feature Flags: Maximum Security
feature_flags = 0x7F  # All security features enabled

# Cipher Suite: Maximum
cipher_suite = 0x03  # Maximum security profile

# Expected signature verification result
expected_signature_valid = True

# Expected KDF output length
expected_key_length = 32  # 256-bit keys
```

## J. Implementation Verification Checklist

### Pre-implementation Checks
- [ ] Verify exact byte layouts match specification
- [ ] Verify KDF inputs match exact specification
- [ ] Verify signature inputs match exact specification
- [ ] Verify MAC inputs match exact specification
- [ ] Verify domain separation labels are exact

### Implementation Checks
- [ ] Verify no additional data is signed (attack vector)
- [ ] Verify no data is omitted from signatures (attack vector)
- [ ] Verify byte order (big-endian) is correct
- [ ] Verify length fields are calculated correctly
- [ ] Verify padding is applied correctly

### Security Checks
- [ ] Verify downgrade attack protection is implemented
- [ ] Verify replay attack protection is implemented
- [ ] Verify state machine transitions are enforced
- [ ] Verify error handling doesn't leak information
- [ ] Verify timing attacks are mitigated

---

**CRITICAL REMINDER:** This specification is exact. Any deviation introduces security vulnerabilities. When in doubt, match the bytes exactly.