# Security Hardening Suite - Threat Model and Security Analysis

**Status:** DEPRECATED - Consolidated into THREAT_MODEL_FORMALIZATION.md  
**Version:** 2.0  
**Date:** 2026

## ⚠️ DEPRECATION NOTICE

This document has been **deprecated** and consolidated into the single source of truth for B4AE v2.0 threat modeling:

**→ See [THREAT_MODEL_FORMALIZATION.md](THREAT_MODEL_FORMALIZATION.md)**

## Why This Document Was Deprecated

B4AE v2.0 adopts a **single source of truth** approach for threat modeling to eliminate inconsistencies and duplication. All threat model information, including security hardening features, is now centralized in `THREAT_MODEL_FORMALIZATION.md`.

## What Replaced This Document

The v2.0 threat model includes all security hardening features as core architectural components:

### 1. Adversary Models (6 Types)

**v1.0 Approach (This Document):**
- Passive Network Observer
- Active Network Attacker
- Global Passive Adversary
- Side-Channel Attacker
- Endpoint Compromise Attacker

**v2.0 Approach (THREAT_MODEL_FORMALIZATION.md):**
- A₁: Active MITM (Dolev-Yao)
- A₂: Global Passive Observer
- A₃: Store-Now-Decrypt-Later Quantum
- A₄: Partial State Compromise
- A₅: Timing + Cache Side-Channel
- A₆: Multi-Session Correlation

### 2. Security Features

**v1.0 Approach (This Document):**
- PADMÉ Padding (optional hardening suite)
- XEdDSA Deniability (optional hardening suite)
- Metadata Protection (optional hardening suite)
- Constant-Time Operations (optional hardening suite)

**v2.0 Approach (Core Architecture):**
- **Mode A (Deniable):** XEdDSA only, fast (~0.3ms), not PQ
- **Mode B (PQ):** Dilithium5 only, slower (~9ms), quantum-resistant
- **Global Traffic Scheduler:** Cross-session metadata protection (always enabled)
- **Constant-Time Operations:** All security-critical code (always enabled)
- **Cookie Challenge:** DoS protection (always enabled)
- **Session Binding:** Key transplant prevention (always enabled)

### 3. Key Architectural Differences

| Aspect | v1.0 (This Document) | v2.0 (New Architecture) |
|--------|---------------------|------------------------|
| Security Features | Optional hardening suite | Security-by-default (always enabled) |
| Authentication | Hybrid (XEdDSA + Dilithium5) always | Mode separation (Mode A or Mode B) |
| Metadata Protection | Per-session, optional | Global unified scheduler, always enabled |
| DoS Protection | None | Cookie challenge (360x improvement) |
| Session Isolation | Weak | Strong (session key binding) |
| Threat Model | Multiple documents | Single source of truth |

## Migration Guide

If you were using this document for:

### Adversary Models
→ See [THREAT_MODEL_FORMALIZATION.md](THREAT_MODEL_FORMALIZATION.md) Section 2 for formal adversary definitions (A₁-A₆)

### Attack Scenarios
→ See [THREAT_MODEL_FORMALIZATION.md](THREAT_MODEL_FORMALIZATION.md) Section 7 for attack scenarios and defenses

### PADMÉ Padding
→ Now part of core protocol, see [V2_ARCHITECTURE_OVERVIEW.md](V2_ARCHITECTURE_OVERVIEW.md)

### XEdDSA Deniability
→ Now Mode A authentication, see [THREAT_MODEL_FORMALIZATION.md](THREAT_MODEL_FORMALIZATION.md) Section 6.1

### Metadata Protection
→ Now Global Unified Traffic Scheduler, see [V2_ARCHITECTURE_OVERVIEW.md](V2_ARCHITECTURE_OVERVIEW.md) Section 3

### Constant-Time Operations
→ See [THREAT_MODEL_FORMALIZATION.md](THREAT_MODEL_FORMALIZATION.md) Section 2.5 for A₅ (Side-Channel Adversary)

### Configuration Recommendations
→ See [V2_MODE_SELECTION_GUIDE.md](V2_MODE_SELECTION_GUIDE.md) (to be created) for mode selection guidance

## Related v2.0 Documents

- **[THREAT_MODEL_FORMALIZATION.md](THREAT_MODEL_FORMALIZATION.md)** - Single source of truth for threat model
- **[V2_ARCHITECTURE_OVERVIEW.md](V2_ARCHITECTURE_OVERVIEW.md)** - Complete v2.0 architecture
- **[V2_MIGRATION_GUIDE.md](V2_MIGRATION_GUIDE.md)** - Migration from v1.0 to v2.0
- **[FORMAL_VERIFICATION.md](FORMAL_VERIFICATION.md)** - Formal verification requirements
- **[STATE_MACHINE_SPECIFICATION.md](STATE_MACHINE_SPECIFICATION.md)** - v2.0 state machines
- **[SECURITY_INVARIANTS_HARDENING.md](SECURITY_INVARIANTS_HARDENING.md)** - v2.0 security invariants

## Key v2.0 Improvements

1. **Security-by-Default:** All protections always enabled (no optional security)
2. **Mode Separation:** Clear trade-offs between deniability (Mode A) and post-quantum security (Mode B)
3. **DoS Protection:** Cookie challenge reduces amplification by 360x
4. **Global Metadata Protection:** Cross-session indistinguishability via unified traffic scheduler
5. **Session Isolation:** Cryptographic binding prevents key transplant attacks
6. **Formal Verification:** Tamarin + ProVerif models (in progress)
7. **Single Source of Truth:** One authoritative threat model document

---

**For all threat modeling and security hardening questions, refer to [THREAT_MODEL_FORMALIZATION.md](THREAT_MODEL_FORMALIZATION.md)**
