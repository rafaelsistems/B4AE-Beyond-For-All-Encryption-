# Threat Model with Security Hardening Features

**Status:** DEPRECATED - Consolidated into THREAT_MODEL_FORMALIZATION.md  
**Version:** 2.0  
**Date:** 2026

## ⚠️ DEPRECATION NOTICE

This document has been **deprecated** and consolidated into the single source of truth for B4AE v2.0 threat modeling:

**→ See [THREAT_MODEL_FORMALIZATION.md](THREAT_MODEL_FORMALIZATION.md)**

## Why This Document Was Deprecated

B4AE v2.0 adopts a **single source of truth** approach for threat modeling to eliminate inconsistencies and duplication. All threat model information is now centralized in `THREAT_MODEL_FORMALIZATION.md`.

## What Replaced This Document

The v2.0 threat model includes:

1. **6 Formal Adversary Types** (A₁-A₆):
   - A₁: Active MITM (Dolev-Yao)
   - A₂: Global Passive Observer
   - A₃: Store-Now-Decrypt-Later Quantum
   - A₄: Partial State Compromise
   - A₅: Timing + Cache Side-Channel
   - A₆: Multi-Session Correlation

2. **Mode-Specific Security Properties**:
   - Mode A (Deniable): XEdDSA only, fast, not PQ
   - Mode B (PQ): Dilithium5 only, slower, quantum-resistant

3. **v2.0 Architectural Improvements**:
   - Stateless cookie challenge (DoS protection)
   - Global unified traffic scheduler (metadata protection)
   - Session key binding (prevents key transplant)
   - Protocol ID derivation (cryptographic agility)

4. **Attack Scenarios and Defenses**:
   - MITM attacks
   - Mode downgrade attacks
   - DoS attacks on handshake
   - Replay attacks
   - Harvest-now-decrypt-later attacks
   - Cross-session traffic correlation
   - Key transplant attacks

## Migration Guide

If you were using this document for:

### Security Analysis
→ See [THREAT_MODEL_FORMALIZATION.md](THREAT_MODEL_FORMALIZATION.md) Section 2-3 for adversary models and security properties

### Attack Scenarios
→ See [THREAT_MODEL_FORMALIZATION.md](THREAT_MODEL_FORMALIZATION.md) Section 7 for attack scenarios and defenses

### Metadata Protection
→ See [V2_ARCHITECTURE_OVERVIEW.md](V2_ARCHITECTURE_OVERVIEW.md) Section 3 for Global Unified Traffic Scheduler

### Side-Channel Resistance
→ See [THREAT_MODEL_FORMALIZATION.md](THREAT_MODEL_FORMALIZATION.md) Section 2.5 for A₅ (Side-Channel Adversary)

### Deployment Guidance
→ See [DEPLOYMENT_MODEL_THREAT_ANALYSIS.md](DEPLOYMENT_MODEL_THREAT_ANALYSIS.md) for platform-specific threat analysis

## Key Differences in v2.0

### v1.0 Approach (This Document)
- Multiple threat model documents
- Security hardening as optional suite
- Per-session metadata protection
- Hybrid signatures (XEdDSA + Dilithium5) always

### v2.0 Approach (New Documents)
- Single source of truth (THREAT_MODEL_FORMALIZATION.md)
- Security-by-default (no optional security)
- Global unified traffic scheduler
- Mode separation (Mode A deniable, Mode B PQ)

## Related v2.0 Documents

- **[THREAT_MODEL_FORMALIZATION.md](THREAT_MODEL_FORMALIZATION.md)** - Single source of truth for threat model
- **[V2_ARCHITECTURE_OVERVIEW.md](V2_ARCHITECTURE_OVERVIEW.md)** - Complete v2.0 architecture
- **[V2_MIGRATION_GUIDE.md](V2_MIGRATION_GUIDE.md)** - Migration from v1.0 to v2.0
- **[FORMAL_VERIFICATION.md](FORMAL_VERIFICATION.md)** - Formal verification requirements
- **[STATE_MACHINE_SPECIFICATION.md](STATE_MACHINE_SPECIFICATION.md)** - v2.0 state machines

---

**For all threat modeling questions, refer to [THREAT_MODEL_FORMALIZATION.md](THREAT_MODEL_FORMALIZATION.md)**
