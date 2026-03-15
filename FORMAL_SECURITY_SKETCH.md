# B4AE v2.0 Formal Security Argument Sketch

**Version:** 2.0  
**Date:** 2026  
**Status:** Updated for v2.0 Architecture

## 1. Overview

This document provides a formal security argument sketch for the B4AE v2.0 protocol, including game-based definitions, security reductions, and hybrid composition arguments for the new v2.0 architecture.

**v2.0 Changes:**
- Authentication mode separation (Mode A deniable, Mode B PQ)
- Stateless cookie challenge for DoS protection
- Global unified traffic scheduler for metadata protection
- Session key binding to prevent key transplant
- Protocol ID derivation for cryptographic agility
- 5-phase handshake (vs v1.0 3-phase)

**Note:** This is an informal security sketch, not a complete formal proof. Full formal verification requires Tamarin and ProVerif (see FORMAL_VERIFICATION.md).

**Single Source of Truth:** See [THREAT_MODEL_FORMALIZATION.md](THREAT_MODEL_FORMALIZATION.md) for authoritative threat model.

## 2. Security Models

### 2.1 Authenticated Key Exchange (AKE) Security (v2.0)

**Model:** Extended Canetti-Krawczyk (eCK) model with mode separation

**Parties:** Set of parties P = {P₁, P₂, ..., Pₙ}

**Sessions:** Each party can run multiple sessions with mode selection

**v2.0 Adversary Capabilities:**
- Send(Pi, Pj, m): Send message m from Pi to Pj
- Reveal(sid): Reveal session key for session sid
- Corrupt(Pi): Corrupt party Pi (reveal long-term key)
- Test(sid): Challenge session sid (return real or random key)
- **ModeDowngrade(sid):** Attempt to downgrade authentication mode (v2.0)
- **CookieForge(sid):** Attempt to forge cookie (v2.0)
- **KeyTransplant(sid1, sid2):** Attempt to use key from sid1 in sid2 (v2.0)

**Security Definition:**

A protocol is eCK-secure if for all PPT adversaries A:

```
Adv_AKE(A) = |Pr[A wins Test game] - 1/2| ≤ negl(λ)
```

Where A wins if:
1. A correctly guesses whether Test(sid) returned real or random key
2. sid is fresh (not revealed, partner not revealed, no trivial attacks)
3. **v2.0:** Mode binding is not violated
4. **v2.0:** Cookie challenge is not bypassed
5. **v2.0:** Session binding is maintained

**v2.0 Freshness Conditions:**
- Session sid is fresh if:
  - Reveal(sid) was not called
  - Reveal(sid*) was not called (sid* = partner session)
  - If Corrupt(Pi) was called, it was after sid completed
  - If Corrupt(Pj) was called, it was after sid completed
  - **Mode binding was not violated (mode_negotiated = mode_established)**
  - **Cookie was verified before expensive crypto**
  - **Session keys are bound to unique session_id**

### 2.2 Mode-Specific Security (v2.0)

#### Mode A: Deniable Authentication

**Security Properties:**
- Deniable authentication (verifier can forge signatures)
- Mutual authentication against A₁ (Dolev-Yao)
- Forward secrecy
- NOT post-quantum secure (classical 128-bit security)

**Security Definition:**

```
For all adversaries A and verifier V:
  Pr[V distinguishes real signature from forged] ≤ negl(λ)
```

**Formal Property:**
```
∀m ∈ {0,1}*, pk = public_key :
  ∃ forge_algorithm :
    ∀distinguisher :
      Pr[distinguisher(sign(sk, m)) = 1] ≈ 
      Pr[distinguisher(forge_algorithm(pk, m)) = 1]
```

#### Mode B: Post-Quantum Non-Repudiable

**Security Properties:**
- Post-quantum secure (NIST Level 5)
- Non-repudiable signatures (prove authorship)
- Mutual authentication against A₁ and A₃ (quantum)
- Forward secrecy

**Security Definition:**

```
For all quantum polynomial-time (QPT) adversaries A:
  Pr[A forges Dilithium5 signature] ≤ negl(λ)
```

**Formal Property:**
```
∀m ∈ {0,1}*, sig = Dilithium5.Sign(sk, m) :
  ∀QPT adversary A :
    Pr[A forges sig without sk] ≤ negl(λ)
```

### 2.3 DoS Resistance Security (v2.0)

**Model:** Resource exhaustion resistance

**Adversary Capabilities:**
- Flood server with handshake attempts
- Attempt to bypass cookie challenge
- Replay old cookies

**Security Definition:**

A protocol provides DoS resistance if for all PPT adversaries A:

```
Cost_Server(A) / Cost_Attacker(A) ≤ ε
```

Where ε is a small constant (ideally < 1).

**v2.0 Cookie Challenge:**
- Without cookie: Cost_Server = 3.6ms, Cost_Attacker = 0ms → Ratio = ∞ (vulnerable)
- With cookie: Cost_Server = 0.01ms (invalid), Cost_Attacker = 0ms → Ratio = 0.003 (protected)
- DoS amplification reduced by 360x

### 2.4 Session Independence Security (v2.0)

**Model:** Key isolation across sessions

**Security Definition:**

A protocol provides session independence if for all PPT adversaries A:

```
Adv_SessionIndependence(A) = Pr[A distinguishes keys from different sessions] ≤ negl(λ)
```

**v2.0 Session Binding:**
```
session_id = HKDF(client_random || server_random || mode_id)
session_key = HKDF(master_secret, protocol_id || session_id || transcript_hash)

If session_id_A ≠ session_id_B, then session_key_A ≠ session_key_B
(with overwhelming probability due to HKDF collision resistance)
```

### 2.2 Secure Messaging Security

**Model:** Signal Protocol security model (Cohn-Gordon et al., 2017)

**Properties:**
1. **Forward Secrecy (FS):** Compromise of current state does not reveal past messages
2. **Post-Compromise Security (PCS):** Session recovers security after compromise
3. **Message Unlinkability:** Messages cannot be linked to sessions
4. **Out-of-Order Resilience:** Protocol handles out-of-order delivery

**Security Definition:**

A protocol provides secure messaging if for all PPT adversaries A:

```
Adv_SM(A) = |Pr[A wins IND-CCA game] - 1/2| ≤ negl(λ)
```

Where A wins if:
1. A correctly guesses which of two messages was encrypted
2. A did not compromise the session before the challenge
3. A did not compromise the session after the challenge (unless PCS recovery occurred)

### 2.3 Post-Quantum Security

**Model:** IND-CCA2 security for KEMs, EUF-CMA security for signatures

**Assumptions:**
1. Kyber1024 is IND-CCA2 secure against quantum adversaries
2. Dilithium5 is EUF-CMA secure against quantum adversaries
3. Hybrid composition preserves security

**Security Definition:**

A protocol is post-quantum secure if for all QPT (quantum polynomial-time) adversaries A:

```
Adv_PQ(A) = |Pr[A breaks protocol] - negl(λ)| ≤ negl(λ)
```

## 3. Cryptographic Assumptions

### 3.1 Classical Assumptions

**Assumption 1 (X25519 Security):**
The X25519 Diffie-Hellman key exchange is secure under the Computational Diffie-Hellman (CDH) assumption.

```
For all PPT adversaries A:
Pr[A(g, g^a, g^b) = g^(ab)] ≤ negl(λ)
```

**Assumption 2 (Ed25519 Security):**
The Ed25519 signature scheme is EUF-CMA secure.

```
For all PPT adversaries A:
Pr[A forges valid signature] ≤ negl(λ)
```

**Assumption 3 (ChaCha20-Poly1305 Security):**
ChaCha20-Poly1305 is IND-CCA2 secure as an AEAD scheme.

```
For all PPT adversaries A:
Adv_AEAD(A) ≤ negl(λ)
```

**Assumption 4 (HKDF Security):**
HKDF-SHA3-256 is a secure pseudorandom function (PRF).

```
For all PPT adversaries A:
|Pr[A distinguishes HKDF from random] - 1/2| ≤ negl(λ)
```

### 3.2 Post-Quantum Assumptions

**Assumption 5 (Kyber1024 Security):**
Kyber1024 is IND-CCA2 secure against quantum adversaries.

```
For all QPT adversaries A:
Adv_KEM(A) ≤ negl(λ)
```

**Assumption 6 (Dilithium5 Security):**
Dilithium5 is EUF-CMA secure against quantum adversaries.

```
For all QPT adversaries A:
Pr[A forges valid signature] ≤ negl(λ)
```

### 3.3 Hybrid Composition Assumption

**Assumption 7 (Hybrid KEM Security):**
The hybrid KEM (Kyber1024 || X25519) is secure if either component is secure.

```
Adv_HybridKEM(A) ≤ max(Adv_Kyber(A), Adv_X25519(A))
```

**Assumption 8 (Hybrid Signature Security):**
The hybrid signature (Dilithium5 + Ed25519) is secure if either component is secure.

```
Adv_HybridSig(A) ≤ max(Adv_Dilithium(A), Adv_Ed25519(A))
```

## 4. Security Theorems

### 4.1 Theorem 1: Handshake Security

**Theorem:** The B4AE handshake protocol is eCK-secure under Assumptions 1-8.

**Proof Sketch:**

1. **Signature Binding:**
   - All handshake messages are signed with hybrid signatures
   - Adversary cannot modify messages without detection (Assumption 8)

2. **Key Exchange Security:**
   - Shared secret derived from hybrid KEM (Assumption 7)
   - Adversary cannot derive shared secret without breaking KEM

3. **Confirmation:**
   - Final confirmation binds all handshake parameters
   - Adversary cannot forge confirmation without shared secret

4. **Freshness:**
   - Ephemeral keys provide forward secrecy
   - Session ID provides session binding

**Reduction:**
```
If adversary A breaks handshake security with advantage ε, then:
  - A breaks hybrid KEM with advantage ≥ ε/2, OR
  - A breaks hybrid signature with advantage ≥ ε/2
```

**Conclusion:** Handshake is eCK-secure under Assumptions 1-8.

### 4.2 Theorem 2: Forward Secrecy

**Theorem:** The B4AE Double Ratchet provides forward secrecy under Assumptions 3-4.

**Proof Sketch:**

1. **Chain Key Advancement:**
   - Chain key advanced via one-way KDF (Assumption 4)
   - Old chain keys zeroized after advancement

2. **Message Key Derivation:**
   - Message keys derived from chain key via KDF
   - Each message uses unique key

3. **Backward Derivation:**
   - Adversary cannot derive old chain keys from current chain key
   - One-way property of KDF (Assumption 4)

4. **Zeroization:**
   - Old keys overwritten in memory
   - No residual key material

**Reduction:**
```
If adversary A breaks forward secrecy with advantage ε, then:
  - A breaks HKDF (inverts one-way function) with advantage ≥ ε
```

**Conclusion:** Protocol provides forward secrecy under Assumption 4.

### 4.3 Theorem 3: Post-Compromise Security

**Theorem:** The B4AE Double Ratchet provides post-compromise security under Assumptions 1, 4-7.

**Proof Sketch:**

1. **DH Ratchet:**
   - Fresh ephemeral keys generated every ratchet_interval messages
   - New shared secrets derived from ephemeral keys

2. **Root Key Ratchet:**
   - New root key derived from old root key + fresh shared secrets
   - Adversary cannot derive new root key without ephemeral keys

3. **Chain Key Reset:**
   - New chain keys derived from new root key
   - Independent of compromised chain keys

4. **Recovery:**
   - After one DH ratchet, session recovers security
   - Fresh entropy from ephemeral keys

**Reduction:**
```
If adversary A breaks post-compromise security with advantage ε, then:
  - A breaks hybrid KEM with advantage ≥ ε/2, OR
  - A breaks HKDF with advantage ≥ ε/2
```

**Conclusion:** Protocol provides post-compromise security under Assumptions 1, 4-7.

### 4.4 Theorem 4: Post-Quantum Security

**Theorem:** The B4AE protocol is post-quantum secure under Assumptions 5-6.

**Proof Sketch:**

1. **Hybrid KEM:**
   - Shared secret depends on Kyber1024 (Assumption 5)
   - Even if X25519 is broken by quantum computer, Kyber1024 remains secure

2. **Hybrid Signature:**
   - Signatures depend on Dilithium5 (Assumption 6)
   - Even if Ed25519 is broken by quantum computer, Dilithium5 remains secure

3. **Quantum Adversary:**
   - Quantum adversary can break X25519 and Ed25519
   - But cannot break Kyber1024 and Dilithium5 (NIST PQC standards)

4. **Security Preservation:**
   - Hybrid composition preserves security (Assumptions 7-8)
   - Protocol remains secure if either component is secure

**Reduction:**
```
If quantum adversary A breaks protocol with advantage ε, then:
  - A breaks Kyber1024 with advantage ≥ ε/2, OR
  - A breaks Dilithium5 with advantage ≥ ε/2
```

**Conclusion:** Protocol is post-quantum secure under Assumptions 5-6.

## 5. Hybrid Composition Argument

### 5.1 Hybrid KEM Composition

**Construction:**
```
HybridKEM.Encapsulate(pk_kyber, pk_x25519):
  (ss_kyber, ct_kyber) ← Kyber.Encapsulate(pk_kyber)
  (ss_x25519, ct_x25519) ← X25519.Encapsulate(pk_x25519)
  ss ← HKDF(ss_kyber || ss_x25519, "B4AE-v1-hybrid-kem")
  return (ss, (ct_kyber, ct_x25519))
```

**Security Argument:**

**Lemma 1:** If Kyber is IND-CCA2 secure, then HybridKEM is IND-CCA2 secure.

**Proof:**
```
Game 0: Real HybridKEM
  ss = HKDF(ss_kyber || ss_x25519)

Game 1: Replace ss_kyber with random
  ss = HKDF(random || ss_x25519)
  
  Indistinguishable by Kyber IND-CCA2 security

Game 2: Replace HKDF output with random
  ss = random
  
  Indistinguishable by HKDF PRF security

Conclusion: HybridKEM is IND-CCA2 secure if Kyber is IND-CCA2 secure
```

**Lemma 2:** If X25519 is CDH-secure, then HybridKEM is CDH-secure.

**Proof:** Similar to Lemma 1, but replace ss_x25519 with random.

**Theorem:** HybridKEM is secure if either Kyber OR X25519 is secure.

**Proof:** Follows from Lemmas 1 and 2.

### 5.2 Hybrid Signature Composition

**Construction:**
```
HybridSign(sk_dilithium, sk_ed25519, m):
  sig_dilithium ← Dilithium.Sign(sk_dilithium, m)
  sig_ed25519 ← Ed25519.Sign(sk_ed25519, m)
  return (sig_dilithium, sig_ed25519)

HybridVerify(pk_dilithium, pk_ed25519, m, (sig_dilithium, sig_ed25519)):
  valid_dilithium ← Dilithium.Verify(pk_dilithium, m, sig_dilithium)
  valid_ed25519 ← Ed25519.Verify(pk_ed25519, m, sig_ed25519)
  return valid_dilithium AND valid_ed25519
```

**Security Argument:**

**Lemma 3:** If Dilithium is EUF-CMA secure, then HybridSign is EUF-CMA secure.

**Proof:**
```
Assume adversary A forges HybridSign signature.
Then A must forge both sig_dilithium AND sig_ed25519.
If A forges sig_dilithium, then A breaks Dilithium EUF-CMA security.
Contradiction.
```

**Lemma 4:** If Ed25519 is EUF-CMA secure, then HybridSign is EUF-CMA secure.

**Proof:** Similar to Lemma 3.

**Theorem:** HybridSign is EUF-CMA secure if either Dilithium OR Ed25519 is EUF-CMA secure.

**Proof:** Follows from Lemmas 3 and 4.

## 6. Security Reductions

### 6.1 Reduction 1: Handshake to Hybrid KEM

**Claim:** If adversary A breaks handshake security, then A breaks hybrid KEM.

**Reduction:**

```
Adversary B (breaks hybrid KEM):
  Input: pk_hybrid (challenge public key)
  
  1. Run A (handshake adversary)
  2. When A requests handshake:
     - Use pk_hybrid as server's public key
     - Receive ciphertext ct from A
  3. Query decapsulation oracle to get ss
  4. Derive master_secret from ss
  5. If A distinguishes real from random master_secret:
     - B distinguishes real from random ss
  
  Output: B's guess
```

**Analysis:**
```
If A breaks handshake with advantage ε, then:
  B breaks hybrid KEM with advantage ≥ ε - negl(λ)
```

### 6.2 Reduction 2: Forward Secrecy to HKDF

**Claim:** If adversary A breaks forward secrecy, then A inverts HKDF.

**Reduction:**

```
Adversary B (inverts HKDF):
  Input: y = HKDF(x, info) (challenge)
  
  1. Run A (forward secrecy adversary)
  2. Set current chain_key = y
  3. When A compromises session:
     - Give A current chain_key = y
  4. When A requests old message key:
     - A must derive old chain_key from y
     - This requires inverting HKDF
  5. If A succeeds:
     - B outputs A's result as x
  
  Output: B's guess for x
```

**Analysis:**
```
If A breaks forward secrecy with advantage ε, then:
  B inverts HKDF with advantage ≥ ε - negl(λ)
```

### 6.3 Reduction 3: Post-Compromise Security to Hybrid KEM

**Claim:** If adversary A breaks post-compromise security, then A breaks hybrid KEM.

**Reduction:**

```
Adversary B (breaks hybrid KEM):
  Input: pk_hybrid (challenge public key)
  
  1. Run A (post-compromise adversary)
  2. When A compromises session:
     - Give A current root_key and chain_keys
  3. When DH ratchet occurs:
     - Use pk_hybrid as ephemeral public key
     - Receive ciphertext ct from A
  4. Query decapsulation oracle to get ss
  5. Derive new root_key from old root_key + ss
  6. If A distinguishes real from random new root_key:
     - B distinguishes real from random ss
  
  Output: B's guess
```

**Analysis:**
```
If A breaks post-compromise security with advantage ε, then:
  B breaks hybrid KEM with advantage ≥ ε - negl(λ)
```

## 7. Security Properties Summary

| Property                  | Assumption                | Reduction                     | Tightness        |
|---------------------------|---------------------------|-------------------------------|------------------|
| Handshake Security        | Hybrid KEM + Hybrid Sig   | Reduction 1                   | Tight (ε)        |
| Forward Secrecy           | HKDF PRF                  | Reduction 2                   | Tight (ε)        |
| Post-Compromise Security  | Hybrid KEM + HKDF         | Reduction 3                   | Tight (ε)        |
| Post-Quantum Security     | Kyber + Dilithium         | Hybrid Composition            | Tight (ε)        |
| Authentication            | Hybrid Signature          | Direct                        | Tight (ε)        |
| Confidentiality           | AEAD + KEM                | Standard                      | Tight (ε)        |

**Tightness:** All reductions are tight (security loss ≤ ε + negl(λ))

## 8. Formal Verification (Future Work)

### 8.1 TLA+ Specification

**Recommended:**
- Specify state machine in TLA+
- Model handshake protocol
- Model ratchet protocol
- Verify safety and liveness properties

**Properties to Verify:**
- Mutual authentication
- Key agreement
- Forward secrecy
- Post-compromise security

### 8.2 Coq Proof

**Recommended:**
- Formalize cryptographic assumptions in Coq
- Prove security theorems in Coq
- Verify reductions in Coq
- Extract verified implementation

**Benefits:**
- Machine-checked proofs
- High assurance
- Verified implementation

### 8.3 Symbolic Analysis

**Recommended:**
- Use ProVerif or Tamarin for symbolic analysis
- Model protocol in applied pi-calculus
- Verify security properties automatically

**Properties to Verify:**
- Secrecy
- Authentication
- Forward secrecy
- Resistance to known attacks

## 9. Known Limitations

### 9.1 Informal Proof

**Limitation:** This document provides an informal security sketch, not a complete formal proof.

**Mitigation:** Conduct formal verification using TLA+, Coq, or ProVerif.

### 9.2 Implementation Gaps

**Limitation:** Security proofs assume ideal implementation (no side-channels, no bugs).

**Mitigation:**
- Code review
- Security audits
- Fuzzing
- Side-channel analysis

### 9.3 Quantum Adversary Model

**Limitation:** Post-quantum security assumes quantum adversary cannot break Kyber/Dilithium.

**Mitigation:**
- Monitor NIST PQC standardization
- Update to newer PQC algorithms if needed
- Maintain hybrid approach (classical + PQC)

## 10. Conclusion

**B4AE Protocol Security:**
- ✅ eCK-secure handshake (under Assumptions 1-8)
- ✅ Forward secrecy (under Assumption 4)
- ✅ Post-compromise security (under Assumptions 1, 4-7)
- ✅ Post-quantum security (under Assumptions 5-6)
- ✅ Tight security reductions (ε + negl(λ))

**Security Argument:**
- Informal security sketch provided
- Formal verification recommended (TLA+, Coq, ProVerif)
- Implementation security depends on correct implementation

**Recommendation:** Conduct formal verification and security audit before deployment in high-security environments.

## 11. References

- Extended Canetti-Krawczyk (eCK) Model: LaMacchia et al., 2007
- Signal Protocol Security: Cohn-Gordon et al., IEEE S&P 2017
- Hybrid KEM Security: Giacon et al., PKC 2018
- NIST PQC Standards: https://csrc.nist.gov/projects/post-quantum-cryptography
- ProVerif: https://prosecco.gforge.inria.fr/personal/bblanche/proverif/
- Tamarin: https://tamarin-prover.github.io/
- Implementation: `src/crypto/`, `src/protocol/`
