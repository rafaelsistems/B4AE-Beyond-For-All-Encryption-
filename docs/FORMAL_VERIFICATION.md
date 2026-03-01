# B4AE v2.0 Formal Verification Requirements

**Version:** 2.0  
**Date:** 2026  
**Status:** Research-Grade Formal Verification Plan  
**Requirement:** Formal verification is MANDATORY for B4AE v2.0

## Overview

B4AE v2.0 requires formal verification using Tamarin and ProVerif to provide machine-checked proofs of security properties. This is a fundamental requirement for research-grade protocol architecture.

**Key Changes from v1.0:**
- Tamarin symbolic verification (REQUIRED)
- ProVerif computational verification (REQUIRED)
- Formal threat model integration
- Mode-specific security properties
- Cookie challenge verification
- Global traffic scheduler properties

**Design Philosophy:** Formally verified (not just tested), machine-checked proofs (not informal arguments).

---

## Verification Status

| Area | Status | Tool | Priority |
|------|--------|------|----------|
| **Tamarin handshake model** | **Required** | **Tamarin** | **P0** |
| **ProVerif handshake model** | **Required** | **ProVerif** | **P0** |
| **Mode A (Deniable) verification** | **Required** | **Tamarin + ProVerif** | **P0** |
| **Mode B (PQ) verification** | **Required** | **Tamarin + ProVerif** | **P0** |
| **Cookie challenge verification** | **Required** | **Tamarin** | **P1** |
| **Mode negotiation verification** | **Required** | **Tamarin** | **P1** |
| Property-based testing (proptest) | Done | proptest | P2 |
| TLA+ model checking | Done (v1.0) | TLC | P3 |
| Coq formal spec | Done (v1.0) | Coq 8.20 | P3 |

---

## 1. Proptest Invariants (Implementasi Sekarang)

### Handshake Invariants
- **Completeness**: Jika init → response → complete valid, kedua pihak punya session keys yang sama
- **No regression**: Handshake output deterministic untuk input yang sama
- **State machine**: Invalid transitions must fail

### Crypto Invariants
- **Encrypt/Decrypt roundtrip**: `decrypt(encrypt(m)) == m`
- **Key uniqueness**: Different keys → different ciphertext
- **Nonce uniqueness**: Same key + different nonce → different ciphertext

### Property Tests Location
- `tests/proptest_invariants.rs` (new)

---

## 2. Formal Specification

### TLA+ (specs/B4AE_Handshake.tla)
- Handshake state machine model
- TLC model checking in CI

### Coq (specs/coq/B4AE_Handshake.v)
- Formal model of handshake state machine
- **safety_theorem**: Reachable states satisfy SafetyInvariant
- Both Completed only after valid handshake sequence

---

## 3. Fuzzing

- **libFuzzer**: `cargo fuzz` untuk message parsing, handshake
- **OSS-Fuzz**: Integration ke Google OSS-Fuzz (optional)
- Existing: `tests/fuzzing_test.rs` (unit-style fuzz targets)

---

## Referensi

- [proptest](https://altsysrq.github.io/proptest-book/)
- [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
- [TLA+](https://lamport.azurewebsites.net/tla/tla.html)

## 1. Tamarin Prover (Symbolic Verification)

### 1.1 Overview

**Purpose:** Symbolic verification of protocol logic against Dolev-Yao adversary

**Model Location:** `specs/tamarin/b4ae_v2_handshake.spthy`

**Adversary Model:** Dolev-Yao (A₁) - complete network control, cannot break cryptography

**Timeline:**
- Phase 1: Model handshake protocol (2 weeks)
- Phase 2: Prove security properties (2 weeks)
- Phase 3: Iterate on findings (2 weeks)

### 1.2 Security Properties to Prove

#### 1.2.1 Mutual Authentication

**Property:** If client accepts session with server, then server initiated that session.

**Tamarin Lemma:**
```
lemma mutual_authentication:
  "All C S t1 t2 #i #j.
    ClientAccepted(C, S, t1) @ i &
    ServerAccepted(S, C, t2) @ j
    ==> (Ex #k. ClientInitiated(C, t1) @ k & k < i)"
```

**Verification Target:** Both Mode A and Mode B

#### 1.2.2 Forward Secrecy

**Property:** Compromise of long-term keys does not reveal past session keys.

**Tamarin Lemma:**
```
lemma forward_secrecy:
  "All C S k #i #j.
    SessionKey(C, S, k) @ i &
    LtkReveal(C) @ j &
    i < j
    ==> not(Ex #k. K(k) @ k)"
```

**Verification Target:** Both Mode A and Mode B

#### 1.2.3 Session Independence

**Property:** Compromise of one session does not affect other sessions.

**Tamarin Lemma:**
```
lemma session_independence:
  "All C S k1 k2 sid1 sid2 #i #j.
    SessionKey(C, S, k1, sid1) @ i &
    SessionKey(C, S, k2, sid2) @ j &
    sid1 ≠ sid2
    ==> k1 ≠ k2"
```

**Verification Target:** Both Mode A and Mode B

#### 1.2.4 No-Downgrade Protection

**Property:** Mode negotiation cannot be downgraded by adversary.

**Tamarin Lemma:**
```
lemma no_downgrade:
  "All C S mode1 mode2 #i #j.
    ModeNegotiated(C, S, mode1) @ i &
    SessionEstablished(C, S, mode2) @ j &
    i < j
    ==> mode1 = mode2"
```

**Verification Target:** Mode negotiation protocol

#### 1.2.5 Key Secrecy

**Property:** Adversary cannot learn session keys.

**Tamarin Lemma:**
```
lemma key_secrecy:
  "All C S k #i.
    SessionKey(C, S, k) @ i
    ==> not(Ex #j. K(k) @ j)"
```

**Verification Target:** Both Mode A and Mode B

#### 1.2.6 Deniability (Mode A Only)

**Property:** Verifier can forge equivalent signatures (Mode A).

**Tamarin Lemma:**
```
lemma deniability_mode_a:
  "All C S sig msg #i.
    VerifiedSignature(C, S, sig, msg) @ i &
    ModeA(C, S) @ i
    ==> (Ex #j. CanForge(S, sig, msg) @ j)"
```

**Verification Target:** Mode A only (XEdDSA)

### 1.3 Tamarin Model Structure

```
theory B4AE_v2_Handshake
begin

// Built-in functions
builtins: hashing, symmetric-encryption, asymmetric-encryption, signing

// Protocol rules
rule ClientInit:
  [ Fr(~client_random), Fr(~eph_x25519), Fr(~eph_kyber) ]
  --[ ClientInitiated($C, ~client_random) ]->
  [ Out(<$C, ~client_random, ~eph_x25519, ~eph_kyber>),
    ClientState($C, ~client_random, ~eph_x25519, ~eph_kyber) ]

rule ServerResponse:
  [ In(<$C, client_random, eph_x25519_c, eph_kyber_c>),
    Fr(~server_random), Fr(~eph_x25519_s), Fr(~eph_kyber_s) ]
  --[ ServerResponded($S, $C, ~server_random) ]->
  [ Out(<$S, ~server_random, ~eph_x25519_s, ~eph_kyber_s>),
    ServerState($S, $C, client_random, ~server_random) ]

rule ModeNegotiation:
  [ In(<$C, supported_modes, preferred_mode>),
    Fr(~server_random) ]
  --[ ModeNegotiated($C, $S, selected_mode) ]->
  [ Out(<$S, selected_mode, ~server_random>),
    ModeBinding($C, $S, selected_mode) ]

rule CookieChallenge:
  [ In(<$C, client_random, timestamp>),
    Fr(~server_secret) ]
  --[ CookieIssued($S, $C, cookie) ]->
  [ Out(<$S, cookie, ~server_random>),
    CookieState($S, $C, cookie, timestamp) ]

// Security properties (lemmas)
lemma mutual_authentication: ...
lemma forward_secrecy: ...
lemma session_independence: ...
lemma no_downgrade: ...
lemma key_secrecy: ...
lemma deniability_mode_a: ...

end
```

### 1.4 Verification Commands

```bash
# Verify all lemmas
tamarin-prover --prove specs/tamarin/b4ae_v2_handshake.spthy

# Verify specific lemma
tamarin-prover --prove=mutual_authentication specs/tamarin/b4ae_v2_handshake.spthy

# Interactive mode
tamarin-prover interactive specs/tamarin/b4ae_v2_handshake.spthy
```

### 1.5 Expected Output

```
==============================================================================
summary of summaries:

analyzed: specs/tamarin/b4ae_v2_handshake.spthy

  mutual_authentication (all-traces): verified (12 steps)
  forward_secrecy (all-traces): verified (18 steps)
  session_independence (all-traces): verified (10 steps)
  no_downgrade (all-traces): verified (8 steps)
  key_secrecy (all-traces): verified (15 steps)
  deniability_mode_a (exists-trace): verified (6 steps)

==============================================================================
```

---

## 2. ProVerif (Computational Verification)

### 2.1 Overview

**Purpose:** Computational verification with cryptographic primitives

**Model Location:** `specs/proverif/b4ae_v2_handshake.pv`

**Adversary Model:** Computational adversary with access to cryptographic operations

**Timeline:**
- Phase 1: Model cryptographic primitives (2 weeks)
- Phase 2: Prove security properties (2 weeks)
- Phase 3: Observational equivalence for deniability (2 weeks)

### 2.2 Security Properties to Prove

#### 2.2.1 Secrecy of Session Keys

**Property:** Adversary cannot learn session keys.

**ProVerif Query:**
```
query attacker(session_key).
```

**Expected Result:** `RESULT not attacker(session_key) is true.`

#### 2.2.2 Authentication Events

**Property:** Authentication events correspond correctly.

**ProVerif Query:**
```
query event(ClientAccepts(C, S, k)) ==> event(ServerSends(S, C, k)).
query event(ServerAccepts(S, C, k)) ==> event(ClientSends(C, S, k)).
```

**Expected Result:** Both queries verified

#### 2.2.3 Correspondence Assertions

**Property:** Handshake messages correspond correctly.

**ProVerif Query:**
```
query event(ClientComplete(C, S, transcript)) ==>
      event(ServerResponse(S, C, transcript)).
```

#### 2.2.4 Observational Equivalence (Deniability)

**Property:** Mode A provides deniability through observational equivalence.

**ProVerif Process:**
```
(* Real protocol *)
let real_protocol = ...

(* Simulated protocol (verifier forges) *)
let simulated_protocol = ...

(* Observational equivalence *)
equivalence real_protocol and simulated_protocol.
```

**Expected Result:** Processes are observationally equivalent

### 2.3 ProVerif Model Structure

```
(* Cryptographic primitives *)
type key.
type nonce.
type pkey.
type skey.

(* Symmetric encryption *)
fun senc(bitstring, key): bitstring.
reduc forall m: bitstring, k: key; sdec(senc(m, k), k) = m.

(* Asymmetric encryption (Kyber) *)
fun aenc(bitstring, pkey): bitstring.
reduc forall m: bitstring, sk: skey; adec(aenc(m, pk(sk)), sk) = m.

(* Signatures (XEdDSA for Mode A, Dilithium for Mode B) *)
fun sign(bitstring, skey): bitstring.
reduc forall m: bitstring, sk: skey; verify(sign(m, sk), m, pk(sk)) = true.
reduc forall m: bitstring, sk: skey; getmess(sign(m, sk)) = m.

(* Key derivation *)
fun kdf(bitstring, bitstring): key.
fun hkdf(bitstring, bitstring, bitstring): key.

(* Hashing *)
fun hash(bitstring): bitstring.

(* Protocol processes *)
let client(pkS: pkey, skC: skey) =
  (* Mode negotiation *)
  new client_random: nonce;
  out(c, (client_random, supported_modes, preferred_mode));
  in(c, (server_random: nonce, selected_mode: bitstring));
  
  (* Cookie challenge *)
  out(c, (client_random, timestamp));
  in(c, (cookie: bitstring, server_random2: nonce));
  
  (* Handshake *)
  new eph_x25519: skey;
  new eph_kyber: skey;
  let handshake_init = (client_random, cookie, pk(eph_x25519), pk(eph_kyber)) in
  let sig_init = sign(handshake_init, skC) in
  out(c, (handshake_init, sig_init));
  
  (* Receive response *)
  in(c, (handshake_response: bitstring, sig_response: bitstring));
  if verify(sig_response, handshake_response, pkS) = true then
  
  (* Derive session key *)
  let shared_x25519 = dh(eph_x25519, get_pk_x25519(handshake_response)) in
  let shared_kyber = adec(get_kyber_ct(handshake_response), eph_kyber) in
  let master_secret = kdf(shared_x25519, shared_kyber) in
  let session_id = hkdf(client_random, server_random, selected_mode) in
  let session_key = hkdf(master_secret, session_id, "session-key") in
  
  event ClientAccepts(client, server, session_key);
  0.

let server(pkC: pkey, skS: skey) =
  (* Mode negotiation *)
  in(c, (client_random: nonce, supported_modes: bitstring, preferred_mode: bitstring));
  new server_random: nonce;
  let selected_mode = select_mode(supported_modes, preferred_mode) in
  out(c, (server_random, selected_mode));
  
  (* Cookie challenge *)
  in(c, (client_random2: nonce, timestamp: bitstring));
  new server_secret: key;
  let cookie = hmac(server_secret, (client_ip, timestamp, client_random2)) in
  out(c, (cookie, server_random));
  
  (* Handshake *)
  in(c, (handshake_init: bitstring, sig_init: bitstring));
  if verify(sig_init, handshake_init, pkC) = true then
  if verify_cookie(cookie, server_secret, client_ip, timestamp, client_random2) = true then
  
  new eph_x25519: skey;
  new eph_kyber: skey;
  let handshake_response = (server_random, pk(eph_x25519), aenc(kyber_ss, get_pk_kyber(handshake_init))) in
  let sig_response = sign(handshake_response, skS) in
  out(c, (handshake_response, sig_response));
  
  (* Derive session key *)
  let shared_x25519 = dh(eph_x25519, get_pk_x25519(handshake_init)) in
  let master_secret = kdf(shared_x25519, kyber_ss) in
  let session_id = hkdf(client_random, server_random, selected_mode) in
  let session_key = hkdf(master_secret, session_id, "session-key") in
  
  event ServerAccepts(server, client, session_key);
  0.

(* Main process *)
process
  new skC: skey; new skS: skey;
  let pkC = pk(skC) in let pkS = pk(skS) in
  out(c, pkC); out(c, pkS);
  ((!client(pkS, skC)) | (!server(pkC, skS)))
```

### 2.4 Verification Commands

```bash
# Verify all queries
proverif specs/proverif/b4ae_v2_handshake.pv

# Verify with detailed output
proverif -html specs/proverif/b4ae_v2_handshake.pv

# Check observational equivalence
proverif -test equiv specs/proverif/b4ae_v2_deniability.pv
```

### 2.5 Expected Output

```
--------------------------------------------------------------
Verification summary:

Query not attacker(session_key) is true.

Query event(ClientAccepts(C,S,k)) ==> event(ServerSends(S,C,k)) is true.

Query event(ServerAccepts(S,C,k)) ==> event(ClientSends(C,S,k)) is true.

Observational equivalence real_protocol ~ simulated_protocol is true.

--------------------------------------------------------------
```

---

## 3. Mode-Specific Verification

### 3.1 Mode A (Deniable) Verification

**Properties to Verify:**
1. ✅ Mutual authentication (Tamarin)
2. ✅ Forward secrecy (Tamarin)
3. ✅ Session independence (Tamarin)
4. ✅ Deniability (ProVerif observational equivalence)
5. ❌ NOT post-quantum secure (documented limitation)

**Tamarin Model:** `specs/tamarin/b4ae_v2_mode_a.spthy`

**ProVerif Model:** `specs/proverif/b4ae_v2_mode_a.pv`

**Deniability Proof:**
- Verifier can forge XEdDSA signatures
- Observational equivalence between real and simulated protocols
- Third parties cannot distinguish real from forged signatures

### 3.2 Mode B (PQ) Verification

**Properties to Verify:**
1. ✅ Mutual authentication (Tamarin)
2. ✅ Forward secrecy (Tamarin)
3. ✅ Session independence (Tamarin)
4. ✅ Post-quantum security (ProVerif with quantum adversary model)
5. ❌ NOT deniable (Dilithium5 is non-repudiable)

**Tamarin Model:** `specs/tamarin/b4ae_v2_mode_b.spthy`

**ProVerif Model:** `specs/proverif/b4ae_v2_mode_b.pv`

**Post-Quantum Security:**
- Kyber1024 provides quantum-resistant key exchange
- Dilithium5 provides quantum-resistant signatures
- Security under quantum adversary model

---

## 4. Cookie Challenge Verification

### 4.1 Properties to Verify

**DoS Resistance:**
- Server performs cheap cookie verification before expensive crypto
- Invalid cookies rejected in ~0.01ms
- Valid cookies proceed to signature verification (~3-5ms)

**Statelessness:**
- Server stores no state before cookie verification
- Cookie = HMAC(server_secret, client_ip || timestamp || client_random)
- Replay protection via Bloom filter

**Tamarin Lemma:**
```
lemma dos_resistance:
  "All S C #i.
    ExpensiveCryptoPerformed(S, C) @ i
    ==> (Ex #j. ValidCookieVerified(S, C) @ j & j < i)"
```

### 4.2 Replay Protection Verification

**Tamarin Lemma:**
```
lemma replay_protection:
  "All S C cookie #i #j.
    CookieAccepted(S, C, cookie) @ i &
    CookieAccepted(S, C, cookie) @ j
    ==> i = j"
```

---

## 5. Property-Based Testing (Proptest)

### 5.1 Handshake Invariants

**Location:** `tests/proptest_invariants.rs`

**Properties:**
- **Completeness:** Valid handshake → both parties have same session keys
- **Determinism:** Same inputs → same outputs
- **State machine:** Invalid transitions must fail

### 5.2 Crypto Invariants

**Properties:**
- **Encrypt/Decrypt roundtrip:** `decrypt(encrypt(m)) == m`
- **Key uniqueness:** Different keys → different ciphertext
- **Nonce uniqueness:** Same key + different nonce → different ciphertext

### 5.3 Mode Negotiation Invariants

**Properties:**
- **Intersection non-empty:** Compatible modes exist → mode selected
- **Intersection empty:** No compatible modes → error
- **Preference respected:** Client preferred mode in intersection → selected

---

## 6. Verification Timeline

### Phase 1: Model Development (Weeks 1-2)

**Deliverables:**
- Tamarin model of handshake protocol
- ProVerif model of handshake protocol
- Mode A and Mode B models
- Cookie challenge model
- Mode negotiation model

**Milestones:**
- Week 1: Basic handshake model
- Week 2: Mode-specific models and cookie challenge

### Phase 2: Property Verification (Weeks 3-4)

**Deliverables:**
- Tamarin proofs for all lemmas
- ProVerif proofs for all queries
- Observational equivalence for deniability
- DoS resistance verification

**Milestones:**
- Week 3: Core security properties (auth, forward secrecy, session independence)
- Week 4: Mode-specific properties and cookie challenge

### Phase 3: Iteration and Documentation (Weeks 5-6)

**Deliverables:**
- Attack trace analysis (if any found)
- Protocol fixes (if vulnerabilities discovered)
- Re-verification after fixes
- Verification report document

**Milestones:**
- Week 5: Analyze findings, fix issues
- Week 6: Final verification and documentation

---

## 7. Verification Deliverables

### 7.1 Tamarin Models

- `specs/tamarin/b4ae_v2_handshake.spthy` - Main handshake model
- `specs/tamarin/b4ae_v2_mode_a.spthy` - Mode A (Deniable) model
- `specs/tamarin/b4ae_v2_mode_b.spthy` - Mode B (PQ) model
- `specs/tamarin/b4ae_v2_cookie.spthy` - Cookie challenge model

### 7.2 ProVerif Models

- `specs/proverif/b4ae_v2_handshake.pv` - Main handshake model
- `specs/proverif/b4ae_v2_mode_a.pv` - Mode A with deniability
- `specs/proverif/b4ae_v2_mode_b.pv` - Mode B with PQ security
- `specs/proverif/b4ae_v2_deniability.pv` - Observational equivalence

### 7.3 Verification Report

**Location:** `docs/FORMAL_VERIFICATION_COMPLETION.md`

**Contents:**
- Verification results for all properties
- Attack traces (if any found)
- Protocol fixes (if vulnerabilities discovered)
- Security theorem statement
- Formal proofs summary

### 7.4 Security Theorem

**Informal Statement:**

> B4AE v2.0 handshake protocol provides mutual authentication, forward secrecy, session independence, and no-downgrade protection against a Dolev-Yao adversary. Mode A provides deniable authentication with classical security. Mode B provides post-quantum non-repudiable authentication.

**Formal Statement (Tamarin):**

```
theorem b4ae_v2_security:
  "All C S k #i.
    SessionEstablished(C, S, k) @ i
    ==> (
      (* Mutual authentication *)
      (Ex #j. ClientInitiated(C) @ j & j < i) &
      (Ex #k. ServerResponded(S) @ k & k < i) &
      
      (* Forward secrecy *)
      (All #m. LtkReveal(C) @ m & m > i ==> not(Ex #n. K(k) @ n)) &
      
      (* Session independence *)
      (All k2 sid2 #p. SessionKey(C, S, k2, sid2) @ p & sid ≠ sid2 ==> k ≠ k2) &
      
      (* No downgrade *)
      (All mode1 mode2 #q #r. ModeNegotiated(C, S, mode1) @ q & 
                               SessionEstablished(C, S, mode2) @ r & 
                               q < r ==> mode1 = mode2)
    )"
```

---

## 8. Integration with CI/CD

### 8.1 Automated Verification

**GitHub Actions Workflow:** `.github/workflows/formal-verification.yml`

```yaml
name: Formal Verification

on: [push, pull_request]

jobs:
  tamarin:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install Tamarin
        run: |
          wget https://github.com/tamarin-prover/tamarin-prover/releases/download/1.8.0/tamarin-prover-1.8.0-linux64.tar.gz
          tar -xzf tamarin-prover-1.8.0-linux64.tar.gz
      - name: Verify Tamarin models
        run: |
          ./tamarin-prover --prove specs/tamarin/b4ae_v2_handshake.spthy
          ./tamarin-prover --prove specs/tamarin/b4ae_v2_mode_a.spthy
          ./tamarin-prover --prove specs/tamarin/b4ae_v2_mode_b.spthy
  
  proverif:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install ProVerif
        run: |
          wget https://prosecco.gforge.inria.fr/personal/bblanche/proverif/proverif2.04.tar.gz
          tar -xzf proverif2.04.tar.gz
          cd proverif2.04 && ./build
      - name: Verify ProVerif models
        run: |
          ./proverif2.04/proverif specs/proverif/b4ae_v2_handshake.pv
          ./proverif2.04/proverif specs/proverif/b4ae_v2_mode_a.pv
          ./proverif2.04/proverif specs/proverif/b4ae_v2_mode_b.pv
```

### 8.2 Verification Gates

**Pull Request Requirements:**
- All Tamarin lemmas must verify
- All ProVerif queries must verify
- No attack traces found
- Verification report updated

---

## 9. References

### 9.1 Tools

- **Tamarin Prover:** https://tamarin-prover.github.io/
- **ProVerif:** https://prosecco.gforge.inria.fr/personal/bblanche/proverif/
- **Proptest:** https://altsysrq.github.io/proptest-book/
- **TLA+:** https://lamport.azurewebsites.net/tla/tla.html

### 9.2 Related Documents

- **THREAT_MODEL_FORMALIZATION.md:** Formal threat model (single source of truth)
- **STATE_MACHINE_SPECIFICATION.md:** Protocol state machines
- **V2_ARCHITECTURE_OVERVIEW.md:** High-level architecture
- **Design Document:** `.kiro/specs/b4ae-v2-research-grade-architecture/design.md`

---

**Document Status:** Complete  
**Last Updated:** 2026  
**Version:** 2.0  
**Verification Status:** Models pending (Phase 1)
