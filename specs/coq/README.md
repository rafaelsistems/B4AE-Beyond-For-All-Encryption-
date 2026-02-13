# B4AE Coq Formal Verification

Spesifikasi formal dan bukti keamanan untuk protokol handshake B4AE.

## Prerequisites

- [Coq](https://coq.inria.fr/) 8.17+ (via opam atau instalasi langsung)

```bash
# Via opam (Linux/macOS)
opam init
opam install coq
```

## Build

```bash
cd specs/coq

# Option 1: Generate Makefile and build
coq_makefile -f _CoqProject -o Makefile
make

# Option 2: Compile single file directly
coqc B4AE_Handshake.v
```

## Contents

- **B4AE_Handshake.v**: Model state machine handshake three-way
  - `HandshakeState`: Initiation, WaitingResponse, WaitingComplete, Completed, Failed
  - `Transition`: Relasi transisi valid (match TLA+ spec)
  - `Reachable`: Predikat reachability
  - **safety_theorem**: Setiap state reachable memenuhi safety invariant

## Teorema Utama

```coq
Theorem safety_theorem :
  forall s, Reachable s -> SafetyInvariant s.
```

Artinya: jika state `s` reachable dari init, maka bila both parties Completed, state tersebut hanya tercapai via urutan handshake yang valid.
