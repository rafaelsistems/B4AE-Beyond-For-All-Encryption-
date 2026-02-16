# B4AE v2.0 Planning

---

## Goals

- Modular crate ecosystem (b4ae-core, b4ae-pq, b4ae-transport)
- RFC alignment (formal spec submission)
- Pluggable algorithm architecture (NIST updates)
- Interoperability specification

---

## Crate Split (Proposed)

| Crate | Contents |
|-------|----------|
| b4ae-core | Protocol types, handshake logic |
| b4ae-pq | Kyber, Dilithium, hybrid |
| b4ae-metadata | Padding, timing, obfuscation |
| b4ae-transport | ELARA, adapters |
| b4ae | Umbrella crate, re-exports |

---

## Timeline

- v1.x: Current, stable API
- v2.0-alpha: Crate split, backward compat layer
- v2.0: New API, deprecate v1 patterns

---

## Risks

- Breaking changes for adopters
- Maintenance burden (multiple crates)
- Mitigation: Long deprecation window, migration guide
