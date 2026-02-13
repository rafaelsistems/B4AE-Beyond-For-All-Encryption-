# B4AE Coq Makefile
# Generate with: coq_makefile -f _CoqProject -o Makefile

COQBIN=
-include coq_makefile.mk

# Fallback: compile single file if coq_makefile not generated
.PHONY: fallback
fallback:
	coqc B4AE_Handshake.v
