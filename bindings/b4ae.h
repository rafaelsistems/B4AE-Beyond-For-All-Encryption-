/* B4AE C FFI - AES-256-GCM bindings */
#ifndef B4AE_H
#define B4AE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Free buffer allocated by b4ae_* functions */
void b4ae_free(uint8_t *ptr);

/** Generate 32-byte key. Caller must free with b4ae_free. */
uint8_t *b4ae_generate_key(size_t *out_len);

/** Encrypt plaintext. Returns [nonce(12)||ciphertext], caller frees. */
uint8_t *b4ae_encrypt(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    size_t *out_len);

/** Decrypt [nonce(12)||ciphertext]. Caller frees result. */
uint8_t *b4ae_decrypt(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *encrypted,
    size_t encrypted_len,
    size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* B4AE_H */
