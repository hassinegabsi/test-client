#ifndef crypto_aead_chacha20poly1305_H
#define crypto_aead_chacha20poly1305_H

#include <stddef.h>
#include "export.h"

#ifdef __cplusplus
# if __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif

extern "C" {
#endif

#define crypto_aead_chacha20poly1305_KEYBYTES 32U
SODIUM_EXPORT
size_t crypto_aead_chacha20poly1305_keybytes(void);

#define crypto_aead_chacha20poly1305_NSECBYTES 0U
SODIUM_EXPORT
size_t crypto_aead_chacha20poly1305_nsecbytes(void);

#define crypto_aead_chacha20poly1305_NPUBBYTES 8U
SODIUM_EXPORT
size_t crypto_aead_chacha20poly1305_npubbytes(void);

#define crypto_aead_chacha20poly1305_ABYTES 16U
SODIUM_EXPORT
size_t crypto_aead_chacha20poly1305_abytes(void);

SODIUM_EXPORT
int crypto_aead_chacha20poly1305_encrypt(unsigned char *c,
                                         uint64_t *clen,
                                         const unsigned char *m,
                                         uint64_t mlen,
                                         const unsigned char *ad,
                                         uint64_t adlen,
                                         const unsigned char *nsec,
                                         const unsigned char *npub,
                                         const unsigned char *k);

SODIUM_EXPORT
int crypto_aead_chacha20poly1305_decrypt(unsigned char *m,
                                         uint64_t *mlen,
                                         unsigned char *nsec,
                                         const unsigned char *c,
                                         uint64_t clen,
                                         const unsigned char *ad,
                                         uint64_t adlen,
                                         const unsigned char *npub,
                                         const unsigned char *k);
#ifdef __cplusplus
}
#endif

#endif
