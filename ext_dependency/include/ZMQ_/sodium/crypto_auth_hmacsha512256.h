#ifndef crypto_auth_hmacsha512256_H
#define crypto_auth_hmacsha512256_H

#include <stddef.h>
#include "crypto_auth_hmacsha512.h"
#include "export.h"

#ifdef __cplusplus
# if __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

typedef crypto_auth_hmacsha512_state crypto_auth_hmacsha512256_state;
SODIUM_EXPORT
size_t crypto_auth_hmacsha512256_statebytes(void);

#define crypto_auth_hmacsha512256_BYTES 32U
SODIUM_EXPORT
size_t crypto_auth_hmacsha512256_bytes(void);

#define crypto_auth_hmacsha512256_KEYBYTES 32U
SODIUM_EXPORT
size_t crypto_auth_hmacsha512256_keybytes(void);

SODIUM_EXPORT
int crypto_auth_hmacsha512256(unsigned char *out, const unsigned char *in,
                              uint64_t  inlen,const unsigned char *k);

SODIUM_EXPORT
int crypto_auth_hmacsha512256_verify(const unsigned char *h,
                                     const unsigned char *in,
                                     uint64_t inlen,
                                     const unsigned char *k);

SODIUM_EXPORT
int crypto_auth_hmacsha512256_init(crypto_auth_hmacsha512256_state *state,
                                   const unsigned char *key,
                                   size_t keylen);

SODIUM_EXPORT
int crypto_auth_hmacsha512256_update(crypto_auth_hmacsha512256_state *state,
                                     const unsigned char *in,
                                     uint64_t inlen);

SODIUM_EXPORT
int crypto_auth_hmacsha512256_final(crypto_auth_hmacsha512256_state *state,
                                    unsigned char *out);

#ifdef __cplusplus
}
#endif

#endif
