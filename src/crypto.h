/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#ifndef _CRYPTO_H
#define _CRYPTO_H

NS_INTERNAL int get_random(uint8_t *out, size_t len);
NS_INTERNAL int get_random_nonzero(uint8_t *out, size_t len);

/* axTLS crypto functions, see C files for copyright info */
typedef struct _SHA256_CTX SHA256_CTX;

NS_INTERNAL void prf(const uint8_t *sec, int sec_len, const uint8_t *seed,
                     int seed_len, uint8_t *out, int olen);

/* SHA256 */
#define SHA256_SIZE 32
#define SHA256_BLOCK_LENGTH 64
struct _SHA256_CTX {
  uint32_t state[8];
  uint64_t bitcount;
  uint8_t buffer[SHA256_BLOCK_LENGTH];
};

NS_INTERNAL void SHA256_Init(SHA256_CTX *c);
NS_INTERNAL void SHA256_Update(SHA256_CTX *, const uint8_t *input, size_t len);
NS_INTERNAL void SHA256_Final(uint8_t digest[32], SHA256_CTX *);

/* SHA1 */
#define SHA1_SIZE 20
typedef struct {
  uint64_t size;
  unsigned int H[5];
  unsigned int W[16];
} SHA_CTX;

NS_INTERNAL void SHA1_Init(SHA_CTX *ctx);
NS_INTERNAL void SHA1_Update(SHA_CTX *ctx, const void *in, unsigned long len);
NS_INTERNAL void SHA1_Final(unsigned char hashout[20], SHA_CTX *ctx);

/* MD5 */
#define MD5_SIZE 16
typedef struct {
  uint32_t state[4];  /* state (ABCD) */
  uint32_t count[2];  /* number of bits, modulo 2^64 (lsb first) */
  uint8_t buffer[64]; /* input buffer */
} MD5_CTX;

NS_INTERNAL void MD5_Init(MD5_CTX *);
NS_INTERNAL void MD5_Update(MD5_CTX *, const uint8_t *msg, int len);
NS_INTERNAL void MD5_Final(uint8_t *digest, MD5_CTX *);

#define MAX_DIGEST_SIZE SHA256_SIZE

/* RC4 */
#define RC4_KEY_SIZE 16
typedef struct {
  uint8_t x, y;
  uint8_t m[256];
} RC4_CTX;

NS_INTERNAL void RC4_setup(RC4_CTX *s, const uint8_t *key, int length);
NS_INTERNAL void RC4_crypt(RC4_CTX *s, const uint8_t *msg, uint8_t *data,
                           int length);

/* HMAC */
NS_INTERNAL void hmac_sha256(const uint8_t *msg, int length, const uint8_t *key,
                             int key_len, uint8_t *digest);
NS_INTERNAL void hmac_md5(const uint8_t *key, size_t key_len,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *msg2, size_t msg2_len,
                          uint8_t *digest);

/* RSA */
NS_INTERNAL void RSA_priv_key_new(RSA_CTX **rsa_ctx, const uint8_t *modulus,
                                  int mod_len, const uint8_t *pub_exp,
                                  int pub_len, const uint8_t *priv_exp,
                                  int priv_len, const uint8_t *p, int p_len,
                                  const uint8_t *q, int q_len,
                                  const uint8_t *dP, int dP_len,
                                  const uint8_t *dQ, int dQ_len,
                                  const uint8_t *qInv, int qInv_len);
NS_INTERNAL void RSA_pub_key_new(RSA_CTX **rsa_ctx, const uint8_t *modulus,
                                 int mod_len, const uint8_t *pub_exp,
                                 int pub_len);
NS_INTERNAL void RSA_free(RSA_CTX *ctx);
NS_INTERNAL int RSA_decrypt(const RSA_CTX *ctx, const uint8_t *in_data,
                            uint8_t *out_data, int out_len, int is_decryption);
NS_INTERNAL bigint *RSA_private(const RSA_CTX *c, bigint *bi_msg);
NS_INTERNAL int RSA_encrypt(const RSA_CTX *ctx, const uint8_t *in_data,
                            uint16_t in_len, uint8_t *out_data, int is_signing);
NS_INTERNAL bigint *RSA_public(const RSA_CTX *c, bigint *bi_msg);
NS_INTERNAL int RSA_block_size(RSA_CTX *ctx);
#if defined(CONFIG_SSL_CERT_VERIFICATION) || \
    defined(CONFIG_SSL_GENERATE_X509_CERT)
NS_INTERNAL bigint *RSA_sign_verify(BI_CTX *ctx, const uint8_t *sig,
                                    int sig_len, bigint *modulus,
                                    bigint *pub_exp);
NS_INTERNAL void RSA_print(const RSA_CTX *ctx);
#endif

/* Faster modular arithmetic, bigger code */
#define CONFIG_BIGINT_BARRETT 1

/* faster multiplies, bigger code, only worth it for bigger keys or systems
 * with very slow multiplys. Not worth it on x86.
*/
/* #define CONFIG_BIGINT_KARATSUBA 1 */
#define MUL_KARATSUBA_THRESH 20
#define SQU_KARATSUBA_THRESH 40

#endif /* _CRYPTO_H */
