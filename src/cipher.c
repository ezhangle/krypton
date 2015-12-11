/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include "ktypes.h"

#if ALLOW_NULL_CIPHERS
static const kr_cipher_info null_cs_info = {1, 0, 0};
#endif
static const kr_cipher_info rc4_cs_info = {1, RC4_KEY_SIZE, 0};
static const kr_cipher_info aes128_cs_info = {16, AES128_KEY_SIZE, 16};

NS_INTERNAL const kr_cipher_info *kr_cipher_get_info(kr_cs_id cs) {
  switch (cs) {
#if ALLOW_NULL_CIPHERS
    case TLS_RSA_WITH_NULL_MD5:
      return NULL;
#endif
    case TLS_RSA_WITH_RC4_128_MD5:
    case TLS_RSA_WITH_RC4_128_SHA:
      return &rc4_cs_info;
    case TLS_RSA_WITH_AES_128_CBC_SHA:
    case TLS_RSA_WITH_AES_128_CBC_SHA256:
      return &aes128_cs_info;
  }
  return NULL;
}

NS_INTERNAL void *kr_cipher_setup(kr_cs_id cs, int decrypt, const uint8_t *key,
                                  const uint8_t *iv) {
  switch (cs) {
#if ALLOW_NULL_CIPHERS
    case TLS_RSA_WITH_NULL_MD5:
      return NULL;
#endif
    case TLS_RSA_WITH_RC4_128_MD5:
    case TLS_RSA_WITH_RC4_128_SHA: {
      kr_rc4_ctx *ctx = kr_rc4_ctx_new();
      kr_rc4_setup(ctx, key, RC4_KEY_SIZE);
      return ctx;
    }
    case TLS_RSA_WITH_AES_128_CBC_SHA:
    case TLS_RSA_WITH_AES_128_CBC_SHA256: {
      AES_CTX *ctx = kr_aes_ctx_new();
      AES_set_key(ctx, key, iv, AES_MODE_128);
      if (decrypt) AES_convert_key(ctx);
      return ctx;
    }
  }
  dprintf(("unsupported cipher suite: %d\n", cs));
  abort();
  return NULL;
}

NS_INTERNAL void kr_cipher_set_iv(kr_cs_id cs, void *ctx, const uint8_t *iv) {
  switch (cs) {
#if ALLOW_NULL_CIPHERS
    case TLS_RSA_WITH_NULL_MD5:
#endif
    case TLS_RSA_WITH_RC4_128_MD5:
    case TLS_RSA_WITH_RC4_128_SHA:
      return;
    case TLS_RSA_WITH_AES_128_CBC_SHA:
    case TLS_RSA_WITH_AES_128_CBC_SHA256:
      memcpy(((AES_CTX *) ctx)->iv, iv, AES_IV_SIZE);
      return;
  }
}

NS_INTERNAL void kr_cipher_encrypt(kr_cs_id cs, void *ctx, const uint8_t *msg,
                                   int len, uint8_t *out) {
  switch (cs) {
#if ALLOW_NULL_CIPHERS
    case TLS_RSA_WITH_NULL_MD5:
      memmove(out, msg, len);
      return;
#endif
    case TLS_RSA_WITH_RC4_128_MD5:
    case TLS_RSA_WITH_RC4_128_SHA:
      kr_rc4_crypt((kr_rc4_ctx *) ctx, msg, out, len);
      return;
    case TLS_RSA_WITH_AES_128_CBC_SHA:
    case TLS_RSA_WITH_AES_128_CBC_SHA256:
      AES_cbc_encrypt((AES_CTX *) ctx, msg, out, len);
      return;
  }
  abort();
}

NS_INTERNAL void kr_cipher_decrypt(kr_cs_id cs, void *ctx, const uint8_t *msg,
                                   int len, uint8_t *out) {
  switch (cs) {
#if ALLOW_NULL_CIPHERS
    case TLS_RSA_WITH_NULL_MD5:
      memmove(out, msg, len);
      return;
#endif
    case TLS_RSA_WITH_RC4_128_MD5:
    case TLS_RSA_WITH_RC4_128_SHA:
      kr_rc4_crypt((kr_rc4_ctx *) ctx, msg, out, len);
      return;
    case TLS_RSA_WITH_AES_128_CBC_SHA:
    case TLS_RSA_WITH_AES_128_CBC_SHA256:
      AES_cbc_decrypt((AES_CTX *) ctx, msg, out, len);
      return;
  }
  abort();
}

NS_INTERNAL void kr_cipher_ctx_free(kr_cs_id cs, void *ctx) {
  switch (cs) {
#if ALLOW_NULL_CIPHERS
    case TLS_RSA_WITH_NULL_MD5:
      return;
#endif
    case TLS_RSA_WITH_RC4_128_MD5:
    case TLS_RSA_WITH_RC4_128_SHA:
    case TLS_RSA_WITH_AES_128_CBC_SHA:
    case TLS_RSA_WITH_AES_128_CBC_SHA256:
      free(ctx);
      return;
  }
  /* Do not panic, we may not have negotiated a cipher at all. */
}
