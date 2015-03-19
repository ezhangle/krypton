/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include "crypto.h"
#include "tlsproto.h"

size_t suite_mac_len(uint16_t suite)
{
  switch(suite) {
  case CIPHER_TLS_NULL_MD5:
  case CIPHER_TLS_RC4_MD5:
    return MD5_SIZE;
  case CIPHER_TLS_RC4_SHA1:
    return SHA1_SIZE;
  case CIPHER_TLS_AES128_GCM:
    return AES_BLOCKSIZE;
  default:
    abort();
    break;
  }
}

size_t suite_expansion(uint16_t suite)
{
  switch(suite) {
  /* AEAD ciphers expand by explicit nonce length */
  case CIPHER_TLS_AES128_GCM:
    return 8;
  default:
    return 0;
  }
}

size_t suite_key_mat_len(uint16_t suite)
{
  switch(suite) {
  case CIPHER_TLS_NULL_MD5:
    return MD5_SIZE * 2;
  case CIPHER_TLS_RC4_MD5:
    return MD5_SIZE * 2 + RC4_KEY_SIZE * 2;
  case CIPHER_TLS_RC4_SHA1:
    return SHA1_SIZE * 2 + RC4_KEY_SIZE * 2;
  case CIPHER_TLS_AES128_GCM:
    return AES_BLOCKSIZE * 2 + AES_GCM_IV_KEY_MAT * 2;
  default:
    abort();
    break;
  }
}

void suite_init(struct cipher_ctx *ctx,
                            uint8_t *keys,
                            int client_write)
{
  switch(ctx->cipher_suite) {
  case CIPHER_TLS_RC4_MD5:
    if ( client_write ) {
      RC4_setup(&ctx->u.rc4_md5.rc4, keys + 32, RC4_KEY_SIZE);
      memcpy(&ctx->u.rc4_md5.md5, keys, MD5_SIZE);
    }else{
      RC4_setup(&ctx->u.rc4_md5.rc4, keys + 48, RC4_KEY_SIZE);
      memcpy(&ctx->u.rc4_md5.md5, keys + MD5_SIZE, MD5_SIZE);
    }
    break;
  case CIPHER_TLS_RC4_SHA1:
    if ( client_write ) {
      RC4_setup(&ctx->u.rc4_sha1.rc4, keys + 40, RC4_KEY_SIZE);
      memcpy(&ctx->u.rc4_sha1.sha1, keys, SHA1_SIZE);
    }else{
      RC4_setup(&ctx->u.rc4_sha1.rc4, keys + 56, RC4_KEY_SIZE);
      memcpy(&ctx->u.rc4_sha1.sha1, keys + SHA1_SIZE, SHA1_SIZE);
    }
    break;
#if WITH_AEAD_CIPHERS
  case CIPHER_TLS_AES128_GCM:
    if ( client_write ) {
      aes_gcm_ctx(&ctx->u.aes_gcm.ctx, keys, AES_BLOCKSIZE);
      memcpy(ctx->u.aes_gcm.salt,
            keys + AES_BLOCKSIZE * 2,
            AES_GCM_IV_KEY_MAT);
    }else{
      aes_gcm_ctx(&ctx->u.aes_gcm.ctx, keys + AES_BLOCKSIZE, AES_BLOCKSIZE);
      memcpy(ctx->u.aes_gcm.salt,
            keys + (AES_BLOCKSIZE * 2) + AES_GCM_IV_KEY_MAT,
            AES_GCM_IV_KEY_MAT);
    }
    break;
#endif
  default:
    abort();
  }
}

#if ALLOW_RC4_CIPHERS
static void box_stream_and_hmac(struct cipher_ctx *ctx,
                                const struct tls_hdr *hdr,
                                const uint8_t *plain, size_t plain_len,
                                uint8_t *out)
{
  struct tls_hmac_hdr phdr;

  /* copy plaintext to output buffer */
  memcpy(out, plain, plain_len);

  phdr.seq = htobe64(ctx->seq);
  phdr.type = hdr->type;
  phdr.vers = hdr->vers;
  phdr.len = htobe16(plain_len);

  /* append HMAC */
  switch (ctx->cipher_suite) {
    case CIPHER_TLS_RC4_MD5:
      hmac_md5(ctx->u.rc4_md5.md5, MD5_SIZE,
               (uint8_t *)&phdr, sizeof(phdr),
               out, plain_len,
               out + plain_len);
      break;
    case CIPHER_TLS_RC4_SHA1:
      hmac_sha1(ctx->u.rc4_sha1.sha1, SHA1_SIZE,
               (uint8_t *)&phdr, sizeof(phdr),
               out, plain_len,
               out + plain_len);
      break;
    default:
      abort();
  }

  /* Encrypt the lot */
  switch (ctx->cipher_suite) {
#if ALLOW_NULL_CIPHERS
    case CIPHER_TLS_NULL_MD5:
      break;
#endif
    case CIPHER_TLS_RC4_MD5:
      RC4_crypt(&ctx->u.rc4_md5.rc4, out, out, plain_len + MD5_SIZE);
      break;
    case CIPHER_TLS_RC4_SHA1:
      RC4_crypt(&ctx->u.rc4_sha1.rc4, out, out, plain_len + SHA1_SIZE);
      break;
    default:
      abort();
  }

  /* Bump the sequence number for the HMAC */
  ctx->seq++;
}
#endif

#if WITH_AEAD_CIPHERS
static void box_aead(struct cipher_ctx *ctx,
                                const struct tls_hdr *hdr,
                                const uint8_t *plain, size_t plain_len,
                                uint8_t *out)
{
  struct tls_hmac_hdr phdr;
  uint8_t nonce[12];

  *(uint64_t *)out = htobe64(ctx->seq);

  phdr.seq = htobe64(ctx->seq);
  phdr.type = hdr->type;
  phdr.vers = hdr->vers;
  phdr.len = htobe16(plain_len);

  memcpy(nonce, ctx->u.aes_gcm.salt, 4);
  memcpy(nonce + 4, out, 8);

  aes_gcm_ae(&ctx->u.aes_gcm.ctx,
             plain, plain_len,
             nonce, sizeof(nonce),
             (void *)&phdr, sizeof(phdr),
             out + 8,
             out + 8 + plain_len);
  ctx->seq++;
}
#endif

/* crypto black-box encrypt+auth and copy to buffer */
void suite_box(struct cipher_ctx *ctx,
               const struct tls_hdr *hdr,
               const uint8_t *plain, size_t plain_len,
               uint8_t *out)
{
  switch(ctx->cipher_suite) {
#if ALLOW_RC4_CIPHERS
  case CIPHER_TLS_RC4_MD5:
  case CIPHER_TLS_RC4_SHA1:
    box_stream_and_hmac(ctx, hdr, plain, plain_len, out);
    break;
#endif
#if WITH_AEAD_CIPHERS
  case CIPHER_TLS_AES128_GCM:
    box_aead(ctx, hdr, plain, plain_len, out);
    break;
#endif
  default:
    abort();
  }
}

#if ALLOW_RC4_CIPHERS
static int unbox_stream_and_hmac(struct cipher_ctx *ctx,
                                 const struct tls_hdr *hdr,
                                 uint8_t *data, size_t data_len,
                                 struct vec *plain)
{
  struct tls_hmac_hdr phdr;
  uint8_t digest[MAX_DIGEST_SIZE];
  size_t mac_len, out_len;
  const uint8_t *mac;

  mac_len = suite_mac_len(ctx->cipher_suite);
  if ( data_len < mac_len )
    return 0;

  out_len = data_len - mac_len;

  switch (ctx->cipher_suite) {
#if ALLOW_NULL_CIPHERS
    case CIPHER_TLS_NULL_MD5:
      break;
#endif
    case CIPHER_TLS_RC4_MD5:
      RC4_crypt(&ctx->u.rc4_md5.rc4, data, data, data_len);
      break;
    case CIPHER_TLS_RC4_SHA1:
      RC4_crypt(&ctx->u.rc4_sha1.rc4, data, data, data_len);
      break;
    default:
      abort();
  }

  phdr.seq = htobe64(ctx->seq);
  phdr.type = hdr->type;
  phdr.vers = hdr->vers;
  phdr.len = htobe16(out_len);

  switch(ctx->cipher_suite) {
    case CIPHER_TLS_RC4_MD5:
      hmac_md5(ctx->u.rc4_md5.md5, MD5_SIZE,
               (uint8_t *)&phdr, sizeof(phdr),
               data, out_len,
               digest);
      break;
    case CIPHER_TLS_RC4_SHA1:
      hmac_sha1(ctx->u.rc4_sha1.sha1, SHA1_SIZE,
               (uint8_t *)&phdr, sizeof(phdr),
               data, out_len,
               digest);
      break;
    default:
      abort();
  }

  mac = data + out_len;
  if ( memcmp(digest, mac, mac_len) )
    return 0;

  ctx->seq++;
  plain->ptr = data;
  plain->len = out_len;

  return 1;
}
#endif

#if WITH_AEAD_CIPHERS
static int unbox_aead(struct cipher_ctx *ctx,
                                 const struct tls_hdr *hdr,
                                 uint8_t *data, size_t data_len,
                                 struct vec *plain)
{
  static struct tls_hmac_hdr phdr;
  static uint8_t nonce[12];
  static uint8_t buff[1024];

  assert(data_len >= 8 + 16);

  phdr.seq = htobe64(ctx->seq);
  phdr.type = hdr->type;
  phdr.vers = hdr->vers;
  phdr.len = htobe16(data_len - (8 + 16));

  memcpy(nonce, ctx->u.aes_gcm.salt, 4);
  memcpy(nonce + 4, data, 8);

  if ( !aes_gcm_ad(&ctx->u.aes_gcm.ctx,
             data + 8, data_len - (8 + 16),
             nonce, sizeof(nonce),
             (void *)&phdr, sizeof(phdr),
             data + (data_len - 16),
             buff) )
    return 0;

  plain->ptr = data + 8;
  plain->len = data_len - (8 + 16);
  memcpy(plain->ptr, buff, plain->len);
  ctx->seq++;
  return 1;
}
#endif

/* crypto unbox in place and authenticate, return auth result, plaintext len */
int suite_unbox(struct cipher_ctx *ctx,
                const struct tls_hdr *hdr,
                uint8_t *data, size_t data_len,
                struct vec *plain)
{
  switch(ctx->cipher_suite) {
#if ALLOW_RC4_CIPHERS
  case CIPHER_TLS_RC4_MD5:
  case CIPHER_TLS_RC4_SHA1:
    return unbox_stream_and_hmac(ctx, hdr, data, data_len, plain);
#endif
#if WITH_AEAD_CIPHERS
  case CIPHER_TLS_AES128_GCM:
    return unbox_aead(ctx, hdr, data, data_len, plain);
#endif
  default:
    abort();
  }
  return 0;
}
