/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include "../openssl/ssl.h"
#include "ktypes.h"
#include "tls.h"
#include "tlsproto.h"

#include <time.h>

static const uint16_t tls_ciphers[] = {
#if ALLOW_NULL_CIPHERS
  be16_const(CIPHER_TLS_NULL_MD5),
#endif
#if WITH_AEAD_CIPHERS
  be16_const(CIPHER_TLS_AES128_GCM),
#endif
#if ALLOW_RC4_CIPHERS
  be16_const(CIPHER_TLS_RC4_SHA1),
  be16_const(CIPHER_TLS_RC4_SHA1),
#endif
  /* signalling cipher suite values -- must be last */
  be16_const(CIPHER_EMPTY_RENEG_EXT),
};

static const uint16_t dtls_ciphers[] = {
#if ALLOW_NULL_CIPHERS
  be16_const(CIPHER_TLS_NULL_MD5),
#endif
#if WITH_AEAD_CIPHERS
  be16_const(CIPHER_TLS_AES128_GCM),
#endif
  /* signalling cipher suite values -- must be last */
  be16_const(CIPHER_EMPTY_RENEG_EXT),
};

static const uint8_t compressors[] = {
  COMPRESSOR_NULL,
};

int tls_cl_hello(SSL *ssl) {
  tls_record_state st;
  struct tls_cl_hello hello;
  struct tls_EXT_reneg reneg;

  /* hello */
  if (!tls_record_begin(ssl, TLS_HANDSHAKE, HANDSHAKE_CLIENT_HELLO, &st))
    return 0;
  if (ssl->ctx->meth.dtls) {
    hello.version = htobe16(DTLSv1_2);
  }else{
    hello.version = htobe16(TLSv1_2);
  }
  hello.random.time = htobe32(time(NULL));
  if (!get_random(hello.random.opaque, sizeof(hello.random.opaque))) {
    ssl_err(ssl, SSL_ERROR_SYSCALL);
    return 0;
  }
  if (!tls_record_data(ssl, &st, &hello, sizeof(hello)))
    return 0;

  /* session id [8] */
  if (!tls_record_opaque8(ssl, &st, NULL, 0))
    return 0;

  /* dtls cookie [8] */
  if (ssl->ctx->meth.dtls) {
    if (!tls_record_opaque8(ssl, &st, NULL, 0))
      return 0;
  }

  /* cipher suites [16] */
  if (ssl->ctx->meth.dtls) {
    if (!tls_record_opaque16(ssl, &st, dtls_ciphers, sizeof(dtls_ciphers)))
      return 0;
  }else{
    if (!tls_record_opaque16(ssl, &st, tls_ciphers, sizeof(tls_ciphers)))
      return 0;
  }

  /* compressors [8] */
  if (!tls_record_opaque8(ssl, &st, compressors, sizeof(compressors)))
    return 0;

  /* extensions [16] */
  reneg.type = htobe16(EXT_RENEG_INFO);
  reneg.len = htobe16(1);
  reneg.ri_len = 0;
  if (!tls_record_opaque16(ssl, &st, &reneg, sizeof(reneg)))
    return 0;

  if (!tls_record_finish(ssl, &st))
    return 0;

  /* store the random we generated */
  memcpy(&ssl->nxt->cl_rnd, &hello.random, sizeof(ssl->nxt->cl_rnd));

  return 1;
}

int tls_cl_finish(SSL *ssl) {
  tls_record_state st;
  struct tls_key_exch exch;
  struct tls_change_cipher_spec cipher;
  struct tls_finished finished;
  size_t key_len = RSA_block_size(ssl->nxt->svr_key);
  unsigned char buf[512];
  struct tls_premaster_secret in;

  assert(key_len < sizeof(buf)); /* Fix this */

  if (!tls_record_begin(ssl, TLS_HANDSHAKE, HANDSHAKE_CLIENT_KEY_EXCH, &st))
    return 0;

  exch.key_len = htobe16(key_len);
  if (!tls_record_data(ssl, &st, &exch, sizeof(exch)))
    return 0;

  if (ssl->ctx->meth.dtls) {
    in.version = htobe16(DTLSv1_2);
  }else{
    in.version = htobe16(TLSv1_2);
  }
  if (!get_random(in.opaque, sizeof(in.opaque))) {
    ssl_err(ssl, SSL_ERROR_SYSCALL);
    return 0;
  }
  tls_compute_master_secret(ssl->nxt, &in);
  tls_generate_keys(ssl->nxt);
  dprintf((" + master secret computed\n"));

  if (RSA_encrypt(ssl->nxt->svr_key, (uint8_t *)&in, sizeof(in), buf, 0) <= 1) {
    dprintf(("RSA encrypt failed\n"));
    ssl_err(ssl, SSL_ERROR_SSL);
    return 0;
  }

  if (!tls_record_data(ssl, &st, buf, key_len))
    return 0;
  if (!tls_record_finish(ssl, &st))
    return 0;

  /* change cipher spec */
  cipher.one = 1;
  if (!tls_record_begin(ssl, TLS_CHANGE_CIPHER_SPEC, 0, &st))
    return 0;
  if (!tls_record_data(ssl, &st, &cipher, sizeof(cipher)))
    return 0;
  if (!tls_record_finish(ssl, &st))
    return 0;
  tls_client_cipher_spec(ssl->nxt, &ssl->tx_ctx);
  ssl->tx_enc = 1;

  /* finished */
  tls_generate_client_finished(ssl->nxt, finished.vrfy, sizeof(finished.vrfy));
  if (!tls_record_begin(ssl, TLS_HANDSHAKE, HANDSHAKE_FINISHED, &st))
    return 0;
  if (!tls_record_data(ssl, &st, &finished, sizeof(finished)))
    return 0;
  if (!tls_record_finish(ssl, &st))
    return 0;

  return 1;
}
