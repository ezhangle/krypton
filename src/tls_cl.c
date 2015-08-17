/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include "../openssl/ssl.h"
#include "ktypes.h"
#include "tls.h"
#include "tlsproto.h"

#include <time.h>

NS_INTERNAL int tls_cl_hello(SSL *ssl) {
  struct tls_cl_hello hello;

  /* hello */
  hello.type = HANDSHAKE_CLIENT_HELLO;
  hello.len_hi = 0;
  hello.len = htobe16(sizeof(hello) - 4);
  hello.version = htobe16(0x0303);
  hello.random.time = htobe32(time(NULL));
  if (!kr_get_random(hello.random.opaque, sizeof(hello.random.opaque))) {
    ssl_err(ssl, SSL_ERROR_SYSCALL);
    return 0;
  }
  hello.sess_id_len = 0;
  hello.cipher_suites_len =
      htobe16((NUM_CIPHER_SUITES + ALLOW_NULL_CIPHERS + 1) * 2);
#if ALLOW_NULL_CIPHERS
  /* if we allow them, it's for testing reasons, so NULL comes first */
  hello.cipher_suite[0] = htobe16(TLS_RSA_WITH_NULL_MD5);
  hello.cipher_suite[1] = htobe16(TLS_RSA_WITH_RC4_128_SHA);
  hello.cipher_suite[2] = htobe16(TLS_RSA_WITH_RC4_128_MD5);
  hello.cipher_suite[3] = htobe16(TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
#else
  hello.cipher_suite[0] = htobe16(TLS_RSA_WITH_RC4_128_SHA);
  hello.cipher_suite[1] = htobe16(TLS_RSA_WITH_RC4_128_MD5);
  hello.cipher_suite[2] = htobe16(TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
#endif
  hello.num_compressors = 1;
  hello.compressor[0] = 0;
  hello.ext_len = htobe16(sizeof(hello.ext_reneg));

  hello.ext_reneg.type = htobe16(EXT_RENEG_INFO);
  hello.ext_reneg.len = htobe16(1);
  hello.ext_reneg.ri_len = 0;

  if (!tls_send(ssl, TLS_HANDSHAKE, &hello, sizeof(hello))) return 0;
  SHA256_Update(&ssl->nxt->handshakes_hash, ((uint8_t *) &hello),
                sizeof(hello));

  /* store the random we generated */
  memcpy(&ssl->nxt->cl_rnd, &hello.random, sizeof(ssl->nxt->cl_rnd));

  return 1;
}

static void set16(unsigned char *p, uint16_t v) {
  p[0] = (v >> 8) & 0xff;
  p[1] = v & 0xff;
}

NS_INTERNAL int tls_cl_finish(SSL *ssl) {
  struct tls_change_cipher_spec cipher;
  struct tls_finished finished;
  size_t buf_len = 6 + RSA_block_size(ssl->nxt->svr_key);
  unsigned char buf[6 + 512];
  struct tls_premaster_secret in;

  assert(buf_len < sizeof(buf)); /* Fix this */

  in.version = htobe16(0x0303);
  if (!kr_get_random(in.opaque, sizeof(in.opaque))) {
    ssl_err(ssl, SSL_ERROR_SYSCALL);
    return 0;
  }
  tls_compute_master_secret(ssl->nxt, &in);
  tls_generate_keys(ssl->nxt);
  dprintf((" + master secret computed\n"));

  if (RSA_encrypt(ssl->nxt->svr_key, (uint8_t *) &in, sizeof(in), buf + 6, 0) <=
      1) {
    dprintf(("RSA encrypt failed\n"));
    ssl_err(ssl, SSL_ERROR_SSL);
    return 0;
  }

  buf[0] = HANDSHAKE_CLIENT_KEY_EXCH;
  buf[1] = 0;
  set16(buf + 2, buf_len - 4);
  set16(buf + 4, buf_len - 6);
  if (!tls_send(ssl, TLS_HANDSHAKE, buf, buf_len)) return 0;
  SHA256_Update(&ssl->nxt->handshakes_hash, buf, buf_len);

  /* change cipher spec */
  cipher.one = 1;
  if (!tls_send(ssl, TLS_CHANGE_CIPHER_SPEC, &cipher, sizeof(cipher))) return 0;

  if (ssl->cur) {
    tls_free_security(ssl->cur);
  }
  ssl->cur = ssl->nxt;
  ssl->nxt = NULL;
  ssl->tx_enc = 1;

  /* finished */
  finished.type = HANDSHAKE_FINISHED;
  finished.len_hi = 0;
  finished.len = htobe16(sizeof(finished.vrfy));
  memset(finished.vrfy, 0, sizeof(finished.vrfy));
  tls_generate_client_finished(ssl->cur, finished.vrfy, sizeof(finished.vrfy));

  if (!tls_send(ssl, TLS_HANDSHAKE, &finished, sizeof(finished))) return 0;

  SHA256_Update(&ssl->cur->handshakes_hash, ((uint8_t *) &finished),
                sizeof(finished));

  return 1;
}
