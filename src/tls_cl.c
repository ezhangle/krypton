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
  tls_record_state st;
  struct tls_cl_hello hello;
  unsigned int i = 0;

  /* hello */
  if (!tls_record_begin(ssl, TLS_HANDSHAKE, HANDSHAKE_CLIENT_HELLO, &st))
    return 0;
  hello.version = htobe16(0x0303);
  hello.random.time = htobe32(time(NULL));
  if (!get_random(hello.random.opaque, sizeof(hello.random.opaque))) {
    ssl_err(ssl, SSL_ERROR_SYSCALL);
    return 0;
  }
  hello.sess_id_len = 0;
  hello.cipher_suites_len =
      htobe16((NUM_CIPHER_SUITES + ALLOW_NULL_CIPHERS + 1) * 2);

  /* ciphers listed in preference order */
#if ALLOW_NULL_CIPHERS
  /* if we allow them, it's for testing reasons, so NULL comes first */
  hello.cipher_suite[i++] = htobe16(CIPHER_TLS_NULL_MD5);
#endif
#if WITH_AEAD_CIPHERS
  hello.cipher_suite[i++] = htobe16(CIPHER_TLS_AES128_GCM);
#endif
#if ALLOW_RC4_CIPHERS
  hello.cipher_suite[i++] = htobe16(CIPHER_TLS_RC4_SHA1);
  hello.cipher_suite[i++] = htobe16(CIPHER_TLS_RC4_MD5);
#endif

  /* apart from this one which is a signalling-value for the renegotiation
   * extension and must come after legit cipher suites
  */
  hello.cipher_suite[i++] = htobe16(CIPHER_EMPTY_RENEG_EXT);

  hello.num_compressors = 1;
  hello.compressor[0] = 0;
  hello.ext_len = htobe16(sizeof(hello.ext_reneg));

  hello.ext_reneg.type = htobe16(EXT_RENEG_INFO);
  hello.ext_reneg.len = htobe16(1);
  hello.ext_reneg.ri_len = 0;

  if (!tls_record_data(ssl, &st, &hello, sizeof(hello)))
    return 0;
  if (!tls_record_finish(ssl, &st))
    return 0;

  /* store the random we generated */
  memcpy(&ssl->nxt->cl_rnd, &hello.random, sizeof(ssl->nxt->cl_rnd));

  return 1;
}

NS_INTERNAL int tls_cl_finish(SSL *ssl) {
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

  in.version = htobe16(0x0303);
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
