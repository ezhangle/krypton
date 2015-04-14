/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include "../openssl/ssl.h"
#include "ktypes.h"
#include "tls.h"
#include "tlsproto.h"
#include "pem.h"

#include <time.h>

NS_INTERNAL int tls_sv_hello(SSL *ssl) {
  tls_record_state st;
  struct tls_svr_hello hello;
  struct tls_cert cert;
  struct tls_cert_hdr chdr;
  unsigned int i;

  /* hello */
  if (!tls_record_begin(ssl, TLS_HANDSHAKE, HANDSHAKE_SERVER_HELLO, &st))
    return 0;
  hello.version = htobe16(0x0303);
  hello.random.time = htobe32(time(NULL));
  if (!get_random(hello.random.opaque, sizeof(hello.random.opaque)))
    return 0;
  hello.sess_id_len = 0;
  hello.cipher_suite = htobe16(ssl->nxt->cipher_suite);
  hello.compressor = ssl->nxt->compressor;
  hello.ext_len = htobe16(sizeof(hello.ext_reneg));

  hello.ext_reneg.type = htobe16(EXT_RENEG_INFO);
  hello.ext_reneg.len = htobe16(1);
  hello.ext_reneg.ri_len = 0;
  if (!tls_record_data(ssl, &st, &hello, sizeof(hello)))
    return 0;
  if (!tls_record_finish(ssl, &st))
    return 0;

  /* certificate */
  if (!tls_record_begin(ssl, TLS_HANDSHAKE, HANDSHAKE_CERTIFICATE, &st))
    return 0;

  cert.certs_len_hi = 0;
  cert.certs_len = htobe16(sizeof(chdr) * ssl->ctx->pem_cert->num_obj +
                           ssl->ctx->pem_cert->tot_len);

  if (!tls_record_data(ssl, &st, &cert, sizeof(cert)))
    return 0;

  for (i = 0; i < ssl->ctx->pem_cert->num_obj; i++) {
    DER *d = &ssl->ctx->pem_cert->obj[i];

    chdr.cert_len_hi = 0;
    chdr.cert_len = htobe16(d->der_len);

    if (!tls_record_data(ssl, &st, &chdr, sizeof(chdr)))
      return 0;
    if (!tls_record_data(ssl, &st, d->der, d->der_len))
      return 0;
  }
  if (!tls_record_finish(ssl, &st))
    return 0;

  /* hello done */
  if (!tls_record_begin(ssl, TLS_HANDSHAKE, HANDSHAKE_SERVER_HELLO_DONE, &st))
    return 0;
  if (!tls_record_finish(ssl, &st))
    return 0;

  /* store the random we generated */
  memcpy(&ssl->nxt->sv_rnd, &hello.random, sizeof(ssl->nxt->sv_rnd));

  return 1;
}

NS_INTERNAL int tls_sv_finish(SSL *ssl) {
  tls_record_state st;
  struct tls_change_cipher_spec cipher;
  struct tls_finished finished;

  /* change cipher spec */
  cipher.one = 1;
  if (!tls_record_begin(ssl, TLS_CHANGE_CIPHER_SPEC, 0, &st))
    return 0;
  if (!tls_record_data(ssl, &st, &cipher, sizeof(cipher)))
    return 0;
  if (!tls_record_finish(ssl, &st))
    return 0;
  tls_server_cipher_spec(ssl->nxt, &ssl->tx_ctx);
  ssl->tx_enc = 1;

  /* finished */
  tls_generate_server_finished(ssl->nxt, finished.vrfy, sizeof(finished.vrfy));
  if (!tls_record_begin(ssl, TLS_HANDSHAKE, HANDSHAKE_FINISHED, &st))
    return 0;
  if (!tls_record_data(ssl, &st, &finished, sizeof(finished)))
    return 0;
  if (!tls_record_finish(ssl, &st))
    return 0;
  return 1;
}
