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
  struct tls_hdr hdr;
  struct tls_svr_hello hello;
  struct tls_cert cert;
  struct tls_cert_hdr chdr;
  struct tls_svr_hello_done done;
  unsigned int i;

  /* hello */
  hello.type = HANDSHAKE_SERVER_HELLO;
  hello.len_hi = 0;
  hello.len = htobe16(sizeof(hello) - 4);
  hello.version = htobe16(0x0303);
  hello.random.time = htobe32(time(NULL));
  if (!get_random(hello.random.opaque, sizeof(hello.random.opaque))) return 0;
  hello.sess_id_len = 0;
  hello.cipher_suite = htobe16(ssl->nxt->cipher_suite);
  hello.compressor = ssl->nxt->compressor;
  hello.ext_len = htobe16(sizeof(hello.ext_reneg));

  hello.ext_reneg.type = htobe16(EXT_RENEG_INFO);
  hello.ext_reneg.len = htobe16(1);
  hello.ext_reneg.ri_len = 0;

  if (!tls_send(ssl, TLS_HANDSHAKE, &hello, sizeof(hello))) return 0;
  SHA256_Update(&ssl->nxt->handshakes_hash, ((uint8_t *) &hello),
                sizeof(hello));

  /* certificate */
  hdr.type = TLS_HANDSHAKE;
  hdr.vers = htobe16(0x0303);
  hdr.len = htobe16(sizeof(cert) + sizeof(chdr) * ssl->ctx->pem_cert->num_obj +
                    ssl->ctx->pem_cert->tot_len);

  if (!tls_tx_push(ssl, &hdr, sizeof(hdr))) return 0;

  cert.type = HANDSHAKE_CERTIFICATE;
  cert.len_hi = 0;
  cert.len = htobe16(sizeof(chdr) + sizeof(chdr) * ssl->ctx->pem_cert->num_obj +
                     ssl->ctx->pem_cert->tot_len);
  cert.certs_len_hi = 0;
  cert.certs_len = htobe16(sizeof(chdr) * ssl->ctx->pem_cert->num_obj +
                           ssl->ctx->pem_cert->tot_len);

  if (!tls_tx_push(ssl, &cert, sizeof(cert))) return 0;

  SHA256_Update(&ssl->nxt->handshakes_hash, ((uint8_t *) &cert), sizeof(cert));

  for (i = 0; i < ssl->ctx->pem_cert->num_obj; i++) {
    DER *d = &ssl->ctx->pem_cert->obj[i];

    chdr.cert_len_hi = 0;
    chdr.cert_len = htobe16(d->der_len);

    if (!tls_tx_push(ssl, &chdr, sizeof(chdr))) return 0;
    if (!tls_tx_push(ssl, d->der, d->der_len)) return 0;
    SHA256_Update(&ssl->nxt->handshakes_hash, ((uint8_t *) &chdr),
                  sizeof(chdr));
    SHA256_Update(&ssl->nxt->handshakes_hash, d->der, d->der_len);
  }

  /* hello done */
  done.type = HANDSHAKE_SERVER_HELLO_DONE;
  done.len_hi = 0;
  done.len = 0;
  if (!tls_send(ssl, TLS_HANDSHAKE, &done, sizeof(done))) return 0;
  SHA256_Update(&ssl->nxt->handshakes_hash, ((uint8_t *) &done), sizeof(done));

  /* store the random we generated */
  memcpy(&ssl->nxt->sv_rnd, &hello.random, sizeof(ssl->nxt->sv_rnd));

  return 1;
}

NS_INTERNAL int tls_sv_finish(SSL *ssl) {
  struct tls_change_cipher_spec cipher;
  struct tls_finished finished;

  /* change cipher spec */
  cipher.one = 1;
  if (!tls_send(ssl, TLS_CHANGE_CIPHER_SPEC, &cipher, sizeof(cipher))) return 0;

  ssl->tx_enc = 1;

  /* finished */
  finished.type = HANDSHAKE_FINISHED;
  finished.len_hi = 0;
  finished.len = htobe16(sizeof(finished.vrfy));
  memset(finished.vrfy, 0, sizeof(finished.vrfy));
  tls_generate_server_finished(ssl->cur, finished.vrfy, sizeof(finished.vrfy));

  return tls_send(ssl, TLS_HANDSHAKE, &finished, sizeof(finished));
}
