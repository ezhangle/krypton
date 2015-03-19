/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include "ktypes.h"

tls_sec_t tls_new_security(void) {
  struct tls_security *sec;

  sec = calloc(1, sizeof(*sec));
  if (NULL == sec)
    return NULL;

  SHA256_Init(&sec->handshakes_hash);

  return sec;
}

void tls_free_security(tls_sec_t sec) {
  if (sec) {
    RSA_free(sec->svr_key);
    free(sec);
  }
}

void tls_compute_master_secret(tls_sec_t sec,
                                           struct tls_premaster_secret *pre) {
  uint8_t buf[13 + sizeof(sec->cl_rnd) + sizeof(sec->sv_rnd)];

  memcpy(buf, "master secret", 13);
  memcpy(buf + 13, &sec->cl_rnd, sizeof(sec->cl_rnd));
  memcpy(buf + 13 + sizeof(sec->cl_rnd), &sec->sv_rnd, sizeof(sec->sv_rnd));

  prf((uint8_t *)pre, sizeof(*pre), buf, sizeof(buf), sec->master_secret,
      sizeof(sec->master_secret));
#if 0
	printf(" + pre-material\n");
	hex_dump(buf, sizeof(buf), 0);
	printf(" + master secret\n");
	hex_dump(sec->master_secret, sizeof(sec->master_secret), 0);
#endif
}

int tls_check_server_finished(tls_sec_t sec, const uint8_t *vrfy,
                                          size_t vrfy_len) {
  uint8_t buf[15 + SHA256_SIZE];
  uint8_t check[12];
  SHA256_CTX tmp_hash;

  assert(sizeof(check) >= vrfy_len);

  /* don't interfere with running hash */
  memcpy(&tmp_hash, &sec->handshakes_hash, sizeof(tmp_hash));

  memcpy(buf, "server finished", 15);
  SHA256_Final(buf + 15, &tmp_hash);

  prf(sec->master_secret, sizeof(sec->master_secret), buf, sizeof(buf), check,
      vrfy_len);

  return !memcmp(check, vrfy, sizeof(check));
}

int tls_check_client_finished(tls_sec_t sec, const uint8_t *vrfy,
                                          size_t vrfy_len) {
  uint8_t buf[15 + SHA256_SIZE];
  uint8_t check[12];
  SHA256_CTX tmp_hash;

  assert(sizeof(check) >= vrfy_len);

  /* don't interfere with running hash */
  memcpy(&tmp_hash, &sec->handshakes_hash, sizeof(tmp_hash));

  memcpy(buf, "client finished", 15);
  SHA256_Final(buf + 15, &tmp_hash);

  prf(sec->master_secret, sizeof(sec->master_secret), buf, sizeof(buf), check,
      vrfy_len);

  return !memcmp(check, vrfy, vrfy_len);
}

void tls_generate_server_finished(tls_sec_t sec, uint8_t *vrfy,
                                              size_t vrfy_len) {
  uint8_t buf[15 + SHA256_SIZE];
  SHA256_CTX tmp_hash;

  /* don't interfere with running hash */
  memcpy(&tmp_hash, &sec->handshakes_hash, sizeof(tmp_hash));

  memcpy(buf, "server finished", 15);
  SHA256_Final(buf + 15, &tmp_hash);

  prf(sec->master_secret, sizeof(sec->master_secret), buf, sizeof(buf), vrfy,
      vrfy_len);
}

void tls_generate_client_finished(tls_sec_t sec, uint8_t *vrfy,
                                              size_t vrfy_len) {
  uint8_t buf[15 + SHA256_SIZE];
  SHA256_CTX tmp_hash;

  /* don't interfere with running hash */
  memcpy(&tmp_hash, &sec->handshakes_hash, sizeof(tmp_hash));

  memcpy(buf, "client finished", 15);
  SHA256_Final(buf + 15, &tmp_hash);

  prf(sec->master_secret, sizeof(sec->master_secret), buf, sizeof(buf), vrfy,
      vrfy_len);
}

void tls_generate_keys(tls_sec_t sec) {
  uint8_t buf[13 + sizeof(sec->cl_rnd) + sizeof(sec->sv_rnd)];

  memcpy(buf, "key expansion", 13);
  memcpy(buf + 13, &sec->sv_rnd, sizeof(sec->sv_rnd));
  memcpy(buf + 13 + sizeof(sec->sv_rnd), &sec->cl_rnd, sizeof(sec->cl_rnd));

  prf(sec->master_secret, sizeof(sec->master_secret), buf, sizeof(buf),
      sec->keys, suite_key_mat_len(sec->cipher_suite));

  sec->server_write_pending = 1;
  sec->client_write_pending = 1;
}

void tls_client_cipher_spec(tls_sec_t sec, struct cipher_ctx *ctx)
{
  assert(sec->client_write_pending);
  ctx->cipher_suite = sec->cipher_suite;
  ctx->seq = 0;
  suite_init(ctx, sec->keys, 1);
  sec->client_write_pending = 0;
}

void tls_server_cipher_spec(tls_sec_t sec, struct cipher_ctx *ctx)
{
  assert(sec->server_write_pending);
  ctx->cipher_suite = sec->cipher_suite;
  ctx->seq = 0;
  suite_init(ctx, sec->keys, 0);
  sec->server_write_pending = 0;
}

int tls_tx_push(SSL *ssl, const void *data, size_t len) {
  if (ssl->tx_len + len > ssl->tx_max_len) {
    size_t new_len;
    void *new;

    new_len = ssl->tx_max_len + (len < 512 ? 512 : len);
    new = realloc(ssl->tx_buf, new_len);
    if (NULL == new) {
      /* or block? */
      ssl_err(ssl, SSL_ERROR_SYSCALL);
      return 0;
    }

    ssl->tx_buf = new;
    ssl->tx_max_len = new_len;
  }

  /* if data is NULL, then just 'assure' the buffer space so the caller
   * can copy in to it directly. Useful for encryption.
  */
  if ( data )
    memcpy(ssl->tx_buf + ssl->tx_len, data, len);

  ssl->tx_len += len;

  return 1;
}

int tls_send(SSL *ssl, uint8_t type, const void *buf, size_t len) {
  struct tls_hdr hdr;
  size_t max;
  size_t mac_len;
  size_t exp_len;

  if (ssl->tx_enc) {
    mac_len = suite_mac_len(ssl->tx_ctx.cipher_suite);
    exp_len = suite_expansion(ssl->tx_ctx.cipher_suite);
  }else{
    mac_len = 0;
    exp_len = 0;
  }

  max = (1 << 14) - (mac_len + exp_len);
  if ( len > max )
    len = max - (mac_len + exp_len);

  hdr.type = type;
  hdr.vers = htobe16(0x0303);
  hdr.len = htobe16(len + exp_len + mac_len);

  if (!tls_tx_push(ssl, &hdr, sizeof(hdr)))
    return 0;

  if ( ssl->tx_enc ) {
    size_t buf_ofs;
    buf_ofs = ssl->tx_len;
    if (!tls_tx_push(ssl, NULL, len + exp_len + mac_len))
      return 0;

    suite_box(&ssl->tx_ctx, &hdr, buf, len, ssl->tx_buf + buf_ofs);
  }else{
    if (!tls_tx_push(ssl, buf, len))
      return 0;
  }

  return len;
}

ssize_t tls_write(SSL *ssl, const uint8_t *buf, size_t sz) {
  /* FIXME: break up in to max-sized packets */
  int res = tls_send(ssl, TLS_APP_DATA, buf, sz);
  return res == 0 ? -1 : res;
}

int tls_alert(SSL *ssl, uint8_t level, uint8_t desc) {
  struct tls_alert alert;
  if (ssl->fatal)
    return 1;
  if (level == ALERT_LEVEL_FATAL)
    ssl->fatal = 1;
  alert.level = level;
  alert.desc = desc;
  return tls_send(ssl, TLS_ALERT, &alert, sizeof(alert));
}

int tls_close_notify(SSL *ssl) {
  return tls_alert(ssl, ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY);
}
