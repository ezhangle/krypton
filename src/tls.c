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

int tls_record_begin(SSL *ssl, uint8_t type,
                     uint8_t subtype, tls_record_state *st)
{
  struct tls_hdr hdr;

  /* record where we started */
  st->ofs = ssl->tx_len;
  st->suite = ssl->tx_ctx.cipher_suite;

  hdr.type = type;
  hdr.vers = htobe16(TLSv1_2);
  hdr.len = ~0;

  if ( !tls_tx_push(ssl, &hdr, sizeof(hdr)) )
    return 0;

  if (ssl->tx_enc) {
    size_t exp_len;
    exp_len = suite_expansion(ssl->tx_ctx.cipher_suite);
    if (!tls_tx_push(ssl, NULL, exp_len))
      return 0;
  }

  if ( type == TLS_HANDSHAKE ) {
    struct tls_handshake hs_hdr;
    hs_hdr.type = subtype;
    if ( !tls_tx_push(ssl, &hs_hdr, sizeof(hs_hdr)) )
      return 0;
  }else{
    assert(!subtype);
  }

  return 1;
}

int tls_record_data(SSL *ssl, tls_record_state *st,
                    const void *buf, size_t len)
{
  return tls_tx_push(ssl, buf, len);
}

int tls_record_finish(SSL *ssl, const tls_record_state *st)
{
  struct tls_hdr *hdr;
  uint8_t *payload;
  size_t plen, tot_len;
  size_t mac_len, exp_len;

  /* cipher suite can't change half-way through record */
  assert(st->suite == ssl->tx_ctx.cipher_suite);

  /* add space for mac if necessary, before length check */
  if (ssl->tx_enc) {
    mac_len = suite_mac_len(ssl->tx_ctx.cipher_suite);
    if (!tls_tx_push(ssl, NULL, mac_len))
      return 0;
  }else{
    mac_len = 0;
  }

  /* figure out the length */
  assert(ssl->tx_len > st->ofs);
  tot_len = ssl->tx_len - st->ofs;
  assert(tot_len >= sizeof(*hdr));
  tot_len -= sizeof(*hdr);

  /* grab the header */
  hdr = (struct tls_hdr *)(ssl->tx_buf + st->ofs);

  /* patch in the length field */
  assert(tot_len <= 0xffff);
  hdr->len = htobe16(tot_len);

  /* locate and size the payload */
  if ( ssl->tx_enc ) {
    exp_len = suite_expansion(ssl->tx_ctx.cipher_suite);
  }else{
    exp_len = 0;
  }
  payload = ssl->tx_buf + st->ofs + sizeof(*hdr) + exp_len;
  plen = tot_len - (exp_len + mac_len);

  /* If it's a handshake, backpatch the handshake size and
   * add the contents to the running hash of all handshake messages
  */
  if (hdr->type == TLS_HANDSHAKE) {
    struct tls_handshake *hs;
    size_t hs_len;

    hs = (struct tls_handshake *)(ssl->tx_buf + st->ofs +
                                  sizeof(*hdr) + exp_len);
    assert(plen >= sizeof(*hs));
    hs_len = plen - sizeof(*hs);

    hs->len_hi = (hs_len >> 16);
    hs->len = htobe16(hs_len & 0xffff);

    SHA256_Update(&ssl->nxt->handshakes_hash, payload, plen);
  }

  /* do the crypto */
  if (ssl->tx_enc) {
    uint8_t *buf;

    buf = ssl->tx_buf + st->ofs + sizeof(*hdr);
    suite_box(&ssl->tx_ctx, hdr, buf + exp_len, plen, buf);
#if 0
    hex_dump(tmp, plen, 0);
    hex_dump(buf + exp_len, plen, 0);
    hex_dump(buf, exp_len + plen + mac_len, 0);
    hex_dump(ssl->tx_buf + st->ofs, ssl->tx_len - st->ofs, 0);
#endif
  }

  return 1;
}

ssize_t tls_write(SSL *ssl, const uint8_t *buf, size_t sz) {
  /* FIXME: break up in to max-sized packets */
  tls_record_state st;
  if (!tls_record_begin(ssl, TLS_APP_DATA, 0, &st))
    return -1;
  if (!tls_record_data(ssl, &st, buf, sz))
    return -1;
  if (!tls_record_finish(ssl, &st))
    return -1;
  return sz;
}

int tls_alert(SSL *ssl, uint8_t level, uint8_t desc) {
  struct tls_alert alert;
  tls_record_state st;

  if (ssl->fatal)
    return 1;
  if (level == ALERT_LEVEL_FATAL)
    ssl->fatal = 1;

  alert.level = level;
  alert.desc = desc;

  if (!tls_record_begin(ssl, TLS_ALERT, 0, &st))
    return 0;
  if (!tls_record_data(ssl, &st, &alert, sizeof(alert)))
    return 0;
  if (!tls_record_finish(ssl, &st))
    return 0;
  return 1;
}

int tls_close_notify(SSL *ssl) {
  return tls_alert(ssl, ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY);
}
