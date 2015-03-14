/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include "ktypes.h"

NS_INTERNAL tls_sec_t tls_new_security(void) {
  struct tls_security *sec;

  sec = calloc(1, sizeof(*sec));
  if (NULL == sec)
    return NULL;

  SHA256_Init(&sec->handshakes_hash);

  return sec;
}

NS_INTERNAL void tls_free_security(tls_sec_t sec) {
  if (sec) {
    RSA_free(sec->svr_key);
    free(sec);
  }
}

NS_INTERNAL void tls_compute_master_secret(tls_sec_t sec,
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

NS_INTERNAL int tls_check_server_finished(tls_sec_t sec, const uint8_t *vrfy,
                                          size_t vrfy_len) {
  uint8_t buf[15 + SHA256_SIZE];
  uint8_t check[128];  /* TODO(lsm): fix this, and assert below */
  SHA256_CTX tmp_hash;

  assert(sizeof(check) > vrfy_len);

  /* don't interfere with running hash */
  memcpy(&tmp_hash, &sec->handshakes_hash, sizeof(tmp_hash));

  memcpy(buf, "server finished", 15);
  SHA256_Final(buf + 15, &tmp_hash);

  prf(sec->master_secret, sizeof(sec->master_secret), buf, sizeof(buf), check,
      vrfy_len);

  return !memcmp(check, vrfy, sizeof(check));
}

NS_INTERNAL int tls_check_client_finished(tls_sec_t sec, const uint8_t *vrfy,
                                          size_t vrfy_len) {
  uint8_t buf[15 + SHA256_SIZE];
  uint8_t check[128];  /* TODO(lsm): fix this, and assert below */
  SHA256_CTX tmp_hash;

  assert(sizeof(check) > vrfy_len);

  /* don't interfere with running hash */
  memcpy(&tmp_hash, &sec->handshakes_hash, sizeof(tmp_hash));

  memcpy(buf, "client finished", 15);
  SHA256_Final(buf + 15, &tmp_hash);

  prf(sec->master_secret, sizeof(sec->master_secret), buf, sizeof(buf), check,
      vrfy_len);

  return !memcmp(check, vrfy, vrfy_len);
}

NS_INTERNAL void tls_generate_server_finished(tls_sec_t sec, uint8_t *vrfy,
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

NS_INTERNAL void tls_generate_client_finished(tls_sec_t sec, uint8_t *vrfy,
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

NS_INTERNAL void tls_generate_keys(tls_sec_t sec) {
  uint8_t buf[13 + sizeof(sec->cl_rnd) + sizeof(sec->sv_rnd)];

  memcpy(buf, "key expansion", 13);
  memcpy(buf + 13, &sec->sv_rnd, sizeof(sec->sv_rnd));
  memcpy(buf + 13 + sizeof(sec->sv_rnd), &sec->cl_rnd, sizeof(sec->cl_rnd));

  prf(sec->master_secret, sizeof(sec->master_secret), buf, sizeof(buf),
      sec->keys, sizeof(sec->keys));

  RC4_setup(&sec->client_write_ctx, sec->keys + 32, 16);
  RC4_setup(&sec->server_write_ctx, sec->keys + 48, 16);
}

NS_INTERNAL int tls_tx_push(SSL *ssl, const void *data, size_t len) {
  if (ssl->tx_len + len > ssl->tx_max_len) {
    size_t new_len;
    void *new;

    new_len = ssl->tx_max_len + 1024;
    new = realloc(ssl->tx_buf, new_len);
    if (NULL == new) {
      /* or block? */
      ssl_err(ssl, SSL_ERROR_SYSCALL);
      return 0;
    }

    ssl->tx_buf = new;
    ssl->tx_max_len = new_len;
  }

  memcpy(ssl->tx_buf + ssl->tx_len, data, len);
  ssl->tx_len += len;

  return 1;
}

NS_INTERNAL int tls_send(SSL *ssl, uint8_t type, const void *buf, size_t len) {
  struct tls_hdr hdr;
  struct tls_hmac_hdr phdr;
  uint8_t digest[MD5_SIZE];
  size_t buf_ofs;
  size_t mac_len;

  if (ssl->tx_enc)
    mac_len = MD5_SIZE;
  else
    mac_len = 0;

  assert(len < (1 << 14));

  hdr.type = type;
  hdr.vers = htobe16(0x0303);
  hdr.len = htobe16(len + mac_len);

  if (!tls_tx_push(ssl, &hdr, sizeof(hdr)))
    return 0;

  buf_ofs = ssl->tx_len;
  if (!tls_tx_push(ssl, buf, len))
    return 0;

  if (ssl->tx_enc) {
    if (ssl->is_server) {
      phdr.seq = htobe64(ssl->cur->server_write_seq);
    } else {
      phdr.seq = htobe64(ssl->cur->client_write_seq);
    }
    phdr.type = hdr.type;
    phdr.vers = hdr.vers;
    phdr.len = htobe16(len);
    if (ssl->is_server) {
      hmac_md5(ssl->cur->keys + MD5_SIZE, MD5_SIZE, (uint8_t *)&phdr,
               sizeof(phdr), buf, len, digest);
    } else {
      hmac_md5(ssl->cur->keys, MD5_SIZE, (uint8_t *)&phdr, sizeof(phdr), buf,
               len, digest);
    }

    if (!tls_tx_push(ssl, digest, sizeof(digest)))
      return 0;

    if (ssl->is_server) {
      ssl->cur->server_write_seq++;
    } else {
      ssl->cur->client_write_seq++;
    }

    switch (ssl->cur->cipher_suite) {
#if ALLOW_NULL_CIPHERS
      case CIPHER_TLS_NULL_MD5:
        break;
#endif
      case CIPHER_TLS_RC4_MD5:
        if (ssl->is_server) {
          RC4_crypt(&ssl->cur->server_write_ctx, ssl->tx_buf + buf_ofs,
                    ssl->tx_buf + buf_ofs, len + mac_len);
        } else {
          RC4_crypt(&ssl->cur->client_write_ctx, ssl->tx_buf + buf_ofs,
                    ssl->tx_buf + buf_ofs, len + mac_len);
        }
        break;
      default:
        abort();
    }
  }

  return 1;
}

NS_INTERNAL ssize_t tls_write(SSL *ssl, const uint8_t *buf, size_t sz) {
  /* FIXME: break up in to max-sized packets */
  if (!tls_send(ssl, TLS_APP_DATA, buf, sz))
    return -1;
  return sz;
}

NS_INTERNAL int tls_alert(SSL *ssl, uint8_t level, uint8_t desc) {
  struct tls_alert alert;
  if (ssl->fatal)
    return 1;
  if (level == ALERT_LEVEL_FATAL)
    ssl->fatal = 1;
  alert.level = level;
  alert.desc = desc;
  return tls_send(ssl, TLS_ALERT, &alert, sizeof(alert));
}

NS_INTERNAL int tls_close_notify(SSL *ssl) {
  return tls_alert(ssl, ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY);
}
