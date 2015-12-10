/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include "ktypes.h"

static int check_cipher(uint16_t suite) {
  switch (suite) {
#if ALLOW_NULL_CIPHERS
    case TLS_RSA_WITH_NULL_MD5:
#endif
    case TLS_RSA_WITH_RC4_128_MD5:
    case TLS_RSA_WITH_RC4_128_SHA:
      return 1;
    default:
      return 0;
  }
}

static int check_compressor(uint8_t compressor) {
  switch (compressor) {
    case COMPRESSOR_NULL:
      return 1;
    default:
      return 0;
  }
}

static void cipher_suite_negotiate(SSL *ssl, uint16_t suite) {
  if (ssl->nxt->cipher_negotiated) return;
  switch (suite) {
#if ALLOW_NULL_CIPHERS
    case TLS_RSA_WITH_NULL_MD5:
#endif
    case TLS_RSA_WITH_RC4_128_MD5:
    case TLS_RSA_WITH_RC4_128_SHA:
      break;
    default:
      return;
  }
  ssl->nxt->cipher_suite = suite;
  ssl->nxt->cipher_negotiated = 1;
}

static void compressor_negotiate(SSL *ssl, uint8_t compressor) {
  if (ssl->nxt->compressor_negotiated) return;
  switch (compressor) {
    case COMPRESSOR_NULL:
      break;
    default:
      return;
  }
  ssl->nxt->compressor = compressor;
  ssl->nxt->compressor_negotiated = 1;
}

static uint32_t kr_load_be32(const uint8_t *buf) {
  int i;
  uint32_t r = 0;
  for (i = 0; i < 4; i++) {
    r <<= 8;
    r |= *buf++;
  }
  return r;
}

static uint32_t kr_load_be16(const uint8_t *buf) {
  uint32_t r = *buf++;
  r <<= 8;
  r |= *buf;
  return r;
}

static int handle_hello(SSL *ssl, const struct tls_hdr *hdr, const uint8_t *buf,
                        const uint8_t *end) {
  unsigned num_ciphers, num_compressions;
  const uint16_t *cipher_suites;
  const uint8_t *compressions;
  const uint8_t *rand;
  unsigned int i;
  size_t ext_len;
  uint8_t sess_id_len;
  uint32_t len;
  uint16_t proto;

  (void) hdr;
  if (ssl->is_server && ssl->state != STATE_CL_HELLO_WAIT) {
    tls_alert(ssl, ALERT_LEVEL_WARNING, ALERT_NO_RENEGOTIATION);
    return 1;
  }
  if (buf + 6 > end) goto err;

  len = kr_load_be32(buf) & 0xffffff;
  buf += 4;
  proto = kr_load_be16(buf);

  if (buf + len < end) {
    end = buf + len;
  }

  buf += 2;

  if (proto != 0x0303    /* TLS v1.2 */
      && proto != 0x0302 /* TLS v1.1 */
      && proto != 0x0301 /* TLS v1.0 */
      && proto != 0x0300 /* SSL 3.0 */
      ) {
    goto bad_vers;
  }

  /* peer random */
  if (buf + sizeof(struct tls_random) > end) goto err;
  rand = buf;
  buf += sizeof(struct tls_random);

  /* skip over session id len + session id */
  if (buf + 1 > end) goto err;
  sess_id_len = buf[0];

  buf += 1 + sess_id_len;
  if (buf > end) goto err;

  if (ssl->is_server) {
    uint16_t cipher_suites_len;

    if (buf + sizeof(cipher_suites_len) > end) goto err;
    cipher_suites_len = kr_load_be16(buf);
    buf += 2;

    if (buf + cipher_suites_len > end) goto err;
    cipher_suites = (uint16_t *) buf;
    num_ciphers = cipher_suites_len / 2;
    buf += cipher_suites_len;
  } else {
    cipher_suites = (uint16_t *) buf;
    num_ciphers = 1;
    buf += sizeof(*cipher_suites);
  }

  if (ssl->is_server) {
    if (buf + 1 > end) goto err;
    num_compressions = buf[0];
    buf++;

    if (buf + num_compressions > end) goto err;

    compressions = buf;
    buf += num_compressions;
  } else {
    num_compressions = 1;
    compressions = buf;
    buf += num_compressions;
  }

  if (buf + 2 > end) goto err;
  ext_len = kr_load_be16(buf);
  buf += 2;
  if (buf + ext_len < end) end = buf + ext_len;

  while (buf + 4 <= end) {
    /* const uint8_t *ext_end; */
    uint16_t ext_type;
    uint16_t ext_len;

    ext_type = kr_load_be16(buf);
    buf += 2;
    ext_len = kr_load_be16(buf);
    buf += 2;

    if (buf + ext_len > end) goto err;

    /* ext_end = buf + ext_len; */

    switch (ext_type) {
      case EXT_SERVER_NAME:
        dprintf((" + EXT: server name\n"));
        break;
      case EXT_SESSION_TICKET:
        dprintf((" + EXT: session ticket\n"));
        break;
      case EXT_HEARTBEAT:
        dprintf((" + EXT: heartbeat\n"));
        break;
      case EXT_SIG_ALGOS:
        /* XXX: spec requires care to be taken of this */
        dprintf((" + EXT: signature algorithms\n"));
        break;
      case EXT_NPN:
        dprintf((" + EXT: npn\n"));
        break;
      case EXT_RENEG_INFO:
        dprintf((" + EXT: reneg info\n"));
        break;
      default:
        dprintf((" + EXT: %.4x len=%u\n", ext_type, ext_len));
        break;
    }

    buf += ext_len;
  }

  if (ssl->is_server) {
    tls_sec_t sec;

    tls_free_security(ssl->nxt);
    sec = tls_new_security();
    if (NULL == sec) {
      tls_alert(ssl, ALERT_LEVEL_FATAL, ALERT_INTERNAL_ERROR);
      return 0;
    }
    ssl->nxt = sec;
  }

  ssl->nxt->peer_vers = be16toh(proto);

  for (i = 0; i < num_ciphers; i++) {
    uint16_t suite = be16toh(cipher_suites[i]);
    dprintf((" + %s cipher_suite[%u]: 0x%.4x\n",
             (ssl->is_server) ? "server" : "client", i, suite));
    if (ssl->is_server) {
      cipher_suite_negotiate(ssl, suite);
    } else {
      if (check_cipher(suite)) {
        ssl->nxt->cipher_suite = suite;
        ssl->nxt->cipher_negotiated = 1;
      }
    }
  }
  for (i = 0; i < num_compressions; i++) {
    uint8_t compressor = compressions[i];
    dprintf((" + %s compression[%u]: 0x%.2x\n",
             (ssl->is_server) ? "server" : "client", i, compressor));
    if (ssl->is_server) {
      compressor_negotiate(ssl, compressor);
    } else {
      if (check_compressor(compressor)) {
        ssl->nxt->compressor = compressor;
        ssl->nxt->compressor_negotiated = 1;
      }
    }
  }

  if (!ssl->nxt->cipher_negotiated || !ssl->nxt->compressor_negotiated) {
    dprintf(("Faled to negotiate cipher\n"));
    goto bad_param;
  }
  if (ssl->is_server) {
    memcpy(&ssl->nxt->cl_rnd, rand, sizeof(ssl->nxt->cl_rnd));
    if (sess_id_len) {
      dprintf(("Impossible session resume\n"));
      goto bad_param;
    }
    ssl->state = STATE_CL_HELLO_RCVD;
  } else {
    memcpy(&ssl->nxt->sv_rnd, rand, sizeof(ssl->nxt->sv_rnd));
    ssl->state = STATE_SV_HELLO_RCVD;
  }

  return 1;

err:
  dprintf(("error decoding hello\n"));
  tls_alert(ssl, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
  return 0;
bad_param:
  dprintf(("failed to negotiate cipher suite\n"));
  tls_alert(ssl, ALERT_LEVEL_FATAL, ALERT_ILLEGAL_PARAMETER);
  return 0;
bad_vers:
  dprintf(("bad protocol version: 0x%.4x\n", proto));
  tls_alert(ssl, ALERT_LEVEL_FATAL, ALERT_PROTOCOL_VERSION);
  return 0;
}

static int handle_certificate(SSL *ssl, const struct tls_hdr *hdr,
                              const uint8_t *buf, const uint8_t *end) {
  const struct tls_cert *cert;
  const struct tls_cert_hdr *chdr;
  unsigned int depth;
  size_t clen, ilen;
  X509 *final = NULL, *chain = NULL;
  int err = ALERT_DECODE_ERROR;

  (void) hdr;
  cert = (struct tls_cert *) buf;
  buf += sizeof(*cert);
  if (buf > end) goto err;

  ilen = ((size_t) cert->len_hi << 16) | be16toh(cert->len);
  clen = ((size_t) cert->certs_len_hi << 16) | be16toh(cert->certs_len);
  if (buf + ilen < end) end = buf + ilen;
  if (buf + clen < end) end = buf + clen;

  for (chain = NULL, depth = 0; buf < end; depth++) {
    X509 *cert;

    chdr = (struct tls_cert_hdr *) buf;
    buf += sizeof(*chdr);
    if (buf > end) {
      goto err;
    }

    clen = ((size_t) chdr->cert_len_hi << 16) | be16toh(chdr->cert_len);

    cert = X509_new(buf, clen);
    if (NULL == cert) {
      dprintf(("bad cert\n"));
      err = ALERT_BAD_CERT;
      goto err;
    }

    /* add to chain */
    cert->next = chain;
    chain = cert;

    /* XXX: early steal the reference to the key */
    if (depth == 0) {
      if (cert->enc_alg != X509_ENC_ALG_RSA) {
        dprintf(("unsupported cert\n"));
        err = ALERT_UNSUPPORTED_CERT;
        goto err;
      }

      ssl->nxt->svr_key = cert->pub_key;
      final = cert;
    }

    buf += clen;
  }

  if (!chain) goto err;

  if (!ssl->is_server) {
    ssl->state = STATE_SV_CERT_RCVD;
  }

  if (ssl->ctx->vrfy_mode) {
    if (!X509_verify(ssl->ctx, chain)) {
      err = ALERT_BAD_CERT;
      goto err;
    }
  } else {
    dprintf(("No cert verification??\n"));
  }

  /* don't free the last pub-key, we need it */
  final->pub_key = NULL;

  X509_free(chain);
  return 1;
err:
  X509_free(chain);
  tls_alert(ssl, ALERT_LEVEL_FATAL, err);
  return 0;
}

static int handle_key_exch(SSL *ssl, const struct tls_hdr *hdr,
                           const uint8_t *buf, const uint8_t *end) {
  uint32_t len;
  uint16_t ilen;
  size_t out_size = RSA_block_size(ssl->ctx->rsa_privkey);
  uint8_t *out = malloc(out_size);
  int ret;

  (void) hdr;
  if (out == NULL) goto err;

  if (buf + sizeof(len) > end) goto err;

  len = kr_load_be32(buf) & 0xffffff;
  buf += sizeof(len);

  if (buf + len > end) goto err;

  ilen = kr_load_be16(buf);
  buf += 2;
  if (buf + ilen > end) goto err;

  memset(out, 0, out_size);
  ret = RSA_decrypt(ssl->ctx->rsa_privkey, buf, out, out_size, 1);
#if 0
  printf(" + Got %u byte RSA premaster secret\n", ilen);
  hex_dump(buf, ilen, 0);
  printf(" + %d bytes originally encrypted\n", ret);
  if ( ret > 0 )
    hex_dump(out, ret, 0);
#endif

  if (ret != 48 || ((out[0] << 8) | out[1]) != ssl->nxt->peer_vers) {
    /* prevents timing attacks by failing later */
    kr_get_random(out, sizeof(struct tls_premaster_secret));
    dprintf(("Bad pre-master secret\n"));
  }

  tls_compute_master_secret(ssl->nxt, (struct tls_premaster_secret *) out);
  free(out);
  dprintf((" + master secret computed\n"));

  return 1;
err:
  free(out);
  tls_alert(ssl, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
  return 0;
}

static int handle_finished(SSL *ssl, const struct tls_hdr *hdr,
                           const uint8_t *buf, const uint8_t *end) {
  uint32_t len;
  int ret = 0;

  (void) hdr;
  if (buf + sizeof(len) > end) goto err;

  len = kr_load_be32(buf) & 0xffffff;
  buf += sizeof(len);

  if (buf + len > end) goto err;

  if (NULL == ssl->cur) {
    dprintf(("No change cipher-spec before finished\n"));
    tls_alert(ssl, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
    return 0;
  }

  if (ssl->is_server) {
    ret = tls_check_client_finished(ssl->cur, buf, len);
    ssl->state = STATE_CLIENT_FINISHED;
  } else {
    ret = tls_check_server_finished(ssl->cur, buf, len);
    ssl->state = STATE_ESTABLISHED;
  }
  if (!ret) {
    tls_alert(ssl, ALERT_LEVEL_FATAL, ALERT_DECRYPT_ERROR);
  }
  dprintf(("finished (%s)\n", (ret) ? "OK" : "EVIL"));

  return ret;
err:
  tls_alert(ssl, ALERT_LEVEL_FATAL, ALERT_DECODE_ERROR);
  return 0;
}

static int handle_sv_handshake(SSL *ssl, const struct tls_hdr *hdr,
                               const uint8_t *buf, const uint8_t *end) {
  uint8_t type;
  int ret = 1;

  if (buf + 1 > end) return 0;

  type = buf[0];

  switch (type) {
    case HANDSHAKE_CLIENT_HELLO:
      dprintf(("client hello\n"));
      ret = handle_hello(ssl, hdr, buf, end);
      break;
    case HANDSHAKE_CERTIFICATE_VRFY:
      dprintf(("cert verify\n"));
      break;
    case HANDSHAKE_CLIENT_KEY_EXCH:
      dprintf(("key exch\n"));
      ret = handle_key_exch(ssl, hdr, buf, end);
      break;
    case HANDSHAKE_FINISHED:
      ret = handle_finished(ssl, hdr, buf, end);
      break;
    default:
      dprintf(("unknown type 0x%.2x (encrypted?)\n", type));
      tls_alert(ssl, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
      return 0;
  }

  if (ssl->nxt) {
    SHA256_Update(&ssl->nxt->handshakes_hash, buf, end - buf);
  } else if (ssl->cur) {
    SHA256_Update(&ssl->cur->handshakes_hash, buf, end - buf);
  }

  return ret;
}

static int handle_cl_handshake(SSL *ssl, const struct tls_hdr *hdr,
                               const uint8_t *buf, const uint8_t *end) {
  uint8_t type;
  int ret = 1;

  if (buf + 1 > end) return 0;

  type = buf[0];

  switch (type) {
    case HANDSHAKE_HELLO_REQ:
      dprintf(("hello req\n"));
      break;
    case HANDSHAKE_SERVER_HELLO:
      dprintf(("server hello\n"));
      ret = handle_hello(ssl, hdr, buf, end);
      break;
    case HANDSHAKE_NEW_SESSION_TICKET:
      dprintf(("new session ticket\n"));
      break;
    case HANDSHAKE_CERTIFICATE:
      dprintf(("certificate\n"));
      ret = handle_certificate(ssl, hdr, buf, end);
      break;
    case HANDSHAKE_SERVER_KEY_EXCH:
      dprintf(("server key exch\n"));
      ret = handle_key_exch(ssl, hdr, buf, end);
      break;
    case HANDSHAKE_CERTIFICATE_REQ:
      dprintf(("cert req\n"));
      ssl->state = STATE_SV_DONE_RCVD;
      break;
    case HANDSHAKE_SERVER_HELLO_DONE:
      dprintf(("hello done\n"));
      ssl->state = STATE_SV_DONE_RCVD;
      break;
    case HANDSHAKE_CERTIFICATE_VRFY:
      dprintf(("cert verify\n"));
      break;
    case HANDSHAKE_FINISHED:
      ret = handle_finished(ssl, hdr, buf, end);
      break;
    default:
      dprintf(("unknown type 0x%.2x (encrypted?)\n", type));
      tls_alert(ssl, ALERT_LEVEL_FATAL, ALERT_UNEXPECTED_MESSAGE);
      return 0;
  }

  if (ssl->nxt) {
    SHA256_Update(&ssl->nxt->handshakes_hash, buf, end - buf);
  } else if (ssl->cur) {
    SHA256_Update(&ssl->cur->handshakes_hash, buf, end - buf);
  }

  return ret;
}

static int handle_handshake(SSL *ssl, const struct tls_hdr *hdr,
                            const uint8_t *buf, const uint8_t *end) {
  if (ssl->is_server)
    return handle_sv_handshake(ssl, hdr, buf, end);
  else
    return handle_cl_handshake(ssl, hdr, buf, end);
}

static int handle_change_cipher(SSL *ssl, const struct tls_hdr *hdr,
                                const uint8_t *buf, const uint8_t *end) {
  dprintf(("change cipher spec\n"));
  (void) hdr;
  (void) end;
  (void) buf;
  if (ssl->is_server) {
    tls_generate_keys(ssl->nxt);
    if (ssl->nxt) {
      if (ssl->cur) {
        free(ssl->cur);
      }
      ssl->cur = ssl->nxt;
      ssl->nxt = NULL;
    }
  }
  ssl->rx_enc = 1;
  return 1;
}

static int handle_appdata(SSL *ssl, struct vec *vec, uint8_t *out, size_t len) {
  uint8_t *rptr;
  size_t rlen;

  if (NULL == out) {
    printf("%d bytes of appdata ignored\n", (int) vec->len);
    return 1;
  }

  assert(ssl->copied < len);

  if (vec->len > len)
    rlen = len;
  else
    rlen = vec->len;

  rptr = out + ssl->copied;
  memcpy(rptr, vec->ptr, rlen);
  ssl->copied += rlen;

  ssl->extra_appdata.ptr = vec->ptr + rlen;
  ssl->extra_appdata.len = vec->len - rlen;
  if (rlen < vec->len) {
    dprintf(
        ("%d trailing bytes of appdata extra\n", (int) ssl->extra_appdata.len));
  }

  ssl->got_appdata = 1;

  return 1;
}

static int handle_alert(SSL *ssl, const struct tls_hdr *hdr, const uint8_t *buf,
                        size_t len) {
  if (len < 2) return 0;

  (void) hdr;
  switch (buf[1]) {
    case ALERT_CLOSE_NOTIFY:
      dprintf(("recieved close notify\n"));
      if (!ssl->close_notify && ssl->state != STATE_CLOSING) {
        dprintf((" + replying\n"));
        tls_alert(ssl, buf[0], buf[1]);
      }
      ssl->close_notify = 1;
      return 1;
    default:
      break;
  }

  switch (buf[0]) {
    case ALERT_LEVEL_WARNING:
      dprintf(("alert warning(%u)\n", buf[1]));
      break;
    case ALERT_LEVEL_FATAL:
      dprintf(("alert fatal(%u)\n", buf[1]));
    default:
      return 0;
  }

  return 1;
}

static int decrypt_and_vrfy(SSL *ssl, const struct tls_hdr *hdr, uint8_t *buf,
                            const uint8_t *end, struct vec *out) {
  struct tls_hmac_hdr phdr;
  uint8_t digest[MAX_DIGEST_SIZE];
  const uint8_t *msgs[2];
  size_t msgl[2];
  const uint8_t *mac;
  size_t len = end - buf;
  size_t mac_len = tls_mac_len(ssl->cur);

  if (!ssl->rx_enc) {
    out->ptr = buf;
    out->len = len;
    return 1;
  }

  if (len < mac_len) {
    dprintf(("No room for MAC\n"));
    return 0;
  }

  switch (ssl->cur->cipher_suite) {
#if ALLOW_NULL_CIPHERS
    case TLS_RSA_WITH_NULL_MD5:
      break;
#endif
    case TLS_RSA_WITH_RC4_128_MD5:
    case TLS_RSA_WITH_RC4_128_SHA:
      if (ssl->is_server) {
        RC4_crypt(&ssl->cur->client_write_ctx, buf, buf, len);
      } else {
        RC4_crypt(&ssl->cur->server_write_ctx, buf, buf, len);
      }
      break;
    default:
      abort();
  }

  out->ptr = buf;
  out->len = len - mac_len;

  mac = out->ptr + out->len;

  if (ssl->is_server) {
    phdr.seq = htobe64(ssl->cur->client_write_seq);
  } else {
    phdr.seq = htobe64(ssl->cur->server_write_seq);
  }
  phdr.type = hdr->type;
  phdr.vers = hdr->vers;
  phdr.len = htobe16(out->len);

  /*
   * MAC(MAC_write_key, seq_num +
   *      TLSCompressed.type +
   *      TLSCompressed.version +
   *      TLSCompressed.length +
   *      TLSCompressed.fragment);
   */

  msgs[0] = (uint8_t *) &phdr;
  msgl[0] = sizeof(phdr);
  msgs[1] = out->ptr;
  msgl[1] = out->len;
  kr_ssl_hmac(ssl, ssl->is_server ? KR_CLIENT_MAC : KR_SERVER_MAC, 2, msgs,
              msgl, digest);

  if (memcmp(digest, mac, mac_len)) {
    dprintf(("Bad MAC %d\n", (int) out->len));
    tls_alert(ssl, ALERT_LEVEL_FATAL, ALERT_BAD_RECORD_MAC);
    return 0;
  } else {
    dprintf(("MAC ok %d\n", (int) out->len));
  }

  if (ssl->is_server) {
    ssl->cur->client_write_seq++;
  } else {
    ssl->cur->server_write_seq++;
  }
  return 1;
}

int tls_handle_recv(SSL *ssl, uint8_t *out, size_t out_len) {
  const struct tls_hdr *hdr;
  uint8_t *buf = ssl->rx_buf, *end = buf + ssl->rx_len;
  int ret = 1;

  while (buf + sizeof(*hdr) <= end) {
    uint8_t *msg_end;
    int iret = 1;
    uint8_t *buf2;
    struct vec v = {NULL, 0};

    if (ssl->close_notify) {
      dprintf(("messages after close_notify??\n"));
      break;
    }
    if (ssl->fatal) {
      dprintf(("stopping processing messages due to fatal\n"));
      break;
    }

    /* already checked in loop conditiion */
    hdr = (struct tls_hdr *) buf;
    buf2 = buf + sizeof(*hdr);

    /* check known ssl/tls versions */
    if (hdr->vers != htobe16(0x0303)    /* TLS v1.2 */
        && hdr->vers != htobe16(0x0302) /* TLS v1.1 */
        && hdr->vers != htobe16(0x0301) /* TLS v1.0 */
        && hdr->vers != htobe16(0x0300) /* SSL 3.0 */
        ) {
      dprintf(("bad framing version: 0x%.4x\n", be16toh(hdr->vers)));
      tls_alert(ssl, ALERT_LEVEL_FATAL, ALERT_PROTOCOL_VERSION);
      goto out;
    }

    msg_end = buf2 + be16toh(hdr->len);
    if (msg_end > end) {
      /* incomplete data */
      goto out;
    }

    if (ssl->cur) {
      if (!decrypt_and_vrfy(ssl, hdr, buf2, msg_end, &v)) {
        goto out;
      }
    } else {
      v.ptr = buf2;
      v.len = msg_end - buf2;
    }

    switch (hdr->type) {
      case TLS_HANDSHAKE:
        iret = handle_handshake(ssl, hdr, v.ptr, v.ptr + v.len);
        break;
      case TLS_CHANGE_CIPHER_SPEC:
        iret = handle_change_cipher(ssl, hdr, v.ptr, v.ptr + v.len);
        break;
      case TLS_ALERT:
        iret = handle_alert(ssl, hdr, v.ptr, v.len);
        break;
      case TLS_APP_DATA:
        iret = handle_appdata(ssl, &v, out, out_len);
        break;
      default:
        dprintf(("unknown header type 0x%.2x\n", hdr->type));
        iret = 0;
        break;
    }

    if (!iret) {
      ssl->rx_len = 0;
      return 0;
    }
    buf = msg_end;
    /* Yield each individual APP_DATA frame, for simplicity. */
    if (hdr->type == TLS_APP_DATA) break;
  }

  ret = 1;

out:
  if (buf == ssl->rx_buf || ssl->extra_appdata.len > 0) return ret;

  if (buf < end) {
    dprintf(("shuffle buffer down: %d left\n", (int) (end - buf)));
    memmove(ssl->rx_buf, buf, end - buf);
    ssl->rx_len = end - buf;
  } else {
    /* Keep idle memory consumption low. */
    free(ssl->rx_buf);
    ssl->rx_buf = NULL;
    ssl->rx_max_len = ssl->rx_len = 0;
  }

  return ret;
}
