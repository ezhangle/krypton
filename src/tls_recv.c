/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include "ktypes.h"

typedef struct {
  enum rx_status_e {
    STATUS__OK, /* the expected message */
    STATUS__RESEND, /* a re-sent message */
    STATUS__OUT_OF_ORDER, /* an out-of-order message, ie. from the future */
    STATUS__RENEG, /* a renegotiation begin */
    STATUS__BAD_DECODE, /* garbage */
    STATUS__BAD_MAC, /* couldn't decrypt */

    /* these messages are specific subtypes of OK, the message came in the right
     * order, but there was som other problem processing it. */
    STATUS__BAD_CERT,
    STATUS__UNSUPPORTED_CERT,
    STATUS__BAD_VERS,
    STATUS__ILLEGAL_PARAM,
    STATUS__EVIL_HANDSHAKE,
    STATUS__INTERNAL_ERROR,
    STATUS__NOTSUPP,
  }st;
}rx_status_t;

#define STATUS_OK (rx_status_t){.st = STATUS__OK,}
#define STATUS_RESEND (rx_status_t){.st = STATUS__RESEND,}
#define STATUS_OUT_OF_ORDER (rx_status_t){.st = STATUS__OUT_OF_ORDER,}
#define STATUS_RENEG (rx_status_t){.st = STATUS__RENEG,}
#define STATUS_BAD_DECODE (rx_status_t){.st = STATUS__BAD_DECODE,}
#define STATUS_BAD_MAC (rx_status_t){.st = STATUS__BAD_MAC,}
#define STATUS_BAD_CERT (rx_status_t){.st = STATUS__BAD_CERT,}
#define STATUS_UNSUPPORTED_CERT (rx_status_t){.st = STATUS__UNSUPPORTED_CERT,}
#define STATUS_BAD_VERS (rx_status_t){.st = STATUS__BAD_VERS,}
#define STATUS_ILLEGAL_PARAM (rx_status_t){.st = STATUS__ILLEGAL_PARAM,}
#define STATUS_EVIL_HANDSHAKE (rx_status_t){.st = STATUS__EVIL_HANDSHAKE,}
#define STATUS_INTERNAL_ERROR (rx_status_t){.st = STATUS__INTERNAL_ERROR,}
#define STATUS_NOTSUPP (rx_status_t){.st = STATUS__NOTSUPP,}

static int check_cipher(uint16_t suite) {
  switch (suite) {
#if ALLOW_NULL_CIPHERS
    case CIPHER_TLS_NULL_MD5:
#endif
#if WITH_AEAD_CIPHERS
    case CIPHER_TLS_AES128_GCM:
#endif
#if ALLOW_RC4_CIPHERS
    case CIPHER_TLS_RC4_SHA1:
    case CIPHER_TLS_RC4_MD5:
#endif
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
  if (ssl->nxt->cipher_negotiated)
    return;
  switch (suite) {
#if ALLOW_NULL_CIPHERS
    case CIPHER_TLS_NULL_MD5:
#endif
#if WITH_AEAD_CIPHERS
    case CIPHER_TLS_AES128_GCM:
#endif
#if ALLOW_RC4_CIPHERS
    case CIPHER_TLS_RC4_SHA1:
    case CIPHER_TLS_RC4_MD5:
#endif
      break;
    default:
      return;
  }
  ssl->nxt->cipher_suite = suite;
  ssl->nxt->cipher_negotiated = 1;
}

static void compressor_negotiate(SSL *ssl, uint8_t compressor) {
  if (ssl->nxt->compressor_negotiated)
    return;
  switch (compressor) {
    case COMPRESSOR_NULL:
      break;
    default:
      return;
  }
  ssl->nxt->compressor = compressor;
  ssl->nxt->compressor_negotiated = 1;
}

static int hello_vers_check(SSL *ssl, uint16_t proto)
{
  if ( ssl->ctx->meth.dtls ) {
    return (
           proto == 0xfeff /* DTLS v1.0 */
        || proto == 0xfefd /* DTLS v1.2 */
        );
  }else{
    return (
           proto == 0x0303    /* TLS v1.2 */
        || proto == 0x0302 /* TLS v1.1 */
        || proto == 0x0301 /* TLS v1.0 */
        || proto == 0x0300 /* SSL 3.0 */
        );
  }
}

static rx_status_t handle_hello(SSL *ssl, const uint8_t *buf,
                                const uint8_t *end) {
  unsigned num_ciphers, num_compressions;
  const uint16_t *cipher_suites;
  const uint8_t *compressions;
  const uint8_t *rand;
#if KRYPTON_DTLS
  uint8_t *cookie;
  uint8_t cookie_len;
#endif
  unsigned int i;
  size_t ext_len;
  uint8_t sess_id_len;
  uint16_t proto;

  if (ssl->is_server && ssl->state != STATE_CL_HELLO_WAIT) {
    return STATUS_RENEG;
  }

  /* hello protocol version */
  if (buf + sizeof(proto) > end)
    return STATUS_BAD_DECODE;
  proto = be16toh(*(uint16_t *)buf);
  buf += 2;

  if (!hello_vers_check(ssl, proto))
    return STATUS_BAD_VERS;

  /* peer random */
  if (buf + sizeof(struct tls_random) > end)
    return STATUS_BAD_DECODE;
  rand = buf;
  buf += sizeof(struct tls_random);

  /* session ID */
  if (buf + 1 > end)
    return STATUS_BAD_DECODE;
  sess_id_len = buf[0];

  buf += 1 + sess_id_len;
  if (buf > end)
    return STATUS_BAD_DECODE;

  /* extract DTLS cookie if present */
#if KRYPTON_DTLS
  if (ssl->is_server && ssl->ctx->meth.dtls) {
    if (buf + sizeof(cookie_len) > end)
      return STATUS_BAD_DECODE;
    cookie_len = buf[0];
    buf += sizeof(cookie_len);

    if (cookie_len) {
      if (buf + cookie_len > end)
        return STATUS_BAD_DECODE;
      /* ugh, fuck you openssl */
      cookie = (uint8_t *)buf;
      buf += cookie_len;
      hex_dump(cookie, cookie_len, 0);
    }
  }else{
    cookie_len = 0;
  }
#endif

  /* cipher suites */
  if (ssl->is_server) {
    uint16_t cipher_suites_len;

    if (buf + sizeof(cipher_suites_len) > end)
      return STATUS_BAD_DECODE;
    cipher_suites_len = be16toh(*(uint16_t *)buf);
    buf += 2;

    if (buf + cipher_suites_len > end)
      return STATUS_BAD_DECODE;
    cipher_suites = (uint16_t *)buf;
    num_ciphers = cipher_suites_len / 2;
    buf += cipher_suites_len;
  } else {
    cipher_suites = (uint16_t *)buf;
    num_ciphers = 1;
    buf += sizeof(*cipher_suites);
  }

  /* compressors */
  if (ssl->is_server) {
    if (buf + 1 > end)
      return STATUS_BAD_DECODE;
    num_compressions = buf[0];
    buf++;

    if (buf + num_compressions > end)
      return STATUS_BAD_DECODE;

    compressions = buf;
    buf += num_compressions;
  } else {
    num_compressions = 1;
    compressions = buf;
    buf += num_compressions;
  }

  /* extensions */
  if (buf + 2 > end)
    return STATUS_BAD_DECODE;
  ext_len = htobe16(*(uint16_t *)buf);
  buf += 2;
  if (buf + ext_len < end)
    end = buf + ext_len;

  while (buf + 4 <= end) {
    /* const uint8_t *ext_end; */
    uint16_t ext_type;
    uint16_t ext_len;

    ext_type = be16toh(*(uint16_t *)buf);
    buf += 2;
    ext_len = be16toh(*(uint16_t *)buf);
    buf += 2;

    if (buf + ext_len > end)
      return STATUS_BAD_DECODE;

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

#if KRYPTON_DTLS
  if (ssl->is_server && ssl->ctx->meth.dtls &&
        (SSL_get_options(ssl) & SSL_OP_COOKIE_EXCHANGE)) {
    if ( cookie_len ) {
      if ( !dtls_verify_cookie(ssl, cookie, cookie_len) ) {
        /* ignore spurious cookies */
        return STATUS_OK;
      }

      /* now fall through to the regular path where we may allocate
       * some state and affect the state machine.
      */
    }else{
      /* return 1 because spurious packets are no problem */
      dtls_hello_verify_request(ssl);
      return STATUS_OK;
    }
  }
#endif

  /* start recording security parameters */
  if (ssl->is_server) {
    tls_sec_t sec;

    tls_free_security(ssl->nxt);
    sec = tls_new_security();
    if (NULL == sec) {
      return STATUS_INTERNAL_ERROR;
    }
    ssl->nxt = sec;
  }

  ssl->nxt->peer_vers = proto;

  for (i = 0; i < num_ciphers; i++) {
    uint16_t suite = be16toh(cipher_suites[i]);
    dprintf((" + %s cipher_suite[%u]: 0x%.4x\n",
            (ssl->is_server) ? "client" : "server", i, suite));
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
            (ssl->is_server) ? "client" : "server", i, compressor));
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
    dprintf(("Failed to negotiate cipher\n"));
    return STATUS_ILLEGAL_PARAM;
  }
  if (ssl->is_server) {
    memcpy(&ssl->nxt->cl_rnd, rand, sizeof(ssl->nxt->cl_rnd));
    if (sess_id_len) {
      dprintf(("Impossible session resume\n"));
      return STATUS_ILLEGAL_PARAM;
    }
    ssl->state = STATE_CL_HELLO_RCVD;
  } else {
    memcpy(&ssl->nxt->sv_rnd, rand, sizeof(ssl->nxt->sv_rnd));
    ssl->state = STATE_SV_HELLO_RCVD;
  }

  return STATUS_OK;
}

static rx_status_t handle_certificate(SSL *ssl,
                              const uint8_t *buf, const uint8_t *end) {
  const struct tls_cert_hdr *chdr;
  unsigned int depth;
  size_t clen;
  X509 *final = NULL, *chain = NULL;
  rx_status_t err = STATUS_BAD_DECODE;

  if (buf + 3 > end)
    goto err;
  clen = ((size_t)buf[0] << 16) | be16toh(*(uint16_t *)(buf + 1));
  buf += 3;

  if (buf + clen < end)
    end = buf + clen;

  for (chain = NULL, depth = 0; buf < end; depth++) {
    X509 *cert;

    chdr = (struct tls_cert_hdr *)buf;
    buf += sizeof(*chdr);
    if (buf > end) {
      goto err;
    }

    clen = ((size_t)chdr->cert_len_hi << 16) | be16toh(chdr->cert_len);

    cert = X509_new(buf, clen);
    if (NULL == cert) {
      dprintf(("bad cert\n"));
      err = STATUS_BAD_CERT;
      goto err;
    }

    /* add to chain */
    cert->next = chain;
    chain = cert;

    /* XXX: take a reference to the key */
    if (depth == 0) {
      if (cert->enc_alg != X509_ENC_ALG_RSA) {
        dprintf(("unsupported cert\n"));
        err = STATUS_UNSUPPORTED_CERT;
        goto err;
      }

      ssl->nxt->svr_key = cert->pub_key;
      final = cert;
    }

    buf += clen;
  }

  if (!chain)
    goto err;

  if (!ssl->is_server) {
    ssl->state = STATE_SV_CERT_RCVD;
  }

  if (ssl->ctx->vrfy_mode) {
    if (!X509_verify(ssl->ctx->ca_store, chain)) {
      err = STATUS_BAD_CERT;
      goto err;
    }
  } else {
    dprintf(("No cert verification??\n"));
  }

  /* don't free the last pub-key, we need it */
  final->pub_key = NULL;

  X509_free(chain);
  return STATUS_OK;
err:
  X509_free(chain);
  return err;
}

static rx_status_t handle_key_exch(SSL *ssl,
                                   const uint8_t *buf, const uint8_t *end) {
  uint16_t ilen;
  size_t out_size = RSA_block_size(ssl->ctx->rsa_privkey);
  uint8_t *out = malloc(out_size);
  int ret;

  if (out == NULL)
    goto err;

  ilen = be16toh(*(uint16_t *)buf);
  buf += 2;
  if (buf + ilen > end)
    goto err;

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
    get_random(out, sizeof(struct tls_premaster_secret));
    dprintf(("Bad pre-master secret\n"));
  }

  tls_compute_master_secret(ssl->nxt, (struct tls_premaster_secret *)out);
  free(out);
  dprintf((" + master secret computed\n"));

  return STATUS_OK;
err:
  free(out);
  return STATUS_BAD_DECODE;
}

static rx_status_t handle_finished(SSL *ssl,
                           const uint8_t *buf, const uint8_t *end) {
  int ret = 0;

  if (ssl->is_server) {
    if ( ssl->state >= STATE_CLIENT_FINISHED )
      return STATUS_RESEND;
    ret = tls_check_client_finished(ssl->nxt, buf, end - buf);
    ssl->state = STATE_CLIENT_FINISHED;
  } else {
    if ( ssl->state >= STATE_ESTABLISHED )
      return STATUS_RESEND;
    ret = tls_check_server_finished(ssl->nxt, buf, end - buf);
    ssl->state = STATE_ESTABLISHED;
    tls_free_security(ssl->nxt);
    ssl->nxt = NULL;
  }
  dprintf(("finished (%s)\n", (ret) ? "OK" : "EVIL"));
  if (!ret) {
    return STATUS_EVIL_HANDSHAKE;
  }

  return STATUS_OK;
}

static rx_status_t handle_verify_request(SSL *ssl, const uint8_t *buf,
                                 const uint8_t *end) {
  struct dtls_verify_request *vreq;
  uint8_t cookie_len;

  if ( ssl->state < STATE_CL_HELLO_SENT )
    return STATUS_OUT_OF_ORDER;
  if ( ssl->state > STATE_CL_HELLO_SENT )
    return STATUS_RESEND;

  vreq = (struct dtls_verify_request *)buf;
  if ( buf + sizeof(*vreq) > end )
    return STATUS_BAD_DECODE;
  buf += sizeof(*vreq);

  /* FIXME: check protocol */

  if ( buf + sizeof(cookie_len) > end )
    return STATUS_BAD_DECODE;
  cookie_len = buf[0];
  buf++;

  if ( buf + cookie_len > end )
    return STATUS_BAD_DECODE;

  SHA256_Init(&ssl->nxt->handshakes_hash);

  dprintf(("re-send hello with cookie\n"));
  hex_dump(buf, cookie_len, 0);

  /* FIXME: use state machine */
  if (!tls_cl_hello(ssl, buf, cookie_len)) {
    return STATUS_OK;
  }

  return STATUS_OK;
}

static rx_status_t handle_sv_handshake(SSL *ssl, uint8_t type,
                               const uint8_t *buf, const uint8_t *end) {
  switch (type) {
    case HANDSHAKE_CLIENT_HELLO:
      dprintf(("client hello\n"));
      return handle_hello(ssl, buf, end);
    case HANDSHAKE_CERTIFICATE_VRFY:
      dprintf(("cert verify\n"));
      return STATUS_NOTSUPP;
    case HANDSHAKE_CLIENT_KEY_EXCH:
      dprintf(("key exch\n"));
      return handle_key_exch(ssl, buf, end);
    case HANDSHAKE_FINISHED:
      return handle_finished(ssl, buf, end);
    default:
      dprintf(("unknown type 0x%.2x (encrypted?)\n", type));
      return STATUS_NOTSUPP;
  }
}

static rx_status_t handle_cl_handshake(SSL *ssl, uint8_t type,
                                       const uint8_t *buf, const uint8_t *end) {
  switch (type) {
    case HANDSHAKE_HELLO_REQ:
      dprintf(("hello req\n"));
      return STATUS_RENEG;
    case HANDSHAKE_SERVER_HELLO:
      dprintf(("server hello\n"));
      return handle_hello(ssl, buf, end);
    case HANDSHAKE_HELLO_VERIFY_REQUEST:
      if (ssl->ctx->meth.dtls) {
        /* FIXME: use state machine */
        return handle_verify_request(ssl, buf, end);
      }else{
        return STATUS_NOTSUPP;
      }
    case HANDSHAKE_NEW_SESSION_TICKET:
      dprintf(("new session ticket\n"));
      return STATUS_NOTSUPP;
    case HANDSHAKE_CERTIFICATE:
      dprintf(("certificate\n"));
      return handle_certificate(ssl, buf, end);
    case HANDSHAKE_SERVER_KEY_EXCH:
      dprintf(("server key exch\n"));
      return handle_key_exch(ssl, buf, end);
    case HANDSHAKE_CERTIFICATE_REQ:
      dprintf(("cert req\n"));
      return STATUS_NOTSUPP;
    case HANDSHAKE_SERVER_HELLO_DONE:
      dprintf(("hello done\n"));
      ssl->state = STATE_SV_DONE_RCVD;
      return STATUS_OK;
    case HANDSHAKE_CERTIFICATE_VRFY:
      dprintf(("cert verify\n"));
      return STATUS_NOTSUPP;
    case HANDSHAKE_FINISHED:
      return handle_finished(ssl, buf, end);
    default:
      return STATUS_NOTSUPP;
  }
}

static rx_status_t handle_handshake(SSL *ssl, struct vec *v) {
  const uint8_t *buf = v->ptr, *end = v->ptr + v->len;
  const uint8_t *ibuf, *iend;
  const struct tls_handshake *hdr;
  uint32_t len;
  rx_status_t ret;

  hdr = (struct tls_handshake *)buf;
  if (buf + sizeof(*hdr) > end) {
    return STATUS_BAD_DECODE;
  }

  len = ((uint32_t)hdr->len_hi << 16) | be16toh(hdr->len);

  if ( end < buf + sizeof(*hdr) + len ) {
    return STATUS_BAD_DECODE;
  }

  ibuf = buf + sizeof(*hdr);
  iend = ibuf + len;

  if (ssl->is_server)
    ret = handle_sv_handshake(ssl, hdr->type, ibuf, iend);
  else
    ret = handle_cl_handshake(ssl, hdr->type, ibuf, iend);

  if (ssl->nxt && ret.st == STATUS__OK) {
    SHA256_Update(&ssl->nxt->handshakes_hash, buf, end - buf);
  }

  return ret;
}

static rx_status_t handle_dtls_handshake(SSL *ssl, struct vec *v) {
  const uint8_t *buf = v->ptr, *end = v->ptr + v->len;
  const uint8_t *ibuf, *iend;
  const struct dtls_handshake *hdr;
  uint32_t len, frag_off, frag_len;
  rx_status_t ret;

  hdr = (struct dtls_handshake *)buf;
  if (buf + sizeof(*hdr) > end) {
    return STATUS_BAD_DECODE;
  }

  len = ((uint32_t)hdr->len_hi << 16) | be16toh(hdr->len);
  frag_off = ((uint32_t)hdr->frag_off_hi << 16) | be16toh(hdr->frag_off);
  frag_len = ((uint32_t)hdr->frag_len_hi << 16) | be16toh(hdr->frag_len);

  if ( end < buf + sizeof(*hdr) + len ) {
    return STATUS_BAD_DECODE;
  }

  /* TODO: handle defragmentation */
  if ( frag_off != 0 || frag_len != len ) {
    printf("Unhandled fragmentation\n");
    printf("DTLS: Handshake: len: %u\n", len);
    printf("DTLS: Handshake: msg_seq: %u\n", be16toh(hdr->msg_seq));
    printf("DTLS: Handshake: frag_off: %u\n", frag_off);
    printf("DTLS: Handshake: frag_len: %u\n", frag_len);
    return STATUS_ILLEGAL_PARAM;
  }

  ibuf = buf + sizeof(*hdr);
  iend = ibuf + len;

  if (ssl->is_server)
    ret = handle_sv_handshake(ssl, hdr->type, ibuf, iend);
  else
    ret = handle_cl_handshake(ssl, hdr->type, ibuf, iend);

  /* do not include cookieless hello, or HelloVerifyRequest */
  if (ssl->nxt && ret.st == STATUS__OK &&
      hdr->type != HANDSHAKE_HELLO_VERIFY_REQUEST) {
    SHA256_Update(&ssl->nxt->handshakes_hash, buf, end - buf);
  }

  return ret;
}

static rx_status_t handle_change_cipher(SSL *ssl, struct vec *v) {
  dprintf(("change cipher spec\n"));

  if (ssl->is_server) {
    tls_generate_keys(ssl->nxt);
    tls_client_cipher_spec(ssl, &ssl->rx_ctx);
  }else{
    tls_server_cipher_spec(ssl, &ssl->rx_ctx);
  }

  ssl->rx_enc = 1;
  return STATUS_OK;
}

static rx_status_t handle_appdata(SSL *ssl, struct vec *vec,
                                  uint8_t *out, size_t len) {
  uint8_t *rptr;
  size_t rlen;

  if (NULL == out) {
    printf("%zu bytes of appdata ignored\n", vec->len);
    return STATUS_OK;
  }

  assert(ssl->copied < len);

  if (vec->len > len)
    rlen = len;
  else
    rlen = vec->len;

  rptr = out + ssl->copied;
  memcpy(rptr, vec->ptr, rlen);
  ssl->copied += rlen;

  if (rlen < vec->len) {
    printf("%zu trailing bytes of appdata ignored\n", vec->len - rlen);
  }

  ssl->got_appdata = 1;

  return STATUS_OK;
}

static rx_status_t handle_alert(SSL *ssl, struct vec *v) {
  const uint8_t *buf = v->ptr;
  size_t len = v->len;
  if (len < 2)
    return STATUS_BAD_DECODE;

  switch (buf[1]) {
    case ALERT_CLOSE_NOTIFY:
      dprintf(("recieved close notify\n"));
      /* FIXME: use state machine */
      if (!ssl->close_notify && ssl->state != STATE_CLOSING) {
        dprintf((" + replying\n"));
        tls_alert(ssl, buf[0], buf[1]);
      }
      ssl->close_notify = 1;
      return STATUS_OK;
    default:
      break;
  }

  switch (buf[0]) {
    case ALERT_LEVEL_WARNING:
      dprintf(("alert warning(%u)\n", buf[1]));
      break;
    case ALERT_LEVEL_FATAL:
      dprintf(("alert fatal(%u)\n", buf[1]));
      ssl->fatal = 1;
    default:
      return STATUS_BAD_DECODE;
  }

  return STATUS_OK;
}

static rx_status_t decrypt_and_vrfy(SSL *ssl, const struct tls_common_hdr *hdr,
                            uint8_t *buf, const uint8_t *end, struct vec *out) {
  size_t mac_len;
  size_t len = end - buf;

  if (!ssl->rx_enc) {
    out->ptr = buf;
    out->len = len;
    return STATUS_OK;
  }

  mac_len = suite_mac_len(ssl->rx_ctx.cipher_suite);
  if (len < mac_len) {
    dprintf(("No room for MAC\n"));
    return STATUS_BAD_DECODE;
  }

  if ( !suite_unbox(&ssl->rx_ctx, hdr, ssl->rx_seq, buf, len, out) ) {
    dprintf(("Bad MAC\n"));
    return STATUS_BAD_MAC;
  }

  if ( !ssl->ctx->meth.dtls )
    ssl->rx_seq++;
  return STATUS_OK;
}

static rx_status_t dispatch(SSL *ssl, struct tls_common_hdr *hdr,
                            struct vec *v, uint8_t *out, size_t out_len)
{
  rx_status_t ret;

  ret = decrypt_and_vrfy(ssl, hdr, v->ptr, v->ptr + v->len, v);
  if ( ret.st != STATUS__OK )
    return ret;

  switch (hdr->type) {
    case TLS_HANDSHAKE:
      if ( ssl->ctx->meth.dtls ) {
        return handle_dtls_handshake(ssl, v);
      }else{
        return handle_handshake(ssl, v);
      }
    case TLS_CHANGE_CIPHER_SPEC:
      return handle_change_cipher(ssl, v);
    case TLS_ALERT:
      return handle_alert(ssl, v);
    case TLS_APP_DATA:
      return handle_appdata(ssl, v, out, out_len);
    default:
      dprintf(("unknown header type 0x%.2x\n", hdr->type));
      return STATUS_NOTSUPP;
  }
}

static int send_alert(SSL *ssl, rx_status_t ret)
{
  uint8_t level = ALERT_LEVEL_FATAL;
  uint8_t desc;
  switch(ret.st) {
    case STATUS__RESEND:
    case STATUS__OUT_OF_ORDER:
    case STATUS__NOTSUPP:
      desc = ALERT_UNEXPECTED_MESSAGE;
      break;
    case STATUS__BAD_DECODE:
      if (ssl->ctx->meth.dtls)
        return 1;
      desc = ALERT_DECODE_ERROR;
      break;
    case STATUS__RENEG:
      desc = ALERT_NO_RENEGOTIATION;
      break;
    case STATUS__BAD_MAC:
      if (ssl->ctx->meth.dtls)
        return 1;
      desc = ALERT_BAD_RECORD_MAC;
      break;
    case STATUS__BAD_CERT:
      desc = ALERT_BAD_CERT;
      break;
    case STATUS__UNSUPPORTED_CERT:
      desc = ALERT_UNSUPPORTED_CERT;
      break;
    case STATUS__BAD_VERS:
      desc = ALERT_PROTOCOL_VERSION;
      break;
    case STATUS__ILLEGAL_PARAM:
      desc = ALERT_ILLEGAL_PARAMETER;
      break;
    case STATUS__EVIL_HANDSHAKE:
      desc = ALERT_DECRYPT_ERROR;
      break;
    case STATUS__INTERNAL_ERROR:
      desc = ALERT_INTERNAL_ERROR;
      break;
    default:
      abort();
      break;
  }

  return tls_alert(ssl, level, desc);
}

int tls_handle_recv(SSL *ssl, uint8_t *out, size_t out_len) {
  const struct tls_hdr *hdr;
  uint8_t *buf = ssl->rx.buf, *end = buf + ssl->rx.len;
  int ret = 1;

  while (buf + sizeof(*hdr) <= end) {
    uint8_t *msg_end;
    rx_status_t st;
    struct vec v;

    if (ssl->close_notify) {
      dprintf(("messages after close_notify??\n"));
      break;
    }
    if (ssl->fatal) {
      dprintf(("stopping processing messages due to fatal\n"));
      break;
    }

    /* already checked in loop conditiion */
    hdr = (struct tls_hdr *)buf;
    v.ptr = buf + sizeof(*hdr);
    v.len = be16toh(hdr->len);
    msg_end = v.ptr + v.len;
    if (msg_end > end) {
      /* incomplete data */
      goto out;
    }

    /* check known ssl/tls versions */
    if (hdr->vers != htobe16(0x0303)    /* TLS v1.2 */
        && hdr->vers != htobe16(0x0302) /* TLS v1.1 */
        && hdr->vers != htobe16(0x0301) /* TLS v1.0 */
        && hdr->vers != htobe16(0x0300) /* SSL 3.0 */
        ) {
      dprintf(("bad framing version: 0x%.4x\n", be16toh(hdr->vers)));
      tls_alert(ssl, ALERT_LEVEL_FATAL, ALERT_PROTOCOL_VERSION);
      ssl->rx.len = 0;
      return 0;
    }

    st = dispatch(ssl,(struct tls_common_hdr *)hdr,&v,out,out_len);
    switch(st.st) {
    case STATUS__OK:
      break;
    default:
      ssl->rx.len = 0;
      send_alert(ssl, st);
      return 0;
    }

    buf = msg_end;
  }

  ret = 1;

out:
  if (buf == ssl->rx.buf)
    return ret;

  if (buf < end) {
    dprintf(("shuffle buffer down: %zu left\n", end - buf));
    memmove(ssl->rx.buf, buf, end - buf);
    ssl->rx.len = end - buf;
  } else {
    ssl->rx.len = 0;
  }

  return ret;
}

int dtls_handle_recv(SSL *ssl, uint8_t *out, size_t out_len)
{
  uint8_t *buf = ssl->rx.buf, *end = buf + ssl->rx.len;
  struct dtls_hdr *hdr;
  struct vec v;
  uint64_t seq;
  uint16_t len, epoch;
  rx_status_t ret;

again:
  if ( buf >= end )
    return 1;

  if ( buf + sizeof(*hdr) > end ) {
    dprintf(("Datagram too small\n"));
    hex_dump(buf, end - buf, 0);
    return 1;
  }

  hdr = (struct dtls_hdr *)buf;
  buf += sizeof(*hdr);

  len = be16toh(hdr->len);

  v.ptr = buf;
  v.len = end - buf;

  if ( v.len > len )
    v.len = len;
  buf = v.ptr + v.len;

#if 0
  dprintf(("DTLS: dgram_len=%u\n", ssl->rx.len));
  dprintf(("DTLS: type=%u\n", hdr->type));
  dprintf(("DTLS: vers=0x%.4x\n", be16toh(hdr->vers)));
  dprintf(("DTLS: seq=%lu\n", be64toh(hdr->seq)));
  dprintf(("DTLS: len=%u\n", len));
#endif
  seq = be64toh(hdr->seq);
  epoch = seq >> 48;
  if ( epoch != (ssl->rx_seq >> 48) ) {
    printf("Bad epoch %u != %u (expected)\n",
          epoch, (uint16_t)(ssl->rx_seq >> 48));
    return 1;
  }

  ssl->rx_seq = seq;

  ret = dispatch(ssl,(struct tls_common_hdr *)hdr,&v,out,out_len);
  switch(ret.st) {
  case STATUS__OK:
    break;
  case STATUS__RESEND:
    printf("re-send: timeout and re-transmit\n");
    break;
  case STATUS__OUT_OF_ORDER:
    printf("out of order transmission\n");
    break;
  default:
    send_alert(ssl, ret);
    break;
  }
  dprintf(("\n"));

  goto again;
}
