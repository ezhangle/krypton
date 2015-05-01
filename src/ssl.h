/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#ifndef _SSL_H
#define _SSL_H

struct ssl_method_st {
  uint8_t sv_undefined : 1;
  uint8_t cl_undefined : 1;
#ifdef KRYPTON_DTLS
  uint8_t dtls : 1;
#else
  uint8_t dummy : 1;
#endif
};

#ifdef KRYPTON_DTLS
#define is_dtls(s) ((s)->ctx->meth.dtls)
#else
#define is_dtls(s) 0
#endif

struct ssl_ctx_st {
#ifdef KRYPTON_DTLS
  krypton_gen_cookie_cb_t gen_cookie;
  krypton_vrfy_cookie_cb_t vrfy_cookie;
#endif
  X509 *ca_store;
  PEM *pem_cert;
  RSA_CTX *rsa_privkey;
  uint8_t mode;
  uint8_t vrfy_mode;
  struct ssl_method_st meth;
};

#define STATE_INITIAL 0
#define STATE_CL_HELLO_SENT 1
#define STATE_CL_HELLO_WAIT 2
#define STATE_CL_HELLO_RCVD 3
#define STATE_SV_HELLO_SENT 4
#define STATE_SV_HELLO_RCVD 5
#define STATE_SV_CERT_RCVD 6
#define STATE_SV_DONE_RCVD 7
#define STATE_CLIENT_FINISHED 8
#define STATE_CL_KEY_EXCH_RCVD 9
#define STATE_CL_CIPHER_SPEC_RCVD 10
#define STATE_CL_FINISHED_RCVD 11
#define STATE_SV_CIPHER_SPEC_RCVD 12
#define STATE_ESTABLISHED 13
#define STATE_CLOSING 14

struct buf {
  uint8_t *buf;
  uint32_t len;
  uint32_t max_len;
};

struct ssl_st {
#if KRYPTON_DTLS
  struct sockaddr_storage st;
  struct timeval timer_expiry;
  long options;
#endif

  uint64_t tx_seq;
  uint64_t rx_seq;

  struct ssl_ctx_st *ctx;
  struct tls_security *nxt;

/* rcv buffer: can be 16bit lens? */
#define RX_INITIAL_BUF 1024
#define RX_MAX_BUF (1 << 14)
  struct buf tx;
  struct buf rx;
#if KRYPTON_DTLS
  struct buf rtx;
#endif

  int fd;
  int err;

  /* for handling appdata recvs */
  unsigned int copied;

#if KRYPTON_DTLS
  uint16_t link_mtu;
  uint16_t handshake_seq;
#endif

  uint8_t state;

  uint8_t vrfy_result;

  uint8_t mode_defined : 1;
  uint8_t is_server : 1;
  uint8_t got_appdata : 1;
  uint8_t tx_enc : 1;
  uint8_t rx_enc : 1;
  uint8_t close_notify : 1;
  uint8_t fatal : 1;
  uint8_t write_pending : 1;

  struct cipher_ctx rx_ctx;
  struct cipher_ctx tx_ctx;
};

#endif /* _SSL_H */
