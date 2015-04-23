/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include "ktypes.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define MIN_LIKELY_MTU    256

int SSL_library_init(void) {
  return 1;
}

SSL *SSL_new(SSL_CTX *ctx) {
  SSL *ssl;

  ssl = calloc(1, sizeof(*ssl));
  if (NULL == ssl)
    goto out;

  assert(ctx != NULL);

  ssl->ctx = ctx;
  ssl->fd = -1;

  /* success */
  goto out;

#if 0
out_free:
  free(ssl);
  ssl = NULL;
#endif
out:
  return ssl;
}

#if KRYPTON_DTLS
static socklen_t dtls_socklen(SSL *ssl)
{
  switch(ssl->st.ss_family) {
  case AF_INET:
    return sizeof(struct sockaddr_in);
  case AF_INET6:
    return sizeof(struct sockaddr_in6);
  default:
    abort();
  }
}

static int dtls_handle_timeout(SSL *ssl)
{
  /* TODO: retransmit buffered messages if necessary */
  printf("TODO: handle timeout\n");
  return 1;
}

static int dtls_get_timeout(SSL *ssl, struct timeval *tv)
{
  switch(ssl->state) {
  case STATE_INITIAL:
  case STATE_CL_HELLO_WAIT:
  case STATE_ESTABLISHED:
    return 0;
  default:
    /* TODO: look at current time, figure out time left to expiry */
    tv->tv_sec = 1;
    tv->tv_usec = 0;
    return 1;
  }
}
#endif

long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg)
{
#ifdef KRYPTON_DTLS
  long ret;
#endif

  switch(cmd) {
#ifdef KRYPTON_DTLS
  case DTLS_CTRL_LISTEN:
    if ( !ssl->ctx->meth.dtls )
      return 0;
    SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
    ret = SSL_accept(ssl);
    if ( ret > 0 ) {
      memcpy(parg, &ssl->st, dtls_socklen(ssl));
    }
    return ret;
  case DTLS_CTRL_GET_TIMEOUT:
    return dtls_get_timeout(ssl, parg);
  case DTLS_CTRL_HANDLE_TIMEOUT:
    return dtls_handle_timeout(ssl);
  case SSL_CTRL_OPTIONS:
    ssl->options |= larg;
    return (ssl->options);
  case DTLS_CTRL_SET_LINK_MTU:
    if ( larg < MIN_LIKELY_MTU )
      return 0;
    ssl->link_mtu = larg;
    return ssl->link_mtu;
  case DTLS_CTRL_GET_LINK_MIN_MTU:
    return MIN_LIKELY_MTU;
#endif
  default:
    return 0;
  }
}

int SSL_set_fd(SSL *ssl, int fd) {
  ssl->fd = fd;
  ssl_err(ssl, SSL_ERROR_NONE);
  return 1;
}

int SSL_get_fd(SSL *ssl) {
  return ssl->fd;
}

#if KRYPTON_DTLS
static int dgram_send_buf(SSL *ssl, struct buf *buf) {
  const uint8_t *ptr, *end;
  struct dtls_hdr *hdr;
  ssize_t ret;

  end = buf->buf + buf->len;

  for(ptr = buf->buf; ptr + sizeof(*hdr) < end; ) {
    size_t len;

    /* TODO: batch up multiple records as long as < mtu */
    hdr = (struct dtls_hdr *)ptr;
    len = sizeof(*hdr) + be16toh(hdr->len);

    if (ssl->is_server) {
      struct sockaddr *sa;
      socklen_t salen;

      sa = (struct sockaddr *)&ssl->st;
      salen = dtls_socklen(ssl);

      ret = sendto(ssl->fd, ptr, len, MSG_NOSIGNAL, sa, salen);
    }else{
      ret = send(ssl->fd, ptr, len, MSG_NOSIGNAL);
    }

    if (ret <= 0) {
      if (SOCKET_ERRNO == EWOULDBLOCK) {
        ssl_err(ssl, SSL_ERROR_WANT_WRITE);
        return 0;
      }
      dprintf(("send: %s\n", strerror(SOCKET_ERRNO)));
      ssl_err(ssl, SSL_ERROR_SYSCALL);
      /* FIXME */
      buf->len = 0;
      ssl->write_pending = 0;
      return 0;
    }

    if ( (size_t)ret < len ) {
      printf("short datagram write, shouldn't happen?\n");
      ssl_err(ssl, SSL_ERROR_SYSCALL);
      return 0;
    }

    ptr += len;
  }

  return 1;
}

static int dgram_send(SSL *ssl) {
  if (!dgram_send_buf(ssl, &ssl->tx))
    return 0;

  switch(ssl->state) {
  case STATE_ESTABLISHED:
    ssl->tx.len = 0;
    break;
  default:
    /* TODO: move to retransmit buffer */
    /* TODO: calc timeout */
    ssl->tx.len = 0;
    break;
  }
  return 1;
}
#endif

static int stream_send(SSL *ssl) {
  const uint8_t *buf;
  size_t len;
  ssize_t ret;

  buf = ssl->tx.buf;
  len = ssl->tx.len;

  if (!len) {
    ssl->write_pending = 0;
    return 1;
  }
again:

#if KRYPTON_DEBUG_NONBLOCKING
  ret = send(ssl->fd, buf, 1, MSG_NOSIGNAL);
#else
  ret = send(ssl->fd, buf, len, MSG_NOSIGNAL);
#endif
  if (ret < 0) {
    if (SOCKET_ERRNO == EWOULDBLOCK) {
      goto shuffle;
    }
    dprintf(("send: %s\n", strerror(SOCKET_ERRNO)));
    ssl_err(ssl, SSL_ERROR_SYSCALL);
    ssl->tx.len = 0;
    ssl->write_pending = 0;
    return 0;
  }
  if (ret == 0) {
    dprintf(("send: peer hung up\n"));
    ssl_err(ssl, SSL_ERROR_ZERO_RETURN);
    ssl->tx.len = 0;
    ssl->write_pending = 0;
    return 0;
  }

  if ((size_t)ret >= len) {
    ssl->tx.len = 0;
    ssl->write_pending = 0;
    return 1;
  }

  buf += ret;
  len -= ret;

#if KRYPTON_DEBUG_NONBLOCKING
  if (len) {
    goto shuffle;
  }
#endif

  goto again;
shuffle:
  ssl->tx.len = len;
  memmove(ssl->tx.buf, buf, ssl->tx.len);
  ssl_err(ssl, SSL_ERROR_WANT_WRITE);
  return 0;
}

static int do_send(SSL *ssl) {
#ifdef KRYPTON_DTLS
  if ( ssl->ctx->meth.dtls )
    return dgram_send(ssl);
#endif
  return stream_send(ssl);
}

#if KRYPTON_DTLS
static int dgram_recv(SSL *ssl, uint8_t *out, size_t out_len) {
  socklen_t salen;
  struct sockaddr *sa;
  ssize_t ret;

  if (NULL == ssl->rx.buf) {
    ssl->rx.buf = malloc(RX_MAX_BUF);
    if (NULL == ssl->rx.buf) {
      ssl_err(ssl, SSL_ERROR_SYSCALL);
      return 0;
    }
    ssl->rx.max_len = RX_MAX_BUF;
    ssl->rx.len = 0;
  }

  sa = (struct sockaddr *)&ssl->st;
  salen = sizeof(ssl->st);

again:
  ret = recvfrom(ssl->fd, ssl->rx.buf, ssl->rx.max_len, 0, sa, &salen);
  if (ret < 0) {
    if (SOCKET_ERRNO == EWOULDBLOCK) {
      ssl_err(ssl, SSL_ERROR_WANT_READ);
      return 0;
    }
    dprintf(("recv: %s\n", strerror(errno)));
    ssl_err(ssl, SSL_ERROR_SYSCALL);
    return 0;
  }

  ssl->rx.len = ret;

  /* TODO:
   * - Update PMTU estimates
  */

  /* clear re-transmit buffer now that we have a reply */
  switch(ssl->state) {
  case STATE_INITIAL:
  case STATE_ESTABLISHED:
  case STATE_CLOSING:
    break;
  default:
    ssl->tx.len = 0;
    break;
  }

  /* ignore bad packets */
  if (!dtls_handle_recv(ssl, out, out_len)) {
    if (!do_send(ssl))
      return 0;
    goto again;
  }

  if (!do_send(ssl))
    return 0;

  return 1;
}
#endif

static int stream_recv(SSL *ssl, uint8_t *out, size_t out_len) {
  uint8_t *ptr;
  ssize_t ret;
  size_t len;

  if (NULL == ssl->rx.buf) {
    ssl->rx.buf = malloc(RX_INITIAL_BUF);
    if (NULL == ssl->rx.buf) {
      ssl_err(ssl, SSL_ERROR_SYSCALL);
      return 0;
    }

    ssl->rx.max_len = RX_INITIAL_BUF;
    ssl->rx.len = 0;
  }
  if (ssl->rx.len >= ssl->rx.max_len) {
    uint8_t *new;
    size_t new_len;

    /* TODO: peek for size */
    new_len = ssl->rx.max_len + RX_INITIAL_BUF;
    new = realloc(ssl->rx.buf, new_len);
    if (NULL == new) {
      ssl_err(ssl, SSL_ERROR_SYSCALL);
      return 0;
    }

    ssl->rx.buf = new;
    ssl->rx.max_len = new_len;
  }

  ptr = ssl->rx.buf + ssl->rx.len;
#if KRYPTON_DEBUG_NONBLOCKING
  len = 1;
#else
  len = ssl->rx.max_len - ssl->rx.len;
#endif

  ret = recv(ssl->fd, ptr, len, MSG_NOSIGNAL);
  /*dprintf(("recv(%d, %p, %d): %d %d\n", ssl->fd, ptr, (int) len, (int) ret, errno));*/
  if (ret < 0) {
    if (SOCKET_ERRNO == EWOULDBLOCK) {
      ssl_err(ssl, SSL_ERROR_WANT_READ);
      return 0;
    }
    dprintf(("recv: %s\n", strerror(errno)));
    ssl_err(ssl, SSL_ERROR_SYSCALL);
    return 0;
  }

  if (ret == 0) {
    ssl_err(ssl, SSL_ERROR_ZERO_RETURN);
    dprintf(("peer hung up\n"));
    return 0;
  }

  ssl->rx.len += ret;

  if (!tls_handle_recv(ssl, out, out_len)) {
    ssl_err(ssl, SSL_ERROR_SSL);
    return 0;
  }

  /* In case any alerts are queued */
  if (!do_send(ssl))
    return 0;

#if KRYPTON_DEBUG_NONBLOCKING
  if (ssl->rx.len) {
    ssl_err(ssl, SSL_ERROR_WANT_READ);
    return 0;
  }
#endif

  return 1;
}

static int do_recv(SSL *ssl, uint8_t *out, size_t out_len) {
#ifdef KRYPTON_DTLS
  if ( ssl->ctx->meth.dtls )
    return dgram_recv(ssl, out, out_len);
#endif
  return stream_recv(ssl, out, out_len);
}

int SSL_accept(SSL *ssl) {
  if (ssl->fatal) {
    ssl_err(ssl, SSL_ERROR_SSL);
    return -1;
  }
  if (ssl->close_notify || ssl->state == STATE_CLOSING) {
    ssl_err(ssl, SSL_ERROR_ZERO_RETURN);
    return 0;
  }

  if (ssl->mode_defined && !ssl->is_server) {
    dprintf(("bad mode in accept\n"));
    ssl_err(ssl, SSL_ERROR_SSL);
    return -1;
  }

  if (ssl->ctx->meth.dtls) {
    /* TODO: re-transmit logic */
  }else{
    while (ssl->tx.len) {
      if (!do_send(ssl))
        return -1;
    }
  }

  switch (ssl->state) {
    case STATE_INITIAL:
      ssl->is_server = 1;
      ssl->mode_defined = 1;
      ssl->state = STATE_CL_HELLO_WAIT;

    /* fall through */
    case STATE_CL_HELLO_WAIT:
      while (ssl->state != STATE_CL_HELLO_RCVD) {
        if (!do_recv(ssl, NULL, 0)) {
          return -1;
        }
      }

    /* fall through */
    case STATE_CL_HELLO_RCVD:
      if (!tls_sv_hello(ssl)) {
        ssl_err(ssl, SSL_ERROR_SYSCALL);
        return -1;
      }

      ssl->state = STATE_SV_HELLO_SENT;
      if (!do_send(ssl))
        return -1;

    /* fall through */
    case STATE_SV_HELLO_SENT:
    case STATE_CL_KEY_EXCH_RCVD:
    case STATE_CL_CIPHER_SPEC_RCVD:
      while (ssl->state != STATE_CL_FINISHED_RCVD) {
        if (!do_recv(ssl, NULL, 0)) {
          return -1;
        }
      }

    /* fall through */
    case STATE_CL_FINISHED_RCVD:
      if (!tls_sv_finish(ssl)) {
        ssl_err(ssl, SSL_ERROR_SYSCALL);
        return -1;
      }

      ssl->state = STATE_ESTABLISHED;
      tls_free_security(ssl->nxt);
      ssl->nxt = NULL;
      if (!do_send(ssl))
        return -1;

    /* fall through */
    default:
      break;
  }

  ssl_err(ssl, SSL_ERROR_NONE);
  return 1;
}

int SSL_connect(SSL *ssl) {
  tls_sec_t sec;

  if (ssl->fatal) {
    ssl_err(ssl, SSL_ERROR_SSL);
    return -1;
  }
  if (ssl->close_notify || ssl->state == STATE_CLOSING) {
    ssl_err(ssl, SSL_ERROR_ZERO_RETURN);
    return 0;
  }

  if (ssl->mode_defined && ssl->is_server) {
    dprintf(("bad mode in connect\n"));
    ssl_err(ssl, SSL_ERROR_SSL);
    return 0;
  }

  if (ssl->ctx->meth.dtls) {
    /* TODO: re-transmit logic */
  }else{
    while (ssl->tx.len) {
      if (!do_send(ssl))
        return -1;
    }
  }

  switch (ssl->state) {
    case STATE_INITIAL:
      ssl->is_server = 0;
      ssl->mode_defined = 1;

      sec = tls_new_security();
      if (NULL == sec) {
        ssl_err(ssl, SSL_ERROR_SYSCALL);
        return -1;
      }
      ssl->nxt = sec;

      if (!tls_cl_hello(ssl, NULL, 0)) {
        dprintf(("failed to construct hello\n"));
        ssl_err(ssl, SSL_ERROR_SYSCALL);
        return -1;
      }

      ssl->state = STATE_CL_HELLO_SENT;
      if (!do_send(ssl))
        return -1;

    /* fall through */

    case STATE_CL_HELLO_SENT:
    case STATE_SV_HELLO_RCVD:
    case STATE_SV_CERT_RCVD:
      while (ssl->state != STATE_SV_DONE_RCVD) {
        if (!do_recv(ssl, NULL, 0)) {
          return -1;
        }
      }

    /* fall through */
    case STATE_SV_DONE_RCVD:
      if (!tls_cl_finish(ssl)) {
        dprintf(("failed to construct key exchange\n"));
        ssl_err(ssl, SSL_ERROR_SYSCALL);
        return -1;
      }

      ssl->state = STATE_CLIENT_FINISHED;
      if (!do_send(ssl))
        return -1;

    /* fall through */
    case STATE_CLIENT_FINISHED:
      while (ssl->state != STATE_ESTABLISHED) {
        if (!do_recv(ssl, NULL, 0)) {
          return -1;
        }
      }

    default:
      break;
  }

  ssl_err(ssl, SSL_ERROR_NONE);
  return 1;
}

int SSL_read(SSL *ssl, void *buf, int num) {
  if (ssl->fatal) {
    ssl_err(ssl, SSL_ERROR_SSL);
    return -1;
  }
  if (ssl->close_notify || ssl->state == STATE_CLOSING) {
    ssl_err(ssl, SSL_ERROR_ZERO_RETURN);
    return 0;
  }

  for (ssl->copied = ssl->got_appdata = 0; !ssl->got_appdata;) {
    if (ssl->state != STATE_ESTABLISHED) {
      int ret;
      if (ssl->is_server) {
        ret = SSL_accept(ssl);
      } else {
        ret = SSL_connect(ssl);
      }
      if (ret <= 0)
        return ret;
    }

    if (!do_recv(ssl, buf, num)) {
      return ssl->err == SSL_ERROR_ZERO_RETURN ? 0 : -1;
    }
  }

  ssl_err(ssl, SSL_ERROR_NONE);
  return ssl->copied;
}

int SSL_write(SSL *ssl, const void *buf, int num) {
  int res = num;
  if (ssl->fatal) {
    ssl_err(ssl, SSL_ERROR_SSL);
    return -1;
  }
  if (ssl->close_notify || ssl->state == STATE_CLOSING) {
    ssl_err(ssl, SSL_ERROR_ZERO_RETURN);
    return 0;
  }

  if (ssl->state != STATE_ESTABLISHED) {
    int ret;
    if (ssl->is_server) {
      ret = SSL_accept(ssl);
    } else {
      ret = SSL_connect(ssl);
    }
    if (ret <= 0)
      return ret;
  }

  /* Assume sender is retrying the same data since he
   * must wait for an successful return before moving on
   * anyway. If we already encrypted and buffered the last
   * message, there's no way we can take it back if he cnages
   * his mind after a WANT_READ or a WANT_WRITE.
  */
  if (!ssl->write_pending) {
    if ((res = tls_write(ssl, buf, num)) <= 0) {
      return -1;
    }
    ssl->write_pending = 1;
  }
  if (!do_send(ssl))
    return -1;

  ssl_err(ssl, SSL_ERROR_NONE);
  return res;
}

int SSL_get_error(const SSL *ssl, int ret) {
  (void)ret;
  return ssl->err;
}

int SSL_shutdown(SSL *ssl) {
  if (ssl->fatal) {
    return 0;
  }
  if (!ssl->close_notify) {
    switch (ssl->state) {
      default:
        dprintf(("sending close notify\n"));
        if (!tls_close_notify(ssl)) {
          dprintf(("failed to construct close_notify\n"));
          return -1;
        }

        ssl->state = STATE_CLOSING;
        if (!do_send(ssl))
          return -1;
      /* fall through */

      case STATE_CLOSING:
        while (!ssl->close_notify) {
          if (!do_recv(ssl, NULL, 0)) {
            return -1;
          }
        }
    }
  }
  return 1;
}

void SSL_free(SSL *ssl) {
  if (ssl) {
    tls_free_security(ssl->nxt);
    free(ssl->rx.buf);
    free(ssl->tx.buf);
    free(ssl);
  }
}

void ssl_err(SSL *ssl, int err) {
  switch (err) {
    case SSL_ERROR_NONE:
      break;
    case SSL_ERROR_SSL:
      break;
    case SSL_ERROR_WANT_READ:
      break;
    case SSL_ERROR_WANT_WRITE:
      break;
    case SSL_ERROR_SYSCALL:
      break;
    case SSL_ERROR_ZERO_RETURN:
      break;
    case SSL_ERROR_WANT_CONNECT:
      break;
    case SSL_ERROR_WANT_ACCEPT:
      break;
    default:
      abort();
  }
  ssl->err = err;
}
