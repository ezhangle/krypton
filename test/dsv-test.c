/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <inttypes.h>
#include <poll.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <openssl/ssl.h>

#define TEST_PORT 4343

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
  printf("cookie len %u\n", *cookie_len);

  *cookie_len = 16;
  memcpy(cookie, "01234567789abcef", 0);
  return 1;
}

int verify_cookie(SSL *ssl, unsigned char *cookie, unsigned int cookie_len)
{
  return 1;
}

static SSL_CTX *setup_ctx(const char *cert_file, const char *key_file) {
  SSL_CTX *ctx;

  ctx = SSL_CTX_new(DTLSv1_2_server_method());
  if (NULL == ctx)
    goto out;

  SSL_CTX_set_mode(ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

  if (!SSL_CTX_use_certificate_chain_file(ctx, cert_file)) {
    fprintf(stderr, "%s: err loading cert file\n", cert_file);
    goto out_free;
  }

  if (!SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM)) {
    fprintf(stderr, "%s: err loading key file\n", key_file);
    goto out_free;
  }

  SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
  SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);

#if !USE_KRYPTON
  SSL_CTX_set_cipher_list(ctx, "AES128-GCM-SHA256");
#endif
  goto out;

out_free:
  SSL_CTX_free(ctx);
  ctx = NULL;
out:
  return ctx;
}

static int waitforit(SSL *ssl) {
  struct pollfd pfd;
  int ret;

  pfd.fd = SSL_get_fd(ssl);
  pfd.revents = 0;

  switch (SSL_get_error(ssl, -1)) {
    case SSL_ERROR_WANT_READ:
      pfd.events = POLLIN;
      break;
    case SSL_ERROR_WANT_WRITE:
      pfd.events = POLLOUT;
      break;
    default:
      return 0;
  }

  ret = poll(&pfd, 1, -1);
  if (ret != 1 || !(pfd.revents & pfd.events))
    return 0;

  return 1;
}

static int do_listen(SSL *ssl) {
  int ret;
  struct sockaddr_in sa;

again:
  ret = DTLSv1_listen(ssl, &sa);
  if (ret < 0) {
    if (waitforit(ssl)) {
      goto again;
    } else {
      return -1;
    }
  }

  return ret;
}

static int do_read(SSL *ssl, void *buf, int len) {
  int ret;

again:
  ret = SSL_read(ssl, buf, len);
  if (ret < 0) {
    if (waitforit(ssl)) {
      goto again;
    } else {
      return -1;
    }
  }

  return ret;
}

static int do_write(SSL *ssl, const void *buf, int len) {
  int ret;

again:
  ret = SSL_write(ssl, buf, len);
  if (ret < 0) {
    if (waitforit(ssl)) {
      goto again;
    } else {
      return -1;
    }
  }

  return ret;
}

static int do_shutdown(SSL *ssl) {
  int ret;

again:
  ret = SSL_shutdown(ssl);
  if (ret < 0) {
    if (waitforit(ssl)) {
      goto again;
    } else {
      return -1;
    }
  }

  return ret;
}

static int test_content(SSL *ssl) {
  static const char *const str1 = "Hello TLS1.2 world!";
  static const char *const str2 = "Hi yourself!";
  char buf[512];
  int ret;

  ret = do_read(ssl, buf, sizeof(buf));
  if (ret < 0 || (size_t)ret != strlen(str1))
    return 0;

  printf("Got: %.*s\n", ret, buf);
  if (memcmp(buf, str1, ret)) {
    return 0;
  }

  ret = do_write(ssl, str2, strlen(str2));
  if (ret < 0 || (size_t)ret != strlen(str2))
    return 0;

  return 1;
}

static void ns_set_non_blocking_mode(int sock) {
#ifdef _WIN32
  unsigned long on = 1;
  ioctlsocket(sock, FIONBIO, &on);
#else
  int flags = fcntl(sock, F_GETFL, 0);
  fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif
}

static int do_test(const char *cert_file, const char *key_file) {
  struct sockaddr_in sa;
  SSL_CTX *ctx;
  SSL *ssl;
  int ret = 0;
  int fd;

  ctx = setup_ctx(cert_file, key_file);
  if (NULL == ctx)
    goto out;
#if !USE_KRYPTON
  SSL_CTX_set_read_ahead(ctx, 1);
#endif

  ssl = SSL_new(ctx);
  if (NULL == ssl)
    goto out_ctx;

  fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0) {
    fprintf(stderr, "socket: %s\n", strerror(errno));
    goto out_ssl;
  }

  do {
    int val = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
  } while (0);

  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = htons(TEST_PORT);
  if (bind(fd, (struct sockaddr *)&sa, sizeof(sa))) {
    fprintf(stderr, "bind: %s\n", strerror(errno));
    goto out_close;
  }

  ns_set_non_blocking_mode(fd);
  SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);

#if USE_KRYPTON
  if (!SSL_set_fd(ssl, fd))
    goto out_close;
#else
  do {
    BIO *sbio;
    sbio = BIO_new_dgram(fd, BIO_NOCLOSE);
    SSL_set_bio(ssl, sbio, sbio);
    SSL_set_accept_state(ssl);
    if (!DTLS_set_link_mtu(ssl, 1500)) {
      goto out_close;
    }
    SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
  }while(0);
#endif

  printf("Listening\n");
  if (do_listen(ssl) <= 0) {
    goto shutdown;
  }

  printf("Got connection\n");

  if (!test_content(ssl)) {
    goto shutdown;
  }

  ret = 1;

shutdown:
  if (do_shutdown(ssl) > 0 && ret) {
    printf("SUCCESS\n");
  } else {
    ret = 0;
  }
out_close:
  close(fd);
out_ssl:
  SSL_free(ssl);
out_ctx:
  SSL_CTX_free(ctx);
out:
  return ret;
}

int main(void) {
  SSL_library_init();
  if (!do_test("server.crt", "server.key"))
    return EXIT_FAILURE;
  return EXIT_SUCCESS;
}
