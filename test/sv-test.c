/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

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
#include <errno.h>

#if USE_KRYPTON
#include "krypton.h"
#else
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#define TEST_PORT 4343

static SSL_CTX *setup_ctx(const char *cert_file, const char *key_file) {
  SSL_CTX *ctx;

  ctx = SSL_CTX_new(TLSv1_2_server_method());
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

#if !USE_KRYPTON
  SSL_CTX_set_cipher_list(ctx, "RC4-MD5,NULL-MD5");
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

static int do_accept(SSL *ssl) {
  int ret;

again:
  ret = SSL_accept(ssl);
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

static int do_test(const char *cert_file, const char *key_file) {
  struct sockaddr_in sa;
  socklen_t slen;
  SSL_CTX *ctx;
  SSL *ssl;
  int ret = 0;
  int fd, cfd;

  ctx = setup_ctx(cert_file, key_file);
  if (NULL == ctx)
    goto out;

  ssl = SSL_new(ctx);
  if (NULL == ssl)
    goto out_ctx;

  fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
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

  if (listen(fd, 128)) {
    fprintf(stderr, "bind: %s\n", strerror(errno));
    goto out_close;
  }

  slen = sizeof(sa);
  printf("Waiting for a connection...\n");
  cfd = accept4(fd, &sa, &slen, SOCK_NONBLOCK);
  if (cfd < 0) {
    fprintf(stderr, "accept: %s\n", strerror(errno));
    goto out_close;
  }

  if (!SSL_set_fd(ssl, cfd))
    goto out_close_cl;

  printf("Got connection\n");
  if (do_accept(ssl) <= 0) {
#if !USE_KRYPTON
    ERR_print_errors_fp(stdout);
#endif
    goto shutdown;
  }

  if (!test_content(ssl)) {
#if !USE_KRYPTON
    ERR_print_errors_fp(stdout);
#endif
    goto shutdown;
  }

  ret = 1;

shutdown:
  if (do_shutdown(ssl) > 0 && ret) {
    printf("SUCCESS\n");
  } else {
    ret = 0;
  }
out_close_cl:
  close(cfd);
out_close:
  close(fd);
out_ssl:
  SSL_free(ssl);
out_ctx:
  SSL_CTX_free(ctx);
out:
  return ret;
}

int main(int argc, char **argv) {
  SSL_library_init();
  if (!do_test("server.crt", "server.key"))
    return EXIT_FAILURE;
  return EXIT_SUCCESS;
}
