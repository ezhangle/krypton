/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#ifndef _KRYPTON_H
#define _KRYPTON_H

typedef struct x509_store_ctx_st X509_STORE_CTX;
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_method_st SSL_METHOD;

int SSL_library_init(void);
SSL *SSL_new(SSL_CTX *ctx);
long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg);
int SSL_set_fd(SSL *ssl, int fd);
int SSL_get_fd(SSL *ssl);
int SSL_accept(SSL *ssl);
int SSL_connect(SSL *ssl);
int SSL_read(SSL *ssl, void *buf, int num);
int SSL_write(SSL *ssl, const void *buf, int num);
int SSL_shutdown(SSL *ssl);
void SSL_free(SSL *ssl);

#define SSL_ERROR_NONE 0
#define SSL_ERROR_SSL 1
#define SSL_ERROR_WANT_READ 2
#define SSL_ERROR_WANT_WRITE 3
#define SSL_ERROR_SYSCALL 5
#define SSL_ERROR_ZERO_RETURN 6
#define SSL_ERROR_WANT_CONNECT 7
#define SSL_ERROR_WANT_ACCEPT 8
int SSL_get_error(const SSL *ssl, int ret);

const SSL_METHOD *TLSv1_2_method(void);
const SSL_METHOD *TLSv1_2_server_method(void);
const SSL_METHOD *TLSv1_2_client_method(void);
const SSL_METHOD *SSLv23_method(void);
const SSL_METHOD *SSLv23_server_method(void);
const SSL_METHOD *SSLv23_client_method(void);

const SSL_METHOD *DTLSv1_2_method(void);
const SSL_METHOD *DTLSv1_2_server_method(void);
const SSL_METHOD *DTLSv1_2_client_method(void);
const SSL_METHOD *DTLSv1_method(void);
const SSL_METHOD *DTLSv1_server_method(void);
const SSL_METHOD *DTLSv1_client_method(void);

SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth);

#define SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER 0x00000002L
#define SSL_CTRL_MODE 33
#define SSL_CTX_set_mode(ctx,op) SSL_CTX_ctrl((ctx),SSL_CTRL_MODE,(op),NULL)
#define SSL_CTX_get_mode(ctx) SSL_CTX_ctrl((ctx),SSL_CTRL_MODE,0,NULL)
long SSL_CTX_ctrl(SSL_CTX *, int, long, void *);

/* for the client */
#define SSL_VERIFY_NONE 0x00
#define SSL_VERIFY_PEER 0x01
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT 0x02
#define SSL_VERIFY_CLIENT_ONCE 0x04
void SSL_CTX_set_verify(SSL_CTX *ctx, int mode,
                        int (*verify_callback)(int, X509_STORE_CTX *));
int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
                                  const char *CAPath);

/* for the server */
#define SSL_FILETYPE_PEM 1
int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file);
int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type);
int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);

void SSL_CTX_free(SSL_CTX *);

#define SSL_OP_NO_QUERY_MTU 0x1000L
#define SSL_OP_COOKIE_EXCHANGE 0x2000L

#define SSL_CTRL_OPTIONS 32
#define DTLS_CTRL_GET_TIMEOUT  73
#define DTLS_CTRL_HANDLE_TIMEOUT 74
#define DTLS_CTRL_LISTEN 75
#define DTLS_CTRL_SET_LINK_MTU 120
#define DTLS_CTRL_GET_LINK_MIN_MTU 121

#define DTLSv1_listen(ssl, sa) SSL_ctrl(ssl, DTLS_CTRL_LISTEN, 0, sa)
#define DTLS_set_link_mtu(ssl, mtu) \
  SSL_ctrl(ssl, DTLS_CTRL_SET_LINK_MTU, mtu, NULL)
#define DTLS_get_link_min_mtu(ssl) \
  SSL_ctrl(ssl, DTLS_CTRL_GET_LINK_MIN_MTU, 0, NULL)
#define SSL_set_options(ssl, opt) SSL_ctrl(ssl, SSL_CTRL_OPTIONS, opt, NULL)
#define SSL_get_options(ssl) SSL_ctrl(ssl, SSL_CTRL_OPTIONS, 0, NULL)
#define DTLSv1_get_timeout(ssl, arg) \
  SSL_ctrl(ssl, DTLS_CTRL_GET_TIMEOUT, 0, arg)
#define DTLSv1_handle_timeout(ssl) \
  SSL_ctrl(ssl, DTLS_CTRL_HANDLE_TIMEOUT, 0, NULL)

typedef int (*krypton_gen_cookie_cb_t)(SSL *ssl,
                                        unsigned char *cookie,
                                        unsigned int *len);
typedef int (*krypton_vrfy_cookie_cb_t)(SSL *ssl,
                                        unsigned char *cookie,
                                        unsigned int cookie_len);
void SSL_CTX_set_cookie_generate_cb(SSL_CTX *ctx, krypton_gen_cookie_cb_t cb);
void SSL_CTX_set_cookie_verify_cb(SSL_CTX *ctx, krypton_vrfy_cookie_cb_t cb);

/* Krypton-specific DTLS cookie generation API */
#ifdef KRYPTON_DTLS
int krypton__generate_secret(unsigned char *secret, unsigned int secret_len);
int krypton__generate_cookie(SSL *ssl,
                             unsigned char *secret,
                             unsigned int secret_len,
                             unsigned char *cookie,
                             unsigned int *len);
int krypton__verify_cookie(SSL *ssl,
                           const unsigned char *secret,
                           unsigned int secret_len,
                           const unsigned char *cookie,
                           unsigned int len);
#endif

#endif /* _KRYPTON_H */
