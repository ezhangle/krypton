/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#ifndef _TLS_H
#define _TLS_H

#include "crypto.h"
#include "tlsproto.h"

typedef struct tls_security {
	/*
	 * client_write_MAC_key
	 * server_write_MAC_key
	 * client_write_key
	 * server_write_key
	*/
	uint8_t keys[MD5_SIZE * 2 + RC4_KEY_SIZE * 2];

	uint64_t client_write_seq;
	uint64_t server_write_seq;

	uint16_t cipher_suite;
	uint16_t peer_vers;
	uint8_t compressor;

	uint8_t cipher_negotiated:1;
	uint8_t compressor_negotiated:1;
	uint8_t bitpad:6;

	RSA_CTX *svr_key;

	uint8_t master_secret[48];
	struct tls_random cl_rnd;
	struct tls_random sv_rnd;

	RC4_CTX server_write_ctx;
	RC4_CTX client_write_ctx;

	SHA256_CTX handshakes_hash;
}*tls_sec_t;

NS_INTERNAL tls_sec_t tls_new_security(void);
NS_INTERNAL void tls_free_security(tls_sec_t sec);

/* generic */
NS_INTERNAL int tls_handle_recv(SSL *ssl, uint8_t *out, size_t out_len);
NS_INTERNAL void tls_generate_keys(tls_sec_t sec);
NS_INTERNAL int tls_send(SSL *ssl, uint8_t type, const void *buf, size_t len);
NS_INTERNAL int tls_tx_push(SSL *ssl, const void *data, size_t len);
NS_INTERNAL ssize_t tls_write(SSL *ssl, const uint8_t *buf, size_t sz);
NS_INTERNAL int tls_alert(SSL *ssl, uint8_t level, uint8_t desc);
NS_INTERNAL int tls_close_notify(SSL *ssl);

/* client */
NS_INTERNAL int tls_cl_finish(SSL *ssl);
NS_INTERNAL int tls_cl_hello(SSL *ssl);
NS_INTERNAL int tls_check_server_finished(tls_sec_t sec,
				const uint8_t *vrfy, size_t vrfy_len);
NS_INTERNAL void tls_generate_client_finished(tls_sec_t sec,
					uint8_t *vrfy, size_t vrfy_len);

/* server */
NS_INTERNAL int tls_sv_hello(SSL *ssl);
NS_INTERNAL int tls_sv_finish(SSL *ssl);

NS_INTERNAL int tls_check_client_finished(tls_sec_t sec,
				const uint8_t *vrfy, size_t vrfy_len);
NS_INTERNAL void tls_generate_server_finished(tls_sec_t sec,
				uint8_t *vrfy, size_t vrfy_len);

NS_INTERNAL void tls_compute_master_secret(tls_sec_t sec,
				struct tls_premaster_secret *pre);

#endif /* _TLS_H */
