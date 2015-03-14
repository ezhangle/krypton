/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#ifndef _X509_H
#define _X509_H

#define X509_ENC_ALG_UNKNOWN	0
#define X509_ENC_ALG_RSA	1

#define X509_HASH_MD5		0x04
#define X509_HASH_SHA1		0x05
#define X509_HASH_SHA256	0x0b

typedef struct X509_st X509;
struct X509_st {
	X509 *next;
	RSA_CTX *pub_key;

	struct vec issuer;
	struct vec subject;
	struct vec sig;

	uint8_t enc_alg;
	uint8_t is_self_signed;

	/* both must be RSA + something */
	uint8_t hash_alg;
	uint8_t issuer_hash_alg;

	uint8_t digest[MAX_DIGEST_SIZE];
};

NS_INTERNAL X509 *X509_new(const uint8_t *ptr, size_t len);
/* chain should be backwards with subject at the end */
NS_INTERNAL int X509_verify(X509 *ca_store, X509 *chain);
NS_INTERNAL void X509_free(X509 *cert);

NS_INTERNAL int x509_issued_by(struct vec *issuer, struct vec *subject);

#endif /* _X509_H */
