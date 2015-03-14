/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include "../openssl/ssl.h"
#include "ktypes.h"
#include "crypto.h"
#include "x509.h"
#include "ber.h"

static int parse_enc_alg(X509 *cert, const uint8_t *ptr, size_t len) {
  static const char *const rsaEncrypt = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
  struct gber_tag tag;

  ptr = ber_decode_tag(&tag, ptr, len);
  if (NULL == ptr) {
    return 0;
  }

  if (tag.ber_len == 9 && !memcmp(rsaEncrypt, ptr, tag.ber_len)) {
    cert->enc_alg = X509_ENC_ALG_RSA;
  } else {
    cert->enc_alg = X509_ENC_ALG_UNKNOWN;
  }

  return 1;
}

static int parse_pubkey(X509 *cert, const uint8_t *ptr, size_t len) {
  const uint8_t *end;
  struct ro_vec mod, exp;
  struct gber_tag tag;

  /* rsaEncrypt it is, let's get the key */
  if (!ptr[0]) {
    ptr++;
    len--;
  }

  ptr = ber_decode_tag(&tag, ptr, len);
  if (NULL == ptr) goto bad_key;
  end = ptr + tag.ber_len;

  ptr = ber_decode_tag(&tag, ptr, end - ptr);
  if (NULL == ptr || tag.ber_len < 1) goto bad_key;
  mod.ptr = ptr + 1;
  mod.len = tag.ber_len - 1;
  ptr += tag.ber_len;

  ptr = ber_decode_tag(&tag, ptr, end - ptr);
  if (NULL == ptr || !tag.ber_len) goto bad_key;
  exp.ptr = ptr;
  exp.len = tag.ber_len;

  switch (cert->enc_alg) {
    case X509_ENC_ALG_RSA:
      RSA_pub_key_new(&cert->pub_key, mod.ptr, mod.len, exp.ptr, exp.len);
      if (NULL == cert->pub_key) goto bad_key;
      break;
    default:
      dprintf("Unknown algorithm\n");
      break;
  }

  return 1;
bad_key:
  dprintf("bad public key in certificate\n");
  return 0;
}

static int parse_sig_alg(X509 *cert, const uint8_t *ptr, size_t len,
                         uint8_t *alg) {
  static const char *const rsaWithX = "\x2a\x86\x48\x86\xf7\x0d\x01\x01";
  const uint8_t *end = ptr + len;
  struct gber_tag tag;

  ptr = ber_decode_tag(&tag, ptr, end - ptr);
  if (NULL == ptr) return 0;

  if (tag.ber_len != 9) return 0;
  if (memcmp(ptr, rsaWithX, 8)) return 0;

  *alg = ptr[8];

  return 1;
}

static int parse_pubkey_info(X509 *cert, const uint8_t *ptr, size_t len) {
  const uint8_t *end = ptr + len;
  struct gber_tag tag;

  ptr = ber_decode_tag(&tag, ptr, end - ptr);
  if (NULL == ptr) return 0;
  if (!parse_enc_alg(cert, ptr, tag.ber_len)) return 0;
  ptr += tag.ber_len;

  ptr = ber_decode_tag(&tag, ptr, end - ptr);
  if (NULL == ptr) return 0;
  if (!parse_pubkey(cert, ptr, tag.ber_len)) return 0;
  ptr += tag.ber_len;

  return 1;
}

static int parse_tbs_cert(X509 *cert, const uint8_t *ptr, size_t len) {
  const uint8_t *end = ptr + len;
  struct gber_tag tag;

  ptr = ber_decode_tag(&tag, ptr, end - ptr);
  if (NULL == ptr) return 0;

  /* if explicit tag, version number is present */
  if (tag.ber_tag == 0xa0) {
    ptr += tag.ber_len;
    ptr = ber_decode_tag(&tag, ptr, end - ptr);
    if (NULL == ptr) return 0;
  }

  /* int:serial number */
  ptr += tag.ber_len;

  ptr = ber_decode_tag(&tag, ptr, end - ptr);
  if (NULL == ptr) return 0;
  if (!parse_sig_alg(cert, ptr, tag.ber_len, &cert->hash_alg)) return 0;
  ptr += tag.ber_len;

  /* name: issuer */
  ptr = ber_decode_tag(&tag, ptr, end - ptr);
  if (NULL == ptr) return 0;
  cert->issuer.ptr = malloc(tag.ber_len);
  if (NULL == cert->issuer.ptr) return 0;
  memcpy(cert->issuer.ptr, ptr, tag.ber_len);
  cert->issuer.len = tag.ber_len;
  ptr += tag.ber_len;

  /* validity (dates) */
  ptr = ber_decode_tag(&tag, ptr, end - ptr);
  if (NULL == ptr) return 0;
  ptr += tag.ber_len;

  /* name: subject */
  ptr = ber_decode_tag(&tag, ptr, end - ptr);
  if (NULL == ptr) return 0;
  cert->subject.ptr = malloc(tag.ber_len);
  if (NULL == cert->subject.ptr) return 0;
  memcpy(cert->subject.ptr, ptr, tag.ber_len);
  cert->subject.len = tag.ber_len;
  ptr += tag.ber_len;

  ptr = ber_decode_tag(&tag, ptr, end - ptr);
  if (NULL == ptr) return 0;
  if (!parse_pubkey_info(cert, ptr, tag.ber_len)) return 0;
  ptr += tag.ber_len;

  /* skip the rest... although apparently there's an alternate DNS-name
   * extension we might care about
   */
  return 1;
}

int x509_issued_by(struct vec *issuer, struct vec *subject) {
  if (issuer->len == subject->len &&
      !memcmp(subject->ptr, issuer->ptr, issuer->len)) {
    return 1;
  }

  return 0;
}

/* As per RFC3280 */
/* FIXME: need a way to determine error */
X509 *X509_new(const uint8_t *ptr, size_t len) {
  const uint8_t *end = ptr + len;
  struct gber_tag tag;
  struct ro_vec tbs;
  union {
    MD5_CTX md5;
    SHA_CTX sha1;
    SHA256_CTX sha256;
  } u;
  X509 *cert;

  cert = calloc(1, sizeof(*cert));
  if (NULL == cert) return NULL;

  ptr = ber_decode_tag(&tag, ptr, end - ptr);
  if (NULL == ptr) goto bad_cert;
  end = ptr + tag.ber_len;

  /* tbsCertificate - to be signed */
  tbs.ptr = ptr;
  ptr = ber_decode_tag(&tag, ptr, end - ptr);
  if (NULL == ptr) goto bad_cert;
  tbs.len = (ptr + tag.ber_len) - tbs.ptr;
  if (!parse_tbs_cert(cert, ptr, tag.ber_len)) {
    goto bad_cert;
  }
  ptr += tag.ber_len;

  /* signatureAlgorithm */
  ptr = ber_decode_tag(&tag, ptr, end - ptr);
  if (NULL == ptr) goto bad_cert;
  if (!parse_sig_alg(cert, ptr, tag.ber_len, &cert->issuer_hash_alg)) return 0;
  ptr += tag.ber_len;

  /* signatureValue */
  ptr = ber_decode_tag(&tag, ptr, end - ptr);
  if (NULL == ptr) goto bad_cert;
  if (tag.ber_len && !ptr[0]) {
    /* strip sign-forcing byte */
    ptr++;
    tag.ber_len--;
  }
  cert->sig.ptr = malloc(tag.ber_len);
  if (NULL == cert->sig.ptr) return 0;
  memcpy(cert->sig.ptr, ptr, tag.ber_len);
  cert->sig.len = tag.ber_len;
  ptr += tag.ber_len;

  if (x509_issued_by(&cert->issuer, &cert->subject)) {
    cert->is_self_signed = 1;
  }

  switch (cert->issuer_hash_alg) {
    case X509_HASH_MD5:
      MD5_Init(&u.md5);
      MD5_Update(&u.md5, tbs.ptr, tbs.len);
      MD5_Final(cert->digest, &u.md5);
      break;
    case X509_HASH_SHA1:
      SHA1_Init(&u.sha1);
      SHA1_Update(&u.sha1, tbs.ptr, tbs.len);
      SHA1_Final(cert->digest, &u.sha1);
      break;
    case X509_HASH_SHA256:
      SHA256_Init(&u.sha256);
      SHA256_Update(&u.sha256, tbs.ptr, tbs.len);
      SHA256_Final(cert->digest, &u.sha256);
      break;
    default:
      break;
  }

  return cert;
bad_cert:
  X509_free(cert);
  dprintf("bad certificate\n");
  return NULL;
}

void X509_free(X509 *cert) {
  if (cert) {
    free(cert->issuer.ptr);
    free(cert->subject.ptr);
    free(cert->sig.ptr);
    X509_free(cert->next);
    RSA_free(cert->pub_key);
    free(cert);
  }
}
