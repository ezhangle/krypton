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
      dprintf(("Unknown algorithm\n"));
      break;
  }

  return 1;
bad_key:
  dprintf(("bad public key in certificate\n"));
  return 0;
}

static int parse_sig_alg(X509 *cert, const uint8_t *ptr, size_t len,
                         uint8_t *alg) {
  static const char *const rsaWithX = "\x2a\x86\x48\x86\xf7\x0d\x01\x01";
  const uint8_t *end = ptr + len;
  struct gber_tag tag;

  (void) cert;
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

static int kr_id_ce(const uint8_t *oid, size_t oid_len) {
  return (oid_len == 3 && oid[0] == 0x55 && oid[1] == 0x1d) ? oid[2] : -1;
}

static int decode_extension(X509 *cert, const uint8_t *oid, size_t oid_len,
                            const uint8_t critical, const uint8_t *val,
                            size_t val_len) {
  struct gber_tag tag;

  switch (kr_id_ce(oid, oid_len)) {
    case 15: { /* keyUsage */
      /* TODO(rojer): handle this. */
      return 1;
    }

    case 17: { /* subjectAltName */
      struct gber_tag tag;
      const uint8_t *ptr = val, *end = val + val_len;
      ptr = ber_decode_tag(&tag, ptr, end - ptr);
      if (ptr == NULL) return 0;
      if (tag.ber_tag != 0x30) return 0; /* Sequence. */
      cert->alt_names.ptr = realloc(cert->alt_names.ptr, tag.ber_len);
      if (cert->alt_names.ptr == NULL) return 0;
      memcpy(cert->alt_names.ptr, ptr, tag.ber_len);
      cert->alt_names.len = tag.ber_len;
      return 1;
    }

    case 19: { /* basicConstraints */
      /* encapsulated value */
      val = ber_decode_tag(&tag, val, val_len);
      if (NULL == val) return 0;
      val_len = tag.ber_len;

      if (val_len && val[0]) cert->is_ca = 1;
      return 1;
    }
  }

  if (critical) {
    dprintf(("unhandled critical extension\n"));
#ifdef KRYPTON_DEBUG
    hex_dump(oid, oid_len, 0);
#endif
    return 0;
  }

  return 1;
}

static int parse_extensions(X509 *cert, const uint8_t *ptr, size_t len) {
  const uint8_t *end = ptr + len;
  struct gber_tag tag;

  /* skip issuerUniqueID if present */
  ptr = ber_decode_tag(&tag, ptr, end - ptr);
  if (NULL == ptr) return 0;

  /* extensions are tagged as data */
  if (tag.ber_tag == 0xa3) {
    goto ext;
  }
  ptr += tag.ber_len;

  /* skip subjectUniqueID if present */
  ptr = ber_decode_tag(&tag, ptr, end - ptr);
  if (NULL == ptr) return 0;

  /* extensions are tagged as data */
  if (tag.ber_tag == 0xa3) {
    goto ext;
  }

  ptr = ber_decode_tag(&tag, ptr, end - ptr);
  if (NULL == ptr) return 0;

  if (tag.ber_tag != 0xa3) {
    /* failed to find extensions */
    return 1;
  }
ext:
  ptr = ber_decode_tag(&tag, ptr, end - ptr);
  if (NULL == ptr) return 0;

  /* sequence */
  if (tag.ber_tag != 0x30) {
    /* failed to find extensions */
    return 1;
  }

  while (ptr < end) {
    const uint8_t *oid, *val, *ext_end;
    size_t oid_len, val_len;
    uint8_t critical = 0;

    ptr = ber_decode_tag(&tag, ptr, end - ptr);
    if (NULL == ptr) return 0;
    if (tag.ber_tag != 0x30) {
      ptr += tag.ber_len;
      continue;
    }

    ext_end = ptr + tag.ber_len;

    ptr = ber_decode_tag(&tag, ptr, ext_end - ptr);
    if (NULL == ptr) return 0;
    oid = ptr;
    oid_len = tag.ber_len;
    ptr += tag.ber_len;

    ptr = ber_decode_tag(&tag, ptr, ext_end - ptr);
    if (NULL == ptr) return 0;

    if (tag.ber_tag == 1) {
      critical = (*ptr != 0);
      ptr++;
      ptr = ber_decode_tag(&tag, ptr, ext_end - ptr);
      if (NULL == ptr) return 0;
    }

    val = ptr;
    val_len = tag.ber_len;

    if (!decode_extension(cert, oid, oid_len, critical, val, val_len)) {
      dprintf(("failed to decode extension\n"));
      return 0;
    }

    ptr = ext_end;
  }

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

  if (!parse_extensions(cert, ptr, end - ptr)) return 0;

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
  X509 *cert;

  dprintf(("cert %p %d\n", ptr, (int) len));

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
      kr_hash_md5_v(1, &tbs.ptr, &tbs.len, cert->digest);
      break;
    case X509_HASH_SHA1:
      kr_hash_sha1_v(1, &tbs.ptr, &tbs.len, cert->digest);
      break;
    case X509_HASH_SHA256:
      kr_hash_sha256_v(1, &tbs.ptr, &tbs.len, cert->digest);
      break;
    default:
      break;
  }

  return cert;
bad_cert:
  X509_free(cert);
  dprintf(("bad certificate\n"));
  return NULL;
}

void X509_free(X509 *cert) {
  if (cert == NULL) return;
  free(cert->issuer.ptr);
  free(cert->subject.ptr);
  free(cert->sig.ptr);
  free(cert->alt_names.ptr);
  X509_free(cert->next);
  RSA_free(cert->pub_key);
  free(cert);
}

static void kr_get_next_label(struct ro_vec d, struct ro_vec *l) {
  const uint8_t *p = d.ptr + d.len - 1;
  l->ptr = p;
  l->len = 0;
  while (p >= d.ptr && *p != '.') {
    l->ptr = p--;
    l->len++;
  }
}

NS_INTERNAL int kr_match_domain_name(struct ro_vec pat, struct ro_vec dom) {
  struct ro_vec pl, dl;
  kr_get_next_label(pat, &pl);
  kr_get_next_label(dom, &dl);
  while (pl.len != 0 && dl.len != 0) {
    if (pl.len == 1 && *pl.ptr == '*') {
      /* Wildcard matching is underspecified. But this seems to be common
       * behavior. */
      return 1;
    }
    if (pl.len == dl.len) {
      /* No strncasecmp on W***ows... */
      size_t i;
      for (i = 0; i < pl.len; i++) {
        if (tolower(pl.ptr[i]) != tolower(dl.ptr[i])) return 0;
      }
    } else {
      return 0;
    }
    pat.len -= pl.len;
    if (pat.len > 0 && pat.ptr[pat.len - 1] == '.') pat.len--;
    dom.len -= dl.len;
    if (dom.len > 0 && dom.ptr[dom.len - 1] == '.') dom.len--;
    kr_get_next_label(pat, &pl);
    kr_get_next_label(dom, &dl);
  }
  return (pl.len == 0 && dl.len == 0);
}

NS_INTERNAL int X509_verify_name(X509 *cert, const char *name) {
  struct ro_vec n;
  n.ptr = (const uint8_t *) name;
  n.len = strlen(name);
  if (cert->alt_names.len > 0) {
    struct gber_tag tag;
    const uint8_t *ptr = cert->alt_names.ptr;
    const uint8_t *end = cert->alt_names.ptr + cert->alt_names.len;
    while (ptr < end) {
      ptr = ber_decode_tag(&tag, ptr, end - ptr);
      if (ptr == NULL) return 0;
      if ((tag.ber_tag & 0x1f) == 2) { /* dNSName */
        struct ro_vec an;
        an.ptr = ptr;
        an.len = tag.ber_len;
        dprintf(("alt name: %.*s\n", (int) an.len, an.ptr));
        if (kr_match_domain_name(n, an)) {
          dprintf(("name %s matched %.*s\n", name, (int) an.len, an.ptr));
          return 1;
        }
      }
      ptr += tag.ber_len;
    }
  }
  return 0;
}
