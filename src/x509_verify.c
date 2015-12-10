/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include "ktypes.h"

static int get_sig_digest(RSA_CTX *rsa, struct vec *sig, uint8_t *digest,
                          size_t *dlen) {
  uint8_t buf[512];
  struct gber_tag tag;
  const uint8_t *ptr, *end;
  int ret;

  assert(sig->len < sizeof(buf)); /* TODO(lsm): fix this */

  ret = RSA_decrypt(rsa, sig->ptr, buf, sig->len, 0);
  if (ret <= 0) {
    dprintf(("RSA signature check failed\n"));
    return 0;
  }

  ptr = ber_decode_tag(&tag, buf, ret);
  if (NULL == ptr) {
    goto err;
  }

  end = ptr + tag.ber_len;

  ptr = ber_decode_tag(&tag, ptr, end - ptr);
  if (NULL == ptr) {
    goto err;
  }
  ptr += tag.ber_len;

  ptr = ber_decode_tag(&tag, ptr, end - ptr);
  if (NULL == ptr) {
    goto err;
  }

  if (tag.ber_len > MAX_DIGEST_SIZE) goto err;

  memcpy(digest, ptr, tag.ber_len);
  *dlen = tag.ber_len;
  return 1;
err:
  dprintf(("Failed to decode signature block\n"));
  return 0;
}

static int do_verify(X509 *cur, X509 *nxt) {
  uint8_t digest[MAX_DIGEST_SIZE];
  size_t digest_len, expected_len;
again:

  if (!cur->is_ca) {
    dprintf(("Not a CA certificate!\n"));
    return 0;
  }

  /* TODO: chek expiry date on cur */

  if (cur->hash_alg != cur->issuer_hash_alg) {
    dprintf(("hash algorithms don't match\n"));
    return 0;
  }

  if ((size_t) RSA_block_size(cur->pub_key) != nxt->sig.len) {
    dprintf(("signature size doesn't match\n"));
    return 0;
  }

  switch (nxt->hash_alg) {
    case X509_HASH_MD5:
      expected_len = MD5_SIZE;
      break;
    case X509_HASH_SHA1:
      expected_len = SHA1_SIZE;
      break;
    case X509_HASH_SHA256:
      expected_len = SHA256_SIZE;
      break;
    default:
      dprintf(("Unsupported hash alg\n"));
      return 0;
  }
#if DEBUG_VERIFY
  dprintf(("%d byte RSA key, %zu byte sig\n", RSA_block_size(cur->pub_key),
           nxt->sig.len));
#endif

  if (!get_sig_digest(cur->pub_key, &nxt->sig, digest, &digest_len)) return 0;
#if DEBUG_VERIFY
  dprintf(("%zu byte digest (%d):\n", digest_len, nxt->hash_alg));
  hex_dump(digest, digest_len, 0);
#endif
  if (digest_len != expected_len) {
    dprintf(("Bad digest length: %d vs %d\n", (int) digest_len,
             (int) expected_len));
    return 0;
  }
#if DEBUG_VERIFY
  hex_dump(nxt->digest, digest_len, 0);
#endif
  if (memcmp(nxt->digest, digest, digest_len)) {
    dprintf(("bad signature\n"));
    return 0;
  }
#if DEBUG_VERIFY
  dprintf(("Verified OK\n"));
  dprintf(("\n"));
#endif

  /* if not the end of the chain, then tail-recursively check
   * the next pair
  */
  if (nxt->next) {
    cur = nxt;
    nxt = cur->next;
    if (!x509_issued_by(&cur->subject, &nxt->issuer)) {
      dprintf(("Bad chain\n"));
      return 0;
    }
    goto again;
  } else { /* TODO: check expiry date on nxt */
  }

  return 1;
}

/* Find a CA in our store which signed the last key in the cert chain.  Usually
 * we'd build a chain all the way back to a root CA which is self signed. But
 * for now, easier to just trust everything in our cert store that it's OK.
 *
 * This will matter in practice, for example if the root CA cert expires...
*/
#ifndef KR_NO_LOAD_CA_STORE
static X509 *find_anchor(SSL_CTX *ctx, X509 *chain) {
  X509 *cur;

  for (cur = ctx->ca_store; cur; cur = cur->next) {
    if (x509_issued_by(&cur->subject, &chain->issuer)) {
      return cur;
    }
  }

  return NULL;
}
#else

static enum pem_filter_result pem_issuer_filter(const DER *obj, int type,
                                                void *arg) {
  enum pem_filter_result res = PEM_FILTER_NO;
  struct vec *issuer = (struct vec *) arg;
  if (type != PEM_SIG_CERT) return PEM_FILTER_NO;
  X509 *new = X509_new(obj->der, obj->der_len);
  if (new != NULL && x509_issued_by(&new->subject, issuer)) {
    res = PEM_FILTER_YES_AND_STOP;
#if DEBUG_VERIFY
    dprintf(("found trust anchor\n"));
#endif
  }
  X509_free(new);
  return res;
}

static X509 *find_anchor(SSL_CTX *ctx, X509 *chain) {
  PEM *p = pem_load(ctx->ca_file, pem_issuer_filter, &chain->issuer);
  if (p != NULL && p->num_obj == 1) {
    X509 *new = X509_new(p->obj->der, p->obj->der_len);
    if (new != NULL && x509_issued_by(&new->subject, &chain->issuer)) {
      return new;
    }
    X509_free(new);
  }
  return NULL;
}
#endif

int X509_verify(SSL_CTX *ctx, X509 *chain) {
  int res;
  X509 *anchor;

  anchor = find_anchor(ctx, chain);
  if (NULL == anchor) {
    dprintf(("vrfy: Cannot find trust anchor\n"));
    return 0;
  }

#if DEBUG_VERIFY
  dprintf(("Verifying to here:\n"));
  hex_dump(anchor->subject.ptr, anchor->subject.len, 0);
#endif

  res = do_verify(anchor, chain);
#ifdef KR_NO_LOAD_CA_STORE
  X509_free(anchor);
#endif
  return res;
}
