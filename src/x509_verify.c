/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include "../openssl/ssl.h"
#include "ktypes.h"
#include "crypto.h"
#include "x509.h"
#include "ber.h"

static int get_sig_digest(RSA_CTX *rsa, struct vec *sig,
                          uint8_t digest[static MAX_DIGEST_SIZE],
                          size_t *dlen) {
  uint8_t buf[sig->len];
  struct gber_tag tag;
  const uint8_t *ptr, *end;
  int ret;

  ret = RSA_decrypt(rsa, sig->ptr, buf, sizeof(buf), 0);
  if (ret <= 0) {
    dprintf("RSA signature check failed\n");
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
  dprintf("Failed to decode signature block\n");
  return 0;
}

static int do_verify(X509 *cur, X509 *nxt) {
  uint8_t digest[MAX_DIGEST_SIZE];
  size_t digest_len, expected_len;
again:
  /* TODO: chek expiry date on cur */

  if (cur->hash_alg != cur->issuer_hash_alg) {
    dprintf("hash algorithms don't match\n");
    return 0;
  }

  if ((size_t)RSA_block_size(cur->pub_key) != nxt->sig.len) {
    dprintf("signature size doesn't match\n");
    return 0;
  }

  switch (cur->hash_alg) {
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
      dprintf("Unsupported hash alg\n");
      return 0;
  }
#if DEBUG_VERIFY
  dprintf("%d byte RSA key, %zu byte sig\n", RSA_block_size(cur->pub_key),
          nxt->sig.len);
#endif

  if (!get_sig_digest(cur->pub_key, &nxt->sig, digest, &digest_len)) return 0;
#if DEBUG_VERIFY
  dprintf("%zu byte digest:\n", digest_len);
  hex_dump(digest, digest_len, 0);
#endif
  if (digest_len != expected_len) {
    dprintf("Bad digest length\n");
    return 0;
  }
#if DEBUG_VERIFY
  hex_dump(nxt->digest, digest_len, 0);
#endif
  if (memcmp(nxt->digest, digest, digest_len)) {
    dprintf("bad signature\n");
    return 0;
  }
#if DEBUG_VERIFY
  dprintf("Verified OK\n");
  dprintf("\n");
#endif

  /* if not the end of the chain, then tail-recursively check
   * the next pair
  */
  if (nxt->next) {
    cur = nxt;
    nxt = cur->next;
    if (!x509_issued_by(&cur->subject, &nxt->issuer)) {
      dprintf("Bad chain\n");
      return 0;
    }
    goto again;
  } else {
    /* TODO: check expiry date on nxt */
  }

  return 1;
}

/* Find a CA in our store which signed the last key in the cert chain.  Usually
 * we'd build a chain all the way back to a root CA which is self signed. But
 * for now, easier to just trust everything in our cert store that it's OK.
 *
 * This will matter in practice, for example if the root CA cert expires...
*/
static X509 *find_anchor(X509 *ca_store, X509 *chain) {
  X509 *cur;

  for (cur = ca_store; cur; cur = cur->next) {
    if (x509_issued_by(&cur->subject, &chain->issuer)) {
      return cur;
    }
  }

  return NULL;
}

int X509_verify(X509 *ca_store, X509 *chain) {
  X509 *anchor;

  anchor = find_anchor(ca_store, chain);
  if (NULL == anchor) {
    dprintf("vrfy: Cannot find trust anchor\n");
    return 0;
  }

#if DEBUG_VERIFY
  dprintf("Verifying to here:\n");
  hex_dump(anchor->subject.ptr, anchor->subject.len, 0);
#endif

  return do_verify(anchor, chain);
}
