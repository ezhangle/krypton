/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include "../openssl/ssl.h"
#include "ktypes.h"
#include "crypto.h"
#include "ber.h"
#include "x509.h"
#include "pem.h"

SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth) {
  SSL_CTX *ctx;

  ctx = calloc(1, sizeof(*ctx));
  if (NULL == ctx)
    goto out;

  assert(meth != NULL);

  ctx->meth = *meth;

  /* success */
  goto out;

#if 0
out_free:
	free(ctx);
	ctx = NULL;
#endif
out:
  return ctx;
}

long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long mode, void *ptr) {
  (void)ctx;
  (void)cmd;
  (void)ptr;
  if (cmd == 33) {
    ctx->mode |= mode;
  }
  return ctx->mode;
}

void SSL_CTX_set_verify(SSL_CTX *ctx, int mode,
                        int (*verify_callback)(int, X509_STORE_CTX *)) {
  /* not implemented */
  assert(verify_callback == NULL);

  ctx->vrfy_mode = mode;
}

int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
                                  const char *CAPath) {
  unsigned int i;
  int ret = 0;
  X509 *ca;
  PEM *p;

  /* not implemented */
  if (CAPath) {
    dprintf(("%s: CAPath: Not implemented\n", __func__));
  }
  if (NULL == CAfile) {
    /* XXX: SSL_error ?? */
    return 0;
  }

  p = pem_load(CAfile, PEM_SIG_CERT);
  if (NULL == p)
    goto out;

  for (ca = NULL, i = 0; i < p->num_obj; i++) {
    DER *d = &p->obj[i];
    X509 *new;

    new = X509_new(d->der, d->der_len);
    if (NULL == new)
      goto out;

    new->next = ca;
    ca = new;
  }

  X509_free(ctx->ca_store);
  ctx->ca_store = ca;
  ret = 1;
out:
  return ret;
}

int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file) {
  int ret = 0;
  PEM *p;

  p = pem_load(file, PEM_SIG_CERT);
  if (NULL == p)
    goto out;

  pem_free(ctx->pem_cert);
  ctx->pem_cert = p;
  ret = 1;
out:
  return ret;
}

int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type) {
  int ret = 0;
  PEM *p;

  if (type != SSL_FILETYPE_PEM) {
    /* XXX: SSL_error */
    return 0;
  }

  p = pem_load(file, PEM_SIG_CERT);
  if (NULL == p)
    goto out;

  pem_free(ctx->pem_cert);
  ctx->pem_cert = p;
  ret = 1;
out:
  return ret;
}

static int decode_int(const uint8_t **pptr, const uint8_t *end,
                      struct ro_vec *result) {
  struct gber_tag tag;
  const uint8_t *ptr;

  ptr = ber_decode_tag(&tag, *pptr, end - *pptr);
  if (NULL == ptr)
    return 0;

  if (ber_id_octet_constructed(tag.ber_id))
    return 0;

  result->ptr = ptr;
  result->len = tag.ber_len;
  *pptr = ptr + tag.ber_len;

  /* strip a trailing zero byte if it exists,
   * it's like a sign-byte or something?
  */
  if (result->len && !result->ptr[0]) {
    result->len--;
    result->ptr++;
  }

  return 1;
}

/*
RSAPrivateKey ::= SEQUENCE {
  version           Version,
  modulus           INTEGER,  -- n
  publicExponent    INTEGER,  -- e
  privateExponent   INTEGER,  -- d
  prime1            INTEGER,  -- p
  prime2            INTEGER,  -- q
  exponent1         INTEGER,  -- d mod (p-1)
  exponent2         INTEGER,  -- d mod (q-1)
  coefficient       INTEGER,  -- (inverse of q) mod p
  otherPrimeInfos   OtherPrimeInfos OPTIONAL
}
*/
int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type) {
  struct ro_vec vers, n, e, d, p, q, e1, e2, c;
  const uint8_t *ptr, *end;
  struct gber_tag tag;
  RSA_CTX *rsa = NULL;
  int ret = 0;
  PEM *pem;

  (void)type;
  pem = pem_load(file, PEM_SIG_KEY);
  if (NULL == pem)
    goto out;

  ptr = ber_decode_tag(&tag, pem->obj[0].der, pem->obj[0].der_len);
  if (NULL == ptr)
    goto decode_err;

  if (!ber_id_octet_constructed(tag.ber_id))
    goto decode_err;

  end = ptr + tag.ber_len;

  /* eat the version */
  if (!decode_int(&ptr, end, &vers))
    goto decode_err;
  if (!decode_int(&ptr, end, &n))
    goto decode_err;
  if (!decode_int(&ptr, end, &e))
    goto decode_err;
  if (!decode_int(&ptr, end, &d))
    goto decode_err;
  if (!decode_int(&ptr, end, &p))
    goto decode_err;
  if (!decode_int(&ptr, end, &q))
    goto decode_err;
  if (!decode_int(&ptr, end, &e1))
    goto decode_err;
  if (!decode_int(&ptr, end, &e2))
    goto decode_err;
  if (!decode_int(&ptr, end, &c))
    goto decode_err;

  RSA_priv_key_new(&rsa, n.ptr, n.len, e.ptr, e.len, d.ptr, d.len, p.ptr, p.len,
                   q.ptr, q.len, e1.ptr, e1.len, e2.ptr, e2.len, c.ptr, c.len);
  if (NULL == rsa)
    goto out_free_pem;

  RSA_free(ctx->rsa_privkey);
  ctx->rsa_privkey = rsa;
  ret = 1;
  goto out_free_pem;

decode_err:
  dprintf(("%s: RSA private key decode error\n", file));
out_free_pem:
  pem_free(pem);
out:
  return ret;
}

void SSL_CTX_free(SSL_CTX *ctx) {
  if (ctx) {
    X509_free(ctx->ca_store);
    pem_free(ctx->pem_cert);
    RSA_free(ctx->rsa_privkey);
    free(ctx);
  }
}
