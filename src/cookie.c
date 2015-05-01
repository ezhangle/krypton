/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include "../openssl/ssl.h"
#include "ktypes.h"
#include "ssl.h"

#ifdef KRYPTON_DTLS
int krypton__generate_secret(unsigned char *secret, unsigned int secret_len)
{
  return 1;
}

int krypton__generate_cookie(SSL *ssl,
                             unsigned char *secret,
                             unsigned int secret_len,
                             unsigned char *cookie,
                             unsigned int *len)
{
  assert(*len >= SHA256_SIZE);
  hmac_sha256((unsigned char *)&ssl->st, dtls_socklen(ssl),
              secret, secret_len, cookie);
  *len = SHA256_SIZE;
  return 1;
}

int krypton__verify_cookie(SSL *ssl,
                           const unsigned char *secret,
                           unsigned int secret_len,
                           const unsigned char *cookie,
                           unsigned int len)
{
  unsigned char digest[SHA256_SIZE];
  if (len != SHA256_SIZE)
    return 0;
  hmac_sha256((unsigned char *)&ssl->st, dtls_socklen(ssl),
              secret, secret_len, digest);
  return !memcmp(digest, cookie, sizeof(digest));
}
#endif
