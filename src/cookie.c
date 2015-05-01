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
  memcpy(cookie, "01234567789abcef", 16);
  *len = 16;
  return 1;
}

int krypton__verify_cookie(SSL *ssl,
                           const unsigned char *secret,
                           unsigned int secret_len,
                           const unsigned char *cookie,
                           unsigned int len)
{
  return 1;
}
#endif
