/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include "ktypes.h"

/* TLS1.2 Pseudo-Random-Function */
NS_INTERNAL void prf(const uint8_t *sec, size_t sec_len, const uint8_t *seed,
                     size_t seed_len, uint8_t *out, size_t olen) {
  uint8_t A_i[SHA256_SIZE], tmp[SHA256_SIZE];
  const uint8_t *msgs[2];
  size_t msgl[2];

  /* Compute A1 */
  msgs[0] = seed;
  msgl[0] = seed_len;

  kr_hmac_sha256_v(sec, sec_len, 1, msgs, msgl, A_i);

  msgs[0] = A_i;
  msgl[0] = sizeof(A_i);
  msgs[1] = seed;
  msgl[1] = seed_len;

  for (;;) {
    size_t l = olen > SHA256_SIZE ? SHA256_SIZE : olen;
    kr_hmac_sha256_v(sec, sec_len, 2, msgs, msgl, tmp);
    memcpy(out, tmp, l);
    out += l;
    olen -= l;
    if (olen == 0) break;
    kr_hmac_sha256_v(sec, sec_len, 1, msgs, msgl, tmp);
    memcpy(A_i, tmp, SHA256_SIZE);
  }
}
