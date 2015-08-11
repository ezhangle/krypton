/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include "ktypes.h"

/* TLS1.2 Pseudo-Random-Function */
NS_INTERNAL void prf(const uint8_t *sec, size_t sec_len, const uint8_t *seed,
                     size_t seed_len, uint8_t *out, size_t olen) {
  uint8_t A1[128];
  const uint8_t *A1_ptr = &A1[0];
  size_t A1_len = SHA256_SIZE + seed_len;

  assert(A1_len < sizeof(A1)); /* TODO(lsm): fix this */

  kr_hmac_sha256_v(sec, sec_len, 1, &seed, &seed_len, A1);
  memcpy(A1 + SHA256_SIZE, seed, seed_len);

  for (;;) {
    if (olen >= SHA256_SIZE) {
      size_t l = SHA256_SIZE;
      kr_hmac_sha256_v(sec, sec_len, 1, &A1_ptr, &A1_len, out);
      out += SHA256_SIZE;
      olen -= SHA256_SIZE;
      if (olen) kr_hmac_sha256_v(sec, sec_len, 1, &A1_ptr, &l, A1);
    } else {
      uint8_t tmp[SHA256_SIZE];
      kr_hmac_sha256_v(sec, sec_len, 1, &A1_ptr, &A1_len, tmp);
      memcpy(out, tmp, olen);
      break;
    }
  }
}
