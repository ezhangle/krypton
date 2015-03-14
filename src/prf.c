/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include <string.h>
#include "crypto.h"

/* TLS1.2 Pseudo-Random-Function */
NS_INTERNAL void prf(const uint8_t *sec, int sec_len, const uint8_t *seed,
                     int seed_len, uint8_t *out, int olen) {
  uint8_t A1[SHA256_SIZE + seed_len];

  hmac_sha256(seed, seed_len, sec, sec_len, A1);
  memcpy(A1 + SHA256_SIZE, seed, seed_len);

  for (;;) {
    if (olen >= SHA256_SIZE) {
      hmac_sha256(A1, sizeof(A1), sec, sec_len, out);
      out += SHA256_SIZE;
      olen -= SHA256_SIZE;
      if (olen)
        hmac_sha256(A1, SHA256_SIZE, sec, sec_len, A1);
    } else {
      uint8_t tmp[SHA256_SIZE];
      hmac_sha256(A1, sizeof(A1), sec, sec_len, tmp);
      memcpy(out, tmp, olen);
      break;
    }
  }
}
