/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include "ktypes.h"

#define RANDOM_SOURCE "/dev/urandom"
int get_random(uint8_t *out, size_t len) {
  static FILE *fp = NULL;
  size_t ret = 0;

  if (fp == NULL) {
    /* TODO(lsm): provide cleanup API  */
    fp = fopen(RANDOM_SOURCE, "rb");
  }

  if (fp != NULL) {
    ret = fread(out, 1, len, fp);
  }

  return ret == len;
}

int get_random_nonzero(uint8_t *out, size_t len) {
  size_t i;

  if (!get_random(out, len))
    return 0;

  for (i = 0; i < len; i++) {
    while (out[i] == 0) {
      if (!get_random(out + i, 1))
        return 0;
    }
  }

  return 1;
}
