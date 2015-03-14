/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include "../openssl/ssl.h"
#include "ktypes.h"
#include "crypto.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#define RANDOM_SOURCE "/dev/urandom"
int get_random(uint8_t *out, size_t len) {
  static int rfd = -1;
  ssize_t ret;
  if (rfd < 0) {
    rfd = open(RANDOM_SOURCE, O_RDONLY);
    if (rfd < 0) return 0;
  }

  ret = read(rfd, out, len);
  if (ret < 0 || (size_t)ret != len) return 0;

  return 1;
}

int get_random_nonzero(uint8_t *out, size_t len) {
  size_t i;

  if (!get_random(out, len)) return 0;

  for (i = 0; i < len; i++) {
    while (out[i] == 0) {
      if (!get_random(out + i, 1)) return 0;
    }
  }

  return 1;
}
