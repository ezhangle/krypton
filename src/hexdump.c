/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include "../openssl/ssl.h"
#include "ktypes.h"
#include <ctype.h>

#if KRYPTON_DEBUG
void hex_dumpf(FILE *f, const void *buf, size_t len, size_t llen) {
  const uint8_t *tmp = buf;
  size_t i, j;
  size_t line;

  if (NULL == f || 0 == len)
    return;
  if (!llen)
    llen = 0x10;

  for (j = 0; j < len; j += line, tmp += line) {
    if (j + llen > len) {
      line = len - j;
    } else {
      line = llen;
    }

    fprintf(f, " | %05zx : ", j);

    for (i = 0; i < line; i++) {
      if (isprint(tmp[i])) {
        fprintf(f, "%c", tmp[i]);
      } else {
        fprintf(f, ".");
      }
    }

    for (; i < llen; i++)
      fprintf(f, " ");

    for (i = 0; i < line; i++)
      fprintf(f, " %02x", tmp[i]);

    fprintf(f, "\n");
  }
  fprintf(f, "\n");
}

void hex_dump(const void *ptr, size_t len, size_t llen) {
  hex_dumpf(stdout, ptr, len, llen);
}
#endif
