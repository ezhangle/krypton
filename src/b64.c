/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include "ktypes.h"

static int decode(uint8_t in, uint8_t *out) {
  if (in >= 'A' && in <= 'Z') {
    *out = in - 'A';
    return 1;
  }
  if (in >= 'a' && in <= 'z') {
    *out = (in - 'a') + 26;
    return 1;
  }
  if (in >= '0' && in <= '9') {
    *out = (in - '0') + 52;
    return 1;
  }
  if (in == '+') {
    *out = 62;
    return 1;
  }
  if (in == '/') {
    *out = 63;
    return 1;
  }
  return 0;
}

static int decode_block1(const uint8_t *buf, uint8_t *out) {
  uint8_t tmp[2];
  unsigned int i;

  for (i = 0; i < sizeof(tmp); i++) {
    if (!decode(buf[i], &tmp[i])) return 0;
  }

  /* [ 6 from 0 : 2 from 1 ] */
  out[0] = (tmp[0] << 2) | (tmp[1] >> 4);

  return 1;
}
static int decode_block2(const uint8_t *buf, uint8_t *out) {
  uint8_t tmp[3];
  unsigned int i;

  for (i = 0; i < sizeof(tmp); i++) {
    if (!decode(buf[i], &tmp[i])) return 0;
  }

  /* [ 6 from 0 : 2 from 1 ] */
  /* [ 4 from 1 : 4 from 2 ] */
  out[0] = (tmp[0] << 2) | (tmp[1] >> 4);
  out[1] = ((tmp[1] & 0x0f) << 4) | (tmp[2] >> 2);

  return 1;
}
static int decode_block3(const uint8_t *buf, uint8_t *out) {
  uint8_t tmp[4];
  unsigned int i;

  for (i = 0; i < sizeof(tmp); i++) {
    if (!decode(buf[i], &tmp[i])) return 0;
  }

  /* [ 6 from 0 : 2 from 1 ] */
  /* [ 4 from 1 : 4 from 2 ] */
  /* [ 2 from 2 : 6 from 3 ] */
  out[0] = (tmp[0] << 2) | (tmp[1] >> 4);
  out[1] = ((tmp[1] & 0x0f) << 4) | (tmp[2] >> 2);
  out[2] = ((tmp[2] & 0x3) << 6) | tmp[3];
  return 1;
}

NS_INTERNAL int b64_decode(const uint8_t *buf, size_t len, uint8_t *out,
                           size_t *obytes) {
  *obytes = 0;
  while (len) {
    uint8_t olen;
    int ret;

    if (len < 4) {
      return 0;
    }

    if (buf[0] == '=') {
      ret = 1;
      olen = 0;
    } else if (buf[2] == '=') {
      ret = decode_block1(buf, out);
      olen = 1;
    } else if (buf[3] == '=') {
      ret = decode_block2(buf, out);
      olen = 2;
    } else {
      ret = decode_block3(buf, out);
      olen = 3;
    }

    if (!ret) return 0;

    *obytes += olen;
    out += olen;
    buf += 4;
    len -= 4;
  }

  return 1;
}

#if CODE_FU
#include <ctype.h>

int main(int argc, char **argv) {
  char buf[300];
  uint8_t out[400];
  size_t olen;

  while (fgets(buf, sizeof(buf), stdin)) {
    char *lf;

    lf = strchr(buf, '\n');
    *lf = '\0';

    if (!b64_decode((uint8_t *) buf, lf - buf, out, &olen)) {
      printf("error\n");
    } else {
      hex_dump(out, olen, 0);
    }
  }
  return 0;
}
#endif
