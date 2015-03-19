/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include "ktypes.h"

struct test_vec {
  const void *key;
  const void *iv;
  const void *aad;
  const void *plain;
  const void *tag;
  const void *cipher;
  size_t key_len;
  size_t iv_len;
  size_t aad_len;
  size_t plain_len;
  size_t tag_len;
  size_t cipher_len;
};

static int test_vector(const struct test_vec *v)
{
  AES_GCM_CTX ctx;
  uint8_t cipher[256];
  uint8_t plain[256];
  uint8_t tag[32];

  assert(v->plain_len <= sizeof(cipher));
  assert(v->plain_len == v->cipher_len);
  memset(cipher, 0, sizeof(cipher));
  memset(tag, 0, sizeof(tag));

  aes_gcm_ctx(&ctx, v->key, v->key_len);

  aes_gcm_ae(&ctx,
             v->plain, v->plain_len,
             v->iv, v->iv_len,
             v->aad, v->aad_len,
             cipher, tag);

  if ( memcmp(tag, v->tag, v->tag_len) ) {
    printf("Tag failed: (expected, got)\n");
    hex_dump(v->tag, v->tag_len, 0);
    hex_dump(tag, v->tag_len, 0);
    return 0;
  }
  if ( memcmp(cipher, v->cipher, v->cipher_len) ) {
    printf("Ciphertext failed: (expected, got)\n");
    hex_dump(v->cipher, v->cipher_len, 0);
    hex_dump(cipher, v->cipher_len, 0);
    return 0;
  }

  if ( !aes_gcm_ad(&ctx,
             cipher, v->plain_len,
             v->iv, v->iv_len,
             v->aad, v->aad_len,
             tag, plain) ) {
    printf("Reverse tag check failed\n");
    return 0;
  }
  if ( memcmp(plain, v->plain, v->plain_len) ) {
    printf("Reverse failed: (expected, got)\n");
    hex_dump(v->plain, v->plain_len, 0);
    hex_dump(plain, v->plain_len, 0);
    return 0;
  }

  return 1;
}

static const struct test_vec nist4 = {
  .key =    "\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08",
  .iv =     "\xca\xfe\xba\xbe\xfa\xce\xdb\xad\xde\xca\xf8\x88",
  .plain =  "\xd9\x31\x32\x25\xf8\x84\x06\xe5\xa5\x59\x09\xc5\xaf\xf5\x26\x9a"
            "\x86\xa7\xa9\x53\x15\x34\xf7\xda\x2e\x4c\x30\x3d\x8a\x31\x8a\x72"
            "\x1c\x3c\x0c\x95\x95\x68\x09\x53\x2f\xcf\x0e\x24\x49\xa6\xb5\x25"
            "\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57\xba\x63\x7b\x39",
  .aad =    "\xfe\xed\xfa\xce\xde\xad\xbe\xef\xfe\xed\xfa\xce\xde\xad\xbe\xef"
            "\xab\xad\xda\xd2",

  .cipher = "\x42\x83\x1e\xc2\x21\x77\x74\x24\x4b\x72\x21\xb7\x84\xd0\xd4\x9c"
            "\xe3\xaa\x21\x2f\x2c\x02\xa4\xe0\x35\xc1\x7e\x23\x29\xac\xa1\x2e"
            "\x21\xd5\x14\xb2\x54\x66\x93\x1c\x7d\x8f\x6a\x5a\xac\x84\xaa\x05"
            "\x1b\xa3\x0b\x39\x6a\x0a\xac\x97\x3d\x58\xe0\x91",
  .tag =    "\x5b\xc9\x4f\xbc\x32\x21\xa5\xdb\x94\xfa\xe9\x5a\xe7\x12\x1a\x47",

  .key_len = 16,
  .iv_len = 12,
  .plain_len = 60,
  .aad_len = 20,
  .cipher_len = 60,
  .tag_len = 16,
};

int main(int argc, char **argv)
{
  if ( !test_vector(&nist4) )
    return EXIT_FAILURE;
  printf("OK\n");
  return EXIT_SUCCESS;
}
