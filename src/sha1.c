/*
 * SHA1 routine optimized to do word accesses rather than byte accesses,
 * and to avoid unnecessary copies into the context array.
 *
 * This was initially based on the Mozilla SHA1 implementation, although
 * none of the original Mozilla code remains.
 */
#ifndef KR_EXT_SHA1

#include "ktypes.h"

typedef struct {
  uint64_t size;
  unsigned int H[5];
  unsigned int W[16];
} SHA_CTX;

#define SHA_ROT(X, l, r) (((X) << (l)) | ((X) >> (r)))
#define SHA_ROL(X, n) SHA_ROT(X, n, 32 - (n))
#define SHA_ROR(X, n) SHA_ROT(X, 32 - (n), n)
#define setW(x, val) (W(x) = (val))

/*
 * Performance might be improved if the CPU architecture is OK with
 * unaligned 32-bit loads and a fast be32toh() is available.
 * Otherwise fall back to byte loads and shifts which is portable,
 * and is faster on architectures with memory alignment issues.
 */

#if defined(__i386__) || defined(__x86_64__) || defined(_M_IX86) ||        \
    defined(_M_X64) || defined(__ppc__) || defined(__ppc64__) ||           \
    defined(__powerpc__) || defined(__powerpc64__) || defined(__s390__) || \
    defined(__s390x__)

#define get_be32(p) be32toh(*(unsigned int *)(p))
#define put_be32(p, v)                 \
  do {                                 \
    *(unsigned int *)(p) = htobe32(v); \
  } while (0)

#else

#define get_be32(p)                       \
  ((*((unsigned char *) (p) + 0) << 24) | \
   (*((unsigned char *) (p) + 1) << 16) | \
   (*((unsigned char *) (p) + 2) << 8) | (*((unsigned char *) (p) + 3) << 0))
#define put_be32(p, v)                        \
  do {                                        \
    unsigned int __v = (v);                   \
    *((unsigned char *) (p) + 0) = __v >> 24; \
    *((unsigned char *) (p) + 1) = __v >> 16; \
    *((unsigned char *) (p) + 2) = __v >> 8;  \
    *((unsigned char *) (p) + 3) = __v >> 0;  \
  } while (0)

#endif

/* This "rolls" over the 512-bit array */
#define W(x) (array[(x) &15])

/*
 * Where do we get the source from? The first 16 iterations get it from
 * the input data, the next mix it from the 512-bit array.
 */
#define SHA_SRC(t) get_be32((unsigned char *) block + (t) *4)
#define SHA_MIX(t) SHA_ROL(W((t) + 13) ^ W((t) + 8) ^ W((t) + 2) ^ W(t), 1);

#define SHA_ROUND(t, input, fn, constant, A, B, C, D, E) \
  do {                                                   \
    unsigned int TEMP = input(t);                        \
    setW(t, TEMP);                                       \
    E += TEMP + SHA_ROL(A, 5) + (fn) + (constant);       \
    B = SHA_ROR(B, 2);                                   \
  } while (0)

#define T_0_15(t, A, B, C, D, E) \
  SHA_ROUND(t, SHA_SRC, (((C ^ D) & B) ^ D), 0x5a827999, A, B, C, D, E)
#define T_16_19(t, A, B, C, D, E) \
  SHA_ROUND(t, SHA_MIX, (((C ^ D) & B) ^ D), 0x5a827999, A, B, C, D, E)
#define T_20_39(t, A, B, C, D, E) \
  SHA_ROUND(t, SHA_MIX, (B ^ C ^ D), 0x6ed9eba1, A, B, C, D, E)
#define T_40_59(t, A, B, C, D, E) \
  SHA_ROUND(t, SHA_MIX, ((B & C) + (D & (B ^ C))), 0x8f1bbcdc, A, B, C, D, E)
#define T_60_79(t, A, B, C, D, E) \
  SHA_ROUND(t, SHA_MIX, (B ^ C ^ D), 0xca62c1d6, A, B, C, D, E)

static void SHA1_Block(SHA_CTX *ctx, const void *block) {
  unsigned int A, B, C, D, E;
  unsigned int array[16];

  A = ctx->H[0];
  B = ctx->H[1];
  C = ctx->H[2];
  D = ctx->H[3];
  E = ctx->H[4];

  /* Round 1 - iterations 0-16 take their input from 'block' */
  T_0_15(0, A, B, C, D, E);
  T_0_15(1, E, A, B, C, D);
  T_0_15(2, D, E, A, B, C);
  T_0_15(3, C, D, E, A, B);
  T_0_15(4, B, C, D, E, A);
  T_0_15(5, A, B, C, D, E);
  T_0_15(6, E, A, B, C, D);
  T_0_15(7, D, E, A, B, C);
  T_0_15(8, C, D, E, A, B);
  T_0_15(9, B, C, D, E, A);
  T_0_15(10, A, B, C, D, E);
  T_0_15(11, E, A, B, C, D);
  T_0_15(12, D, E, A, B, C);
  T_0_15(13, C, D, E, A, B);
  T_0_15(14, B, C, D, E, A);
  T_0_15(15, A, B, C, D, E);

  /* Round 1 - tail. Input from 512-bit mixing array */
  T_16_19(16, E, A, B, C, D);
  T_16_19(17, D, E, A, B, C);
  T_16_19(18, C, D, E, A, B);
  T_16_19(19, B, C, D, E, A);

  /* Round 2 */
  T_20_39(20, A, B, C, D, E);
  T_20_39(21, E, A, B, C, D);
  T_20_39(22, D, E, A, B, C);
  T_20_39(23, C, D, E, A, B);
  T_20_39(24, B, C, D, E, A);
  T_20_39(25, A, B, C, D, E);
  T_20_39(26, E, A, B, C, D);
  T_20_39(27, D, E, A, B, C);
  T_20_39(28, C, D, E, A, B);
  T_20_39(29, B, C, D, E, A);
  T_20_39(30, A, B, C, D, E);
  T_20_39(31, E, A, B, C, D);
  T_20_39(32, D, E, A, B, C);
  T_20_39(33, C, D, E, A, B);
  T_20_39(34, B, C, D, E, A);
  T_20_39(35, A, B, C, D, E);
  T_20_39(36, E, A, B, C, D);
  T_20_39(37, D, E, A, B, C);
  T_20_39(38, C, D, E, A, B);
  T_20_39(39, B, C, D, E, A);

  /* Round 3 */
  T_40_59(40, A, B, C, D, E);
  T_40_59(41, E, A, B, C, D);
  T_40_59(42, D, E, A, B, C);
  T_40_59(43, C, D, E, A, B);
  T_40_59(44, B, C, D, E, A);
  T_40_59(45, A, B, C, D, E);
  T_40_59(46, E, A, B, C, D);
  T_40_59(47, D, E, A, B, C);
  T_40_59(48, C, D, E, A, B);
  T_40_59(49, B, C, D, E, A);
  T_40_59(50, A, B, C, D, E);
  T_40_59(51, E, A, B, C, D);
  T_40_59(52, D, E, A, B, C);
  T_40_59(53, C, D, E, A, B);
  T_40_59(54, B, C, D, E, A);
  T_40_59(55, A, B, C, D, E);
  T_40_59(56, E, A, B, C, D);
  T_40_59(57, D, E, A, B, C);
  T_40_59(58, C, D, E, A, B);
  T_40_59(59, B, C, D, E, A);

  /* Round 4 */
  T_60_79(60, A, B, C, D, E);
  T_60_79(61, E, A, B, C, D);
  T_60_79(62, D, E, A, B, C);
  T_60_79(63, C, D, E, A, B);
  T_60_79(64, B, C, D, E, A);
  T_60_79(65, A, B, C, D, E);
  T_60_79(66, E, A, B, C, D);
  T_60_79(67, D, E, A, B, C);
  T_60_79(68, C, D, E, A, B);
  T_60_79(69, B, C, D, E, A);
  T_60_79(70, A, B, C, D, E);
  T_60_79(71, E, A, B, C, D);
  T_60_79(72, D, E, A, B, C);
  T_60_79(73, C, D, E, A, B);
  T_60_79(74, B, C, D, E, A);
  T_60_79(75, A, B, C, D, E);
  T_60_79(76, E, A, B, C, D);
  T_60_79(77, D, E, A, B, C);
  T_60_79(78, C, D, E, A, B);
  T_60_79(79, B, C, D, E, A);

  ctx->H[0] += A;
  ctx->H[1] += B;
  ctx->H[2] += C;
  ctx->H[3] += D;
  ctx->H[4] += E;
}

void SHA1_Init(SHA_CTX *ctx) {
  ctx->size = 0;

  /* Initialize H with the magic constants (see FIPS180 for constants) */
  ctx->H[0] = 0x67452301;
  ctx->H[1] = 0xefcdab89;
  ctx->H[2] = 0x98badcfe;
  ctx->H[3] = 0x10325476;
  ctx->H[4] = 0xc3d2e1f0;
}

void SHA1_Update(SHA_CTX *ctx, const void *data, unsigned long len) {
  unsigned int lenW = ctx->size & 63;

  ctx->size += len;

  /* Read the data into W and process blocks as they get full */
  if (lenW) {
    unsigned int left = 64 - lenW;
    if (len < left) left = len;
    memcpy(lenW + (char *) ctx->W, data, left);
    lenW = (lenW + left) & 63;
    len -= left;
    data = ((const char *) data + left);
    if (lenW) return;
    SHA1_Block(ctx, ctx->W);
  }
  while (len >= 64) {
    SHA1_Block(ctx, data);
    data = ((const char *) data + 64);
    len -= 64;
  }
  if (len) memcpy(ctx->W, data, len);
}

void SHA1_Final(unsigned char hashout[20], SHA_CTX *ctx) {
  static const unsigned char pad[64] = {0x80};
  unsigned int padlen[2];
  int i;

  /* Pad with a binary 1 (ie 0x80), then zeroes, then length */
  padlen[0] = htobe32((uint32_t)(ctx->size >> 29));
  padlen[1] = htobe32((uint32_t)(ctx->size << 3));

  i = ctx->size & 63;
  SHA1_Update(ctx, pad, 1 + (63 & (55 - i)));
  SHA1_Update(ctx, padlen, 8);

  /* Output hash */
  for (i = 0; i < 5; i++) put_be32(hashout + i * 4, ctx->H[i]);
}

static void kr_hash_sha1_v(size_t num_msgs, const uint8_t *msgs[],
                           const size_t *msg_lens, uint8_t *digest) {
  size_t i;
  SHA_CTX sha1;
  SHA1_Init(&sha1);
  for (i = 0; i < num_msgs; i++) {
    SHA1_Update(&sha1, msgs[i], msg_lens[i]);
  }
  SHA1_Final(digest, &sha1);
}
#endif /* !KR_EXT_SHA1 */
