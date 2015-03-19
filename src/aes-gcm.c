/*
 * Galois/Counter Mode (GCM) and GMAC with AES
 *
 * Copyright (c) 2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "ktypes.h"
#include "crypto.h"

static inline void WPA_PUT_BE32(uint8_t *a, uint32_t val)
{
	a[0] = (val >> 24) & 0xff;
	a[1] = (val >> 16) & 0xff;
	a[2] = (val >> 8) & 0xff;
	a[3] = val & 0xff;
}

static inline void WPA_PUT_BE64(uint8_t *a, uint64_t val)
{
	a[0] = val >> 56;
	a[1] = val >> 48;
	a[2] = val >> 40;
	a[3] = val >> 32;
	a[4] = val >> 24;
	a[5] = val >> 16;
	a[6] = val >> 8;
	a[7] = val & 0xff;
}

static void inc32(uint8_t *block)
{
	uint32_t val;
	val = be32toh(*(uint32_t *)(block + AES_BLOCKSIZE - 4));
	val++;
	WPA_PUT_BE32(block + AES_BLOCKSIZE - 4, val);
}


static void xor_block(uint8_t *dst, const uint8_t *src)
{
	uint32_t *d = (uint32_t *) dst;
	uint32_t *s = (uint32_t *) src;
	*d++ ^= *s++;
	*d++ ^= *s++;
	*d++ ^= *s++;
	*d++ ^= *s++;
}


static void shift_right_block(uint8_t *v)
{
	uint32_t val;

	val = be32toh(*(uint32_t *)(v + 12));
	val >>= 1;
	if (v[11] & 0x01)
		val |= 0x80000000;
	WPA_PUT_BE32(v + 12, val);

	val = be32toh(*(uint32_t *)(v + 8));
	val >>= 1;
	if (v[7] & 0x01)
		val |= 0x80000000;
	WPA_PUT_BE32(v + 8, val);

	val = be32toh(*(uint32_t *)(v + 4));
	val >>= 1;
	if (v[3] & 0x01)
		val |= 0x80000000;
	WPA_PUT_BE32(v + 4, val);

	val = be32toh(*(uint32_t *)(v));
	val >>= 1;
	WPA_PUT_BE32(v, val);
}


/* Multiplication in GF(2^128) */
static void gf_mult(const uint8_t *x, const uint8_t *y, uint8_t *z)
{
	uint8_t v[16];
	int i, j;

	memset(z, 0, 16); /* Z_0 = 0^128 */
	memcpy(v, y, 16); /* V_0 = Y */

	for (i = 0; i < 16; i++) {
		for (j = 0; j < 8; j++) {
			if (x[i] & (1 << (7 - j))) {
				/* Z_(i + 1) = Z_i XOR V_i */
				xor_block(z, v);
			} else {
				/* Z_(i + 1) = Z_i */
			}

			if (v[15] & 0x01) {
				/* V_(i + 1) = (V_i >> 1) XOR R */
				shift_right_block(v);
				/* R = 11100001 || 0^120 */
				v[0] ^= 0xe1;
			} else {
				/* V_(i + 1) = V_i >> 1 */
				shift_right_block(v);
			}
		}
	}
}


static void ghash_start(uint8_t *y)
{
	/* Y_0 = 0^128 */
	memset(y, 0, 16);
}


static void ghash(const uint8_t *h, const uint8_t *x, size_t xlen, uint8_t *y)
{
	size_t m, i;
	const uint8_t *xpos = x;
	uint8_t tmp[16];

	m = xlen / 16;

	for (i = 0; i < m; i++) {
		/* Y_i = (Y^(i-1) XOR X_i) dot H */
		xor_block(y, xpos);
		xpos += 16;

		/* dot operation:
		 * multiplication operation for binary Galois (finite) field of
		 * 2^128 elements */
		gf_mult(y, h, tmp);
		memcpy(y, tmp, 16);
	}

	if (x + xlen > xpos) {
		/* Add zero padded last block */
		size_t last = x + xlen - xpos;
		memcpy(tmp, xpos, last);
		memset(tmp + last, 0, sizeof(tmp) - last);

		/* Y_i = (Y^(i-1) XOR X_i) dot H */
		xor_block(y, tmp);

		/* dot operation:
		 * multiplication operation for binary Galois (finite) field of
		 * 2^128 elements */
		gf_mult(y, h, tmp);
		memcpy(y, tmp, 16);
	}

	/* Return Y_m */
}


static void aes_gctr(AES_CTX *ctx, const uint8_t *icb, const uint8_t *x, size_t xlen, uint8_t *y)
{
	size_t i, n, last;
	uint8_t cb[AES_BLOCKSIZE], tmp[AES_BLOCKSIZE];
	const uint8_t *xpos = x;
	uint8_t *ypos = y;

	if (xlen == 0)
		return;

	n = xlen / 16;

	memcpy(cb, icb, AES_BLOCKSIZE);
	/* Full blocks */
	for (i = 0; i < n; i++) {
		AES_ecb_encrypt(ctx, cb, ypos);
		xor_block(ypos, xpos);
		xpos += AES_BLOCKSIZE;
		ypos += AES_BLOCKSIZE;
		inc32(cb);
	}

	last = x + xlen - xpos;
	if (last) {
		/* Last, partial block */
		AES_ecb_encrypt(ctx, cb, tmp);
		for (i = 0; i < last; i++)
			*ypos++ = *xpos++ ^ tmp[i];
	}
}


static void aes_gcm_init_hash_subkey(AES_CTX *ctx, const uint8_t *key,
                                     size_t key_len, uint8_t *H)
{
	AES_set_key(ctx, key, AES_MODE_128);

	/* Generate hash subkey H = AES_K(0^128) */
	memset(H, 0, AES_BLOCKSIZE);
	AES_ecb_encrypt(ctx, H, H);
}


static void aes_gcm_prepare_y0(const uint8_t *iv, size_t iv_len, const uint8_t *H, uint8_t *Y0)
{
	uint8_t len_buf[16];

	if (iv_len == GCM_IV_SIZE) {
		/* Prepare block Y_0 = IV || 0^31 || 1 [len(IV) = 96] */
		memcpy(Y0, iv, iv_len);
		memset(Y0 + iv_len, 0, AES_BLOCKSIZE - iv_len);
		Y0[AES_BLOCKSIZE - 1] = 0x01;
	} else {
		/*
		 * s = 128 * ceil(len(IV)/128) - len(IV)
		 * Y_0 = GHASH_H(IV || 0^(s+64) || [len(IV)]_64)
		 */
		ghash_start(Y0);
		ghash(H, iv, iv_len, Y0);
		WPA_PUT_BE64(len_buf, 0);
		WPA_PUT_BE64(len_buf + 8, iv_len * 8);
		ghash(H, len_buf, sizeof(len_buf), Y0);
	}
}


static void aes_gcm_gctr(AES_CTX *ctx, const uint8_t *Y0, const uint8_t *in, size_t len,
			 uint8_t *out)
{
	uint8_t Y0inc[AES_BLOCKSIZE];

	if (len == 0)
		return;

	memcpy(Y0inc, Y0, AES_BLOCKSIZE);
	inc32(Y0inc);
	aes_gctr(ctx, Y0inc, in, len, out);
}


static void aes_gcm_ghash(const uint8_t *H, const uint8_t *aad, size_t aad_len,
			  const uint8_t *crypt, size_t crypt_len, uint8_t *S)
{
	uint8_t len_buf[16];

	/*
	 * u = 128 * ceil[len(C)/128] - len(C)
	 * v = 128 * ceil[len(A)/128] - len(A)
	 * S = GHASH_H(A || 0^v || C || 0^u || [len(A)]64 || [len(C)]64)
	 * (i.e., zero padded to block size A || C and lengths of each in bits)
	 */
	ghash_start(S);
	ghash(H, aad, aad_len, S);
	ghash(H, crypt, crypt_len, S);
	WPA_PUT_BE64(len_buf, aad_len * 8);
	WPA_PUT_BE64(len_buf + 8, crypt_len * 8);
	ghash(H, len_buf, sizeof(len_buf), S);
}

void aes_gcm_ctx(AES_GCM_CTX *ctx,
               const uint8_t *key, size_t key_len)
{
	aes_gcm_init_hash_subkey(&ctx->aes, key, key_len, ctx->H);
}

/**
 * aes_gcm_ae - GCM-AE_K(IV, P, A)
 */
void aes_gcm_ae(AES_GCM_CTX *ctx,
                const uint8_t *plain, size_t plain_len,
                const uint8_t *iv, size_t iv_len,
                const uint8_t *aad, size_t aad_len,
                uint8_t *crypt, uint8_t *tag)
{
	uint8_t S[16];

	aes_gcm_prepare_y0(iv, iv_len, ctx->H, ctx->Y0);

	/* C = GCTR_K(inc_32(Y_0), P) */
	aes_gcm_gctr(&ctx->aes, ctx->Y0, plain, plain_len, crypt);

	aes_gcm_ghash(ctx->H, aad, aad_len, crypt, plain_len, S);

	/* T = MSB_t(GCTR_K(Y_0, S)) */
	aes_gctr(&ctx->aes, ctx->Y0, S, sizeof(S), tag);

	/* Return (C, T) */
}

/**
 * aes_gcm_ad - GCM-AD_K(IV, C, A, T)
 */
int aes_gcm_ad(AES_GCM_CTX *ctx,
               const uint8_t *crypt, size_t crypt_len,
               const uint8_t *iv, size_t iv_len,
               const uint8_t *aad, size_t aad_len,
               const uint8_t *tag, uint8_t *plain)
{
	uint8_t S[16], T[16];

	aes_gcm_prepare_y0(iv, iv_len, ctx->H, ctx->Y0);

	/* P = GCTR_K(inc_32(Y_0), C) */
	aes_gcm_gctr(&ctx->aes, ctx->Y0, crypt, crypt_len, plain);

	aes_gcm_ghash(ctx->H, aad, aad_len, crypt, crypt_len, S);

	/* T' = MSB_t(GCTR_K(Y_0, S)) */
	aes_gctr(&ctx->aes, ctx->Y0, S, sizeof(S), T);

	if (memcmp(tag, T, 16) != 0) {
		dprintf(("GCM: Tag mismatch\n"));
		return 0;
	}

	return 1;
}
