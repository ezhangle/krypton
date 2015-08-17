/*
 * Generic HMAC implementation, takes a vector hash function as an argument.
 * NOTE: does not handle keys larger than the block size.
 */
static void kr_hmac_v(kr_hash_func_t hash_func, const uint8_t *key,
                      size_t key_len, size_t num_msgs, const uint8_t *msgs[],
                      const size_t *msg_lens, uint8_t *digest,
                      size_t digest_len) {
  uint8_t k_pad[64];
  const uint8_t **k_msgs =
      (const uint8_t **) calloc(num_msgs + 2, sizeof(uint8_t *));
  size_t *k_msg_lens = (size_t *) calloc(num_msgs + 2, sizeof(size_t));
  size_t i;
  assert(key_len <= sizeof(k_pad));

  memset(k_pad, 0, sizeof(k_pad));
  memcpy(k_pad, key, key_len);
  for (i = 0; i < 64; i++) k_pad[i] ^= 0x36;

  k_msgs[0] = k_pad;
  k_msg_lens[0] = sizeof(k_pad);
  memcpy(k_msgs + 1, msgs, num_msgs * sizeof(uint8_t *));
  memcpy(k_msg_lens + 1, msg_lens, num_msgs * sizeof(size_t));
  hash_func(num_msgs + 1, k_msgs, k_msg_lens, digest);

  memset(k_pad, 0, sizeof(k_pad));
  memcpy(k_pad, key, key_len);
  for (i = 0; i < 64; i++) k_pad[i] ^= 0x5c;
  k_msgs[0] = k_pad;
  k_msg_lens[0] = sizeof(k_pad);
  k_msgs[1] = digest;
  k_msg_lens[1] = digest_len;
  hash_func(2, k_msgs, k_msg_lens, digest);

  free(k_msg_lens);
  free(k_msgs);
}

static void kr_ssl_hmac(SSL *ssl, int cs, size_t num_msgs,
                        const uint8_t *msgs[], const size_t *msg_lens,
                        uint8_t *digest) {
  kr_hash_func_t hf = NULL;
  size_t mac_len = tls_mac_len(ssl->cur);
  const uint8_t *key =
      (cs == KR_CLIENT_MAC ? ssl->cur->keys : ssl->cur->keys + mac_len);
  switch (ssl->cur->cipher_suite) {
    case TLS_RSA_WITH_NULL_MD5:
    case TLS_RSA_WITH_RC4_128_MD5:
      hf = kr_hash_md5_v;
      break;
    case TLS_RSA_WITH_RC4_128_SHA:
      hf = kr_hash_sha1_v;
      break;
    default:
      abort();
  }
  kr_hmac_v(hf, key, mac_len, num_msgs, msgs, msg_lens, digest, mac_len);
}
