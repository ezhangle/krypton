/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#ifndef _PEM_H
#define _PEM_H

struct pem_st {
  unsigned int tot_len;
  uint16_t num_obj;
  uint16_t max_obj;
  DER *obj;
};

struct der_st {
  uint8_t *der;
  uint32_t der_len;
  uint8_t der_type;
};

#define PEM_SIG_CERT (1 << 0)
#define PEM_SIG_KEY (1 << 1)     /* PKCS#8 */
#define PEM_SIG_RSA_KEY (1 << 2) /* PKCS#1 */
NS_INTERNAL struct pem_st *pem_load(const char *fn, int type_mask);
NS_INTERNAL void pem_free(struct pem_st *p);

/* not crypto, but required for reading keys and certs */
NS_INTERNAL int b64_decode(const uint8_t *buf, size_t len, uint8_t *out,
                           size_t *obytes);

#endif /* _PEM_H */
