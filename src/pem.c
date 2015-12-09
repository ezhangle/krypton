/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include "ktypes.h"

#define DER_INCREMENT 1024
#define OBJ_INCREMENT 4

static int check_end_marker(const char *str, int sig_type) {
  switch (sig_type) {
    case PEM_SIG_CERT:
      if (!strcmp(str, "-----END CERTIFICATE-----")) return 1;
      break;
    case PEM_SIG_KEY:
      if (!strcmp(str, "-----END PRIVATE KEY-----")) return 1;
      break;
    case PEM_SIG_RSA_KEY:
      if (!strcmp(str, "-----END RSA PRIVATE KEY-----")) return 1;
      break;
    default:
      assert(0);
  }
  return 0;
}

static int check_begin_marker(const char *str, uint8_t *got) {
  if (!strcmp(str, "-----BEGIN CERTIFICATE-----")) {
    *got = PEM_SIG_CERT;
    return 1;
  }
  if (!strcmp(str, "-----BEGIN PRIVATE KEY-----")) {
    *got = PEM_SIG_KEY;
    return 1;
  }
  if (!strcmp(str, "-----BEGIN RSA PRIVATE KEY-----")) {
    *got = PEM_SIG_RSA_KEY;
    return 1;
  }
  return 0;
}

static int add_line(DER *d, size_t *max_len, const uint8_t *buf, size_t len) {
  uint8_t dec[96];
  size_t olen;

  if (!b64_decode(buf, len, dec, &olen)) {
    dprintf(("pem: base64 error\n"));
    return 0;
  }

  if (d->der_len + olen > *max_len) {
    size_t new_len;
    uint8_t *new;

    new_len = *max_len + DER_INCREMENT;
    new = realloc(d->der, new_len);
    if (NULL == new) {
      dprintf(("pem: realloc: %s\n", strerror(errno)));
      return 0;
    }

    d->der = new;
    *max_len = new_len;
  }

  memcpy(d->der + d->der_len, dec, olen);
  d->der_len += olen;

  return 1;
}

static int add_object(PEM *p) {
  if (p->num_obj >= p->max_obj) {
    unsigned int max;
    DER *new;

    max = p->max_obj + OBJ_INCREMENT;

    new = realloc(p->obj, sizeof(*p->obj) * max);
    if (NULL == new) return 0;

    p->obj = new;
    p->max_obj = max;
  }
  return 1;
}

PEM *pem_load(const char *fn, int type_mask) {
  /* 2x larger than necesssary */
  unsigned int state, cur, i;
  char buf[128];
  size_t der_max_len = 0;
  uint8_t got;
  PEM *p;
  FILE *f;

  p = calloc(1, sizeof(*p));
  if (NULL == p) {
    goto out;
  }

  f = fopen(fn, "r");
  if (NULL == f) {
    dprintf(("%s: fopen: %s\n", fn, strerror(errno)));
    goto out_free;
  }

  for (state = cur = 0; fgets(buf, sizeof(buf), f);) {
    char *lf;

    /* Trim trailing whitespaces*/
    lf = strchr(buf, '\n');
    while (lf > buf && isspace(*(unsigned char *) lf)) {
      *lf-- = '\0';
    }
    lf++;

    switch (state) {
      case 0: /* begin marker */
        if (check_begin_marker(buf, &got)) {
          if (got & type_mask) {
            if (!add_object(p)) goto out_close;
            cur = p->num_obj++;
            p->obj[cur].der_type = got;
            p->obj[cur].der_len = 0;
            p->obj[cur].der = NULL;
            der_max_len = 0;
            state = 1;
          }
          /* else ignore everything else */
        }
        break;
      case 1: /* content*/
        if (check_end_marker(buf, p->obj[cur].der_type)) {
          p->tot_len += p->obj[cur].der_len;
          state = 0;
#if 0
          dprintf(("%s: Loaded %d byte PEM\n", fn, p->obj[cur].der_len));
          ber_dump(p->obj[cur].der, p->obj[cur].der_len);
#endif
          break;
        }

        if (!add_line(&p->obj[cur], &der_max_len, (uint8_t *) buf, lf - buf)) {
          dprintf(("%s: Corrupted key or cert\n", fn));
          goto out_close;
        }

        break;
      default:
        break;
    }
  }

  if (state != 0) {
    dprintf(("%s: no end marker\n", fn));
    goto out_close;
  }
  if (p->num_obj < 1) {
    dprintf(("%s: no objects in file\n", fn));
    goto out_close;
  }

  fclose(f);
  goto out;

out_close:
  for (i = 0; i < p->num_obj; i++) {
    free(p->obj[i].der);
  }
  free(p->obj);
  fclose(f);
out_free:
  free(p);
  p = NULL;
out:
  return p;
}

void pem_free(PEM *p) {
  if (p) {
    unsigned int i;
    for (i = 0; i < p->num_obj; i++) {
      free(p->obj[i].der);
    }
    free(p->obj);
    free(p);
  }
}
