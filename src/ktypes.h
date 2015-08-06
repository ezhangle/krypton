/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#ifndef _KTYPES_H
#define _KTYPES_H

#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE
#undef WIN32_LEAN_AND_MEAN  // Let windows.h always include winsock2.h

#ifndef NOT_AMALGAMATED
#define NS_INTERNAL static
#else
#define NS_INTERNAL
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#ifdef _MSC_VER
#include <winsock2.h>
#include <windows.h>
#define __unused
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;
typedef unsigned long uintptr_t;
typedef long ssize_t;
#define __func__ ""
#define __packed
#ifndef alloca
#define alloca(x) _alloca(x)
#endif
#ifndef EWOULDBLOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif
#define SOCKET_ERRNO WSAGetLastError()
#pragma comment(lib, "ws2_32.lib")  // Linking with winsock library
#else
#include <sys/socket.h>
#include <stdint.h>
#define __packed __attribute__((packed))
#define SOCKET_ERRNO errno
#endif

#ifndef BYTE_ORDER
#define LITTLE_ENDIAN 0x41424344UL
#define BIG_ENDIAN 0x44434241UL
#define PDP_ENDIAN 0x42414443UL
#define BYTE_ORDER ('ABCD')
#endif

#ifndef htobe16
#define htobe16 htons
#endif

#ifndef htobe32
#define htobe32 htonl
#endif

#ifndef be16toh
#define be16toh ntohs
#endif

#ifndef be32toh
#define be32toh ntohl
#endif

#ifndef htobe64
#if BYTE_ORDER == LITTLE_ENDIAN
#define htobe64(x) \
  (((uint64_t) htonl((x) &0xffffffff) << 32) | htonl((x) >> 32))
#define xxhtobe64(x) __builtin_bswap64(x)
#else
#define htobe64
#endif
#endif

/* #define KRYPTON_DEBUG 1 */
#if defined(KRYPTON_DEBUG)
#define dprintf(x) printf x
#else
#define dprintf(x)
#endif

/* #define KRYPTON_DEBUG_NONBLOCKING 1 */

struct ro_vec {
  const uint8_t *ptr;
  size_t len;
};
struct vec {
  uint8_t *ptr;
  size_t len;
};

typedef struct pem_st PEM;
typedef struct der_st DER;
typedef struct X509_st X509;
typedef struct _RSA_CTX RSA_CTX;

struct x509_store_ctx_st {
  int dummy;
};

struct ssl_method_st {
  uint8_t sv_undefined : 1;
  uint8_t cl_undefined : 1;
};

struct ssl_ctx_st {
  X509 *ca_store;
  PEM *pem_cert;
  RSA_CTX *rsa_privkey;
  uint8_t mode;
  uint8_t vrfy_mode;
  struct ssl_method_st meth;
};

#define STATE_INITIAL 0
#define STATE_CL_HELLO_SENT 1
#define STATE_CL_HELLO_WAIT 2
#define STATE_CL_HELLO_RCVD 3
#define STATE_SV_HELLO_SENT 4
#define STATE_SV_HELLO_RCVD 5
#define STATE_SV_CERT_RCVD 6
#define STATE_SV_DONE_RCVD 7
#define STATE_CLIENT_FINISHED 8
#define STATE_ESTABLISHED 9
#define STATE_CLOSING 10

struct ssl_st {
  struct ssl_ctx_st *ctx;

  struct tls_security *cur;
  struct tls_security *nxt;

/* rcv buffer: can be 16bit lens? */
#define RX_INITIAL_BUF 1024
  uint8_t *rx_buf;
  uint32_t rx_len;
  uint32_t rx_max_len;

  uint8_t *tx_buf;
  uint32_t tx_len;
  uint32_t tx_max_len;

  int fd;
  int err;

  /* for handling appdata recvs */
  unsigned int copied;

  uint8_t state;

  uint8_t vrfy_result;

  uint8_t mode_defined : 1;
  uint8_t is_server : 1;
  uint8_t got_appdata : 1;
  uint8_t tx_enc : 1;
  uint8_t rx_enc : 1;
  uint8_t close_notify : 1;
  uint8_t fatal : 1;
  uint8_t write_pending : 1;
};

NS_INTERNAL void ssl_err(struct ssl_st *ssl, int err);

#if KRYPTON_DEBUG
NS_INTERNAL void hex_dumpf(FILE *f, const void *buf, size_t len, size_t llen);
NS_INTERNAL void hex_dump(const void *ptr, size_t len, size_t llen);
#endif

typedef struct _bigint bigint; /**< An alias for _bigint */

#include "crypto.h"
#include "bigint.h"
#include "bigint_impl.h"
#include "pem.h"
#include "ber.h"
#include "../openssl/ssl.h"
#include "tlsproto.h"
#include "tls.h"
#include "ber.h"
#include "x509.h"

#endif /* _KTYPES_H */
