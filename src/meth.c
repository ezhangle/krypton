/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 */

#include "../openssl/ssl.h"
#include "ktypes.h"

const SSL_METHOD meth = {0, 0};
const SSL_METHOD sv_meth = {0, 1};
const SSL_METHOD cl_meth = {1, 0};

const SSL_METHOD *TLSv1_2_method(void) {
  return &meth;
}
const SSL_METHOD *TLSv1_2_server_method(void) {
  return &sv_meth;
}
const SSL_METHOD *TLSv1_2_client_method(void) {
  return &cl_meth;
}
const SSL_METHOD *SSLv23_method(void) {
  return &meth;
}
const SSL_METHOD *SSLv23_server_method(void) {
  return &sv_meth;
}
const SSL_METHOD *SSLv23_client_method(void) {
  return &cl_meth;
}
