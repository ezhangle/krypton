# Copyright (c) 2015 Cesanta Software Limited
# All rights reserved

SOURCES = src/b64.c src/ber.c src/bigint.c src/ctx.c src/hexdump.c src/hmac.c \
					src/md5.c src/meth.c src/pem.c src/prf.c src/random.c src/rc4.c \
					src/rsa.c src/sha1.c src/sha256.c src/ssl.c src/tls.c src/tls_cl.c \
					src/tls_recv.c src/tls_sv.c src/x509.c src/x509_verify.c
HEADERS = src/ktypes.h src/crypto.h src/tlsproto.h src/tls.h src/ber.h \
					src/pem.h src/x509.h src/bigint_impl.h src/bigint.h
CFLAGS := -O2 -W -Wall -I. $(CLFAGS_EXTRA)

.PHONY: all clean test test-ossl test-krypton

all: sv-krypton

krypton.c: $(HEADERS) $(SOURCES) Makefile
	cat openssl/ssl.h $(HEADERS) $(SOURCES) | sed -E "/#include .*(ssl.h|`echo $(HEADERS) | sed -e 's,src/,,g' -e 's, ,|,g'`)/d" > $@

sv-ossl: test/sv-test.c
	$(CC) $(CFLAGS) -o $@ $< -lssl -lcrypto

cl-ossl: test/cl-test.c
	$(CC) $(CFLAGS) -o $@ $< -lssl -lcrypto

sv-krypton: test/sv-test.c krypton.c
	$(CC) $(CFLAGS) -o $@ $< krypton.c

cl-krypton: test/cl-test.c krypton.c
	$(CC) $(CFLAGS) -o $@ $< krypton.c

clean:
	rm -rf *-ossl *-krypton *.o *.gc* *.dSYM *.exe *.obj *.pdb
