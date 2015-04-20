# Copyright (c) 2015 Cesanta Software Limited
# All rights reserved

SOURCES = src/b64.c src/ber.c src/bigint.c src/ctx.c src/hexdump.c src/hmac.c \
					src/md5.c src/meth.c src/pem.c src/prf.c src/random.c src/rc4.c \
					src/rsa.c src/sha1.c src/sha256.c src/ssl.c src/tls.c src/tls_cl.c \
					src/tls_recv.c src/tls_sv.c src/x509.c src/x509_verify.c src/aes.c \
					src/aes-gcm.c src/suite.c
HEADERS = src/ktypes.h src/bigint_impl.h src/bigint.h src/tlsproto.h \
					src/crypto.h src/ssl.h src/tls.h src/ber.h src/pem.h src/x509.h
TEST_SOURCES = test/sv-test.c test/cl-test.c
CFLAGS := -O2 -W -Wall -Wno-unused-parameter $(CLFAGS_EXTRA) -g -fno-inline

.PHONY: all clean tests crypto-tests openssl-tests krypton-tests

OPENSSL_FLAGS := \
	-I/home/scara/libre/usr/local/include \
	-L/home/scara/libre/usr/local/lib \
	-lssl -lcrypto -ldl

all: tests

krypton.c: $(HEADERS) $(SOURCES) openssl/ssl.h Makefile
	cat openssl/ssl.h $(HEADERS) $(SOURCES) | sed -E "/#include .*(ssl.h|`echo $(HEADERS) | sed -e 's,src/,,g' -e 's, ,|,g'`)/d" > $@

tests: openssl-tests krypton-tests crypto-tests

crypto-tests: test-aes-gcm

test-aes-gcm: CFLAGS += -I./src/ -DKRYPTON_DEBUG=1 -DNOT_AMALGAMATED
test-aes-gcm: test/test-aes-gcm.c krypton.c
	$(CC) $(CFLAGS) -o $@ $< krypton.c

krypton-tests: CFLAGS += -DUSE_KRYPTON=1 -I.
krypton-tests: sv-test-krypton cl-test-krypton dsv-test-krypton dcl-test-krypton

openssl-tests: sv-test-openssl cl-test-openssl dsv-test-openssl dcl-test-openssl

sv-test-openssl: test/sv-test.c
	$(CC) $(CFLAGS) -o $@ test/sv-test.c $(OPENSSL_FLAGS)

cl-test-openssl: test/cl-test.c
	$(CC) $(CFLAGS) -o $@ test/cl-test.c $(OPENSSL_FLAGS)

sv-test-krypton: test/sv-test.c krypton.c
	$(CC) $(CFLAGS) -o $@ test/sv-test.c krypton.c

cl-test-krypton: test/cl-test.c krypton.c
	$(CC) $(CFLAGS) -o $@ test/cl-test.c krypton.c

dsv-test-openssl: test/dsv-test.c
	$(CC) $(CFLAGS) -o $@ test/dsv-test.c $(OPENSSL_FLAGS)

dcl-test-openssl: test/dcl-test.c
	$(CC) $(CFLAGS) -o $@ test/dcl-test.c $(OPENSSL_FLAGS)

dsv-test-krypton: CFLAGS += -DKRYPTON_DTLS=1
dsv-test-krypton: test/dsv-test.c krypton.c
	$(CC) $(CFLAGS) -o $@ test/dsv-test.c krypton.c

dcl-test-krypton: CFLAGS += -DKRYPTON_DTLS=1
dcl-test-krypton: test/dcl-test.c krypton.c
	$(CC) $(CFLAGS) -o $@ test/dcl-test.c krypton.c

vc6: krypton.c
	wine cl -c $(SOURCES) -Isrc -DNOT_AMALGAMATED

format:
	clang-format -i \
	-style '{BasedOnStyle: Google, AllowShortIfStatementsOnASingleLine: false, AllowShortLoopsOnASingleLine: false, AllowShortFunctionsOnASingleLine: None}' \
		$$(grep -lrsi 'copyright.*cesanta' src test)

clean:
	rm -rf *-openssl *-krypton *.o *.gc* *.dSYM *.exe *.obj *.pdb
