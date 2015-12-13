# Copyright (c) 2015 Cesanta Software Limited
# All rights reserved

SOURCES = src/b64.c src/ber.c src/bigint.c src/ctx.c src/hexdump.c \
          src/md5.c src/sha1.c src/sha256.c src/hmac.c \
          src/meth.c src/pem.c src/prf.c src/random.c \
          src/aes.c src/rc4.c src/cipher.c src/rsa.c src/ssl.c \
          src/tls.c src/tls_cl.c src/tls_recv.c src/tls_sv.c \
          src/x509.c src/x509_verify.c
HEADERS = src/ktypes.h src/tlsproto.h src/kexterns.h src/crypto.h src/bigint_impl.h \
          src/bigint.h src/tls.h src/ber.h src/pem.h src/x509.h
TEST_SOURCES = test/sv-test.c test/cl-test.c

CLANG_FORMAT := clang-format

ifneq ("$(wildcard /usr/local/bin/clang-3.6)","")
	CLANG:=/usr/local/bin/clang-3.6
	CLANG_FORMAT:=/usr/local/bin/clang-format-3.6
endif

.PHONY: all clean format tests openssl-tests krypton-tests

all: tests

krypton.c: $(HEADERS) $(SOURCES) Makefile
	@echo "AMALGAMATING\tkrypton.c"
	@../tools/amalgam --srcdir src krypton.h $(HEADERS) $(SOURCES) > $@

format: krypton.c
	@$(CLANG_FORMAT) -i src/*.[ch] test/*.[ch]

clean:
	rm -rf *-openssl *-krypton *.o *.gc* *.dSYM *.exe *.obj *.pdb
