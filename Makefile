# Copyright (c) 2015 Cesanta Software Limited
# All rights reserved

SOURCES = src/b64.c src/ber.c src/bigint.c src/ctx.c src/hexdump.c \
          src/md5.c src/sha1.c src/sha256.c src/hmac.c \
          src/meth.c src/pem.c src/prf.c src/random.c \
          src/rc4.c src/rsa.c src/ssl.c src/tls.c src/tls_cl.c \
          src/tls_recv.c src/tls_sv.c src/x509.c src/x509_verify.c
HEADERS = src/ktypes.h src/kexterns.h src/crypto.h src/bigint_impl.h \
          src/bigint.h src/tlsproto.h src/tls.h src/ber.h src/pem.h src/x509.h
TEST_SOURCES = test/sv-test.c test/cl-test.c
CFLAGS := -O2 -W -Wall -g -Wno-unused-parameter $(CFLAGS_EXTRA)

CLANG_FORMAT := clang-format

ifneq ("$(wildcard /usr/local/bin/clang-3.6)","")
	CLANG:=/usr/local/bin/clang-3.6
	CLANG_FORMAT:=/usr/local/bin/clang-format-3.6
endif

.PHONY: all clean format tests openssl-tests krypton-tests

all: tests

krypton.c: $(HEADERS) $(SOURCES) Makefile
	@echo "AMALGAMATING\tkrypton.c"
	@cp krypton.h $@; \
	 for f in $(HEADERS) $(SOURCES); do \
		 echo >> $@; \
	   echo "/* === `basename $$f` === */" >> $@; \
		 sed -E "/#include .*(ssl.h|`echo $(HEADERS) | sed -e 's,src/,,g' -e 's, ,|,g'`)/d" $$f >> $@; \
	 done

tests: openssl-tests krypton-tests

krypton-tests: sv-test-krypton cl-test-krypton

openssl-tests: sv-test-openssl cl-test-openssl

sv-test-openssl: test/sv-test.c
	$(CC) $(CFLAGS) -o sv-test-openssl test/sv-test.c -lssl -lcrypto

cl-test-openssl: test/cl-test.c
	$(CC) $(CFLAGS) -o cl-test-openssl test/cl-test.c -lssl -lcrypto

%-test-krypton: CFLAGS += -DUSE_KRYPTON=1 -I.

sv-test-krypton: test/sv-test.c krypton.c
	$(CC) $(CFLAGS) -o sv-test-krypton test/sv-test.c krypton.c

cl-test-krypton: test/cl-test.c krypton.c
	$(CC) $(CFLAGS) -o cl-test-krypton test/cl-test.c krypton.c

win-test: krypton.c
ifndef VC6_DIR
	$(error Please set VC6_DIR)
endif
	Include=$(VC6_DIR)/include Lib=$(VC6_DIR)/lib \
	wine $(VC6_DIR)/bin/cl \
		krypton.c test/win-test.c

format: krypton.c
	@$(CLANG_FORMAT) -i src/*.[ch] test/*.[ch]

clean:
	rm -rf *-openssl *-krypton *.o *.gc* *.dSYM *.exe *.obj *.pdb
