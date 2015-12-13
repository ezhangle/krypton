# Copyright (c) 2015 Cesanta Software Limited
# All rights reserved

.PHONY: all tests run-tests clean

CFLAGS := -O0 -W -Wall -Werror -g -I.. -I../.. \
          -DKRYPTON_DEBUG -DDEBUG_VERIFY -DNS_MODULE_LINES \
          $(CFLAGS_EXTRA)

ifdef ASAN
CC = clang-3.6
CFLAGS += -fsanitize=address -fcolor-diagnostics
endif

all: tests

tests: unit-test sv-test-openssl cl-test-openssl sv-test-krypton cl-test-krypton

unit-test: unit-test.c ../krypton.c ../../common/test_util.c
	$(CC) $(CFLAGS) -DNS_INTERNAL= -I../src -o unit-test $^

sv-test-openssl: sv-test.c
	$(CC) $(CFLAGS) -o sv-test-openssl $^ -lssl -lcrypto

cl-test-openssl: cl-test.c
	$(CC) $(CFLAGS) -o cl-test-openssl $^ -lssl -lcrypto

%-test-krypton: CFLAGS += -DUSE_KRYPTON=1 -I.

sv-test-krypton: sv-test.c ../krypton.c
	$(CC) $(CFLAGS) -o sv-test-krypton $^

cl-test-krypton: cl-test.c ../krypton.c
	$(CC) $(CFLAGS) -o cl-test-krypton $^

win-test: ../krypton.c
ifndef VC6_DIR
	$(error Please set VC6_DIR)
endif
	Include=$(VC6_DIR)/include Lib=$(VC6_DIR)/lib \
	wine $(VC6_DIR)/bin/cl win-test.c ../krypton.c

run-tests: tests
	./unit-test
	./sv-test-openssl & ./cl-test-krypton
	./sv-test-krypton & ./cl-test-openssl
	./sv-test-krypton & ./cl-test-krypton

clean:
	rm -f cl-test-* sv-test-* unit-test
