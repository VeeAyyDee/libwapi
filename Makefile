# SPDX-License-Identifier: MPL-2.0
CC ?= cc
AR ?= ar
CPPFLAGS += -Iinclude -Isrc
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Werror -fPIC -MMD -MP
SOURCES := $(wildcard src/*.c)
OBJECTS := $(patsubst src/%.c,build/%.o,$(SOURCES))
.PHONY: all clean test audit
all: build/libwapi.a build/libwapi_crypto.so
build:
	mkdir -p $@
build/%.o: src/%.c | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@
build/libwapi.a: $(OBJECTS)
	$(AR) rcs $@ $^
build/libwapi_crypto.so: build/crypto.o build/constants.o
	$(CC) -shared $^ -o $@
build/test_crypto: tests/test_crypto.c build/crypto.o build/constants.o
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@
test: build/test_crypto build/test_protocol audit
	./build/test_crypto
	./build/test_protocol
clean:
	rm -rf build
build/test_protocol: tests/test_protocol.c build/libwapi.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $^ -o $@

audit: build/libwapi.a
	python3 tests/audit_exports.py $<

-include $(OBJECTS:.o=.d)
