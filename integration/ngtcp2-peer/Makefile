# A raw-stream QUIC server over ngtcp2's C API and its OpenSSL backend.
#
# The pinned ngtcp2 checkout is built by CI (or locally) with:
#   cmake -B build -DENABLE_OPENSSL=ON -DENABLE_GNUTLS=OFF -DBUILD_TESTING=OFF
#   cmake --build build -j $(nproc) --target osslclient
# Point NGTCP2 at that checkout; the shared libraries live under its build tree.
#
#   make NGTCP2=/path/to/ngtcp2
#   ./peer 4433 key.pem cert.pem 1

NGTCP2 ?= ../../ngtcp2
BUILD := $(NGTCP2)/build
ROOT := $(abspath $(NGTCP2))
BUILD_ABS := $(abspath $(BUILD))

CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -std=c11 -g

INCLUDES := -I$(ROOT)/lib/includes \
            -I$(ROOT)/crypto/includes \
            -I$(ROOT)/lib \
            -I$(BUILD_ABS) \
            -I$(BUILD_ABS)/lib \
            -I$(BUILD_ABS)/lib/includes

LIBS := -L$(BUILD_ABS)/lib -L$(BUILD_ABS)/crypto/ossl \
        -lngtcp2_crypto_ossl -lngtcp2 -lssl -lcrypto \
        -Wl,-rpath,$(BUILD_ABS)/lib:$(BUILD_ABS)/crypto/ossl

.PHONY: all clean
all: peer

peer: server.c
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(LIBS)

clean:
	rm -f peer
