CC = /usr/bin/cc
CFLAGS += -Wall -Wextra -march=native -mtune=native -O3 -fomit-frame-pointer
NISTFLAGS += -march=native -mtune=native -O3 -fomit-frame-pointer -fPIC
OPENSSL_LIBS = $(shell pkg-config --libs openssl)
OPENSSL_CFLAGS = $(shell pkg-config --cflags openssl)

BINARY_DIR = bin
BIN_MYTEST_OPENSSL = $(BINARY_DIR)/mytest_openssl

all: mytest_openssl 

bin:
	mkdir -p $(BINARY_DIR)

mytest_openssl: bin
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) mytest/cpucycles.c mytest/speed.c mytest_openssl.c -o $(BIN_MYTEST_OPENSSL) $(OPENSSL_LIBS) 

.PHONY: clean

clean:
	rm $(BIN_MYTEST_OPENSSL)
