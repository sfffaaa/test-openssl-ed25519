CC = /usr/bin/cc
CFLAGS += -Wall -Wextra -march=native -mtune=native -O3 -fomit-frame-pointer
NISTFLAGS += -march=native -mtune=native -O3 -fomit-frame-pointer -fPIC
OPENSSL_LIBS = $(shell pkg-config --libs openssl)
OPENSSL_CFLAGS = $(shell pkg-config --cflags openssl)

all: mytest_openssl

mytest_openssl:
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) $< mytest/cpucycles.c mytest/speed.c mytest_openssl.c -o $@ $(OPENSSL_LIBS) 

.PHONY: clean

clean:
	rm -f mytest_openssl
