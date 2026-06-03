# darkchain/sign/Makefile
CC = gcc
CFLAGS = -Wall -Wextra -I.. -I../../libdark
LIBS = -lmilter -lssl -lcrypto -lresolv -lpthread
LIBDARK = ../../libdark

SRCS = DarkChains.c ../dc_shared.c \
       $(LIBDARK)/dark_string.c $(LIBDARK)/dark_canon.c \
       $(LIBDARK)/dark_crypto.c $(LIBDARK)/dark_util.c

DarkChains: $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f DarkChains
