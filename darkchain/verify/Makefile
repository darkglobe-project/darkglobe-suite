# darkchain/verify/Makefile
CC = gcc
CFLAGS = -Wall -Wextra -I.. -I../../libdark
LIBS = -lmilter -lssl -lcrypto -lresolv -lpthread
LIBDARK = ../../libdark

SRCS = DarkChain.c ../dc_shared.c \
       $(LIBDARK)/dark_string.c $(LIBDARK)/dark_canon.c \
       $(LIBDARK)/dark_crypto.c $(LIBDARK)/dark_util.c

DarkChain: $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f DarkChain
