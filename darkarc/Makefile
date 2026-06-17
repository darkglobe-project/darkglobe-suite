# darkarc/Makefile
# Builds the two ARC milters against the shared libdark sources.
#
# libdark is compiled into each binary directly (same model as darkchain/).
# -ffunction-sections + --gc-sections let the linker drop any libdark
# function a given milter does not reference, so unused shared code is not
# carried into the final binary.

CC      = gcc
CFLAGS  = -Wall -O2 -I../libdark -ffunction-sections -fdata-sections
LDFLAGS = -Wl,--gc-sections
LIBS    = -lmilter -lssl -lcrypto -lresolv -lpthread
LIBDARK = ../libdark

# Shared library sources (libdark, MIT)
LIBDARK_SRCS = $(LIBDARK)/dark_string.c $(LIBDARK)/dark_canon.c \
               $(LIBDARK)/dark_crypto.c $(LIBDARK)/dark_util.c

# DarkARC  = ARC verification milter
# DarkARCs = ARC signing milter
all: DarkARC DarkARCs

DarkARC: DarkARC.c $(LIBDARK_SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

DarkARCs: DarkARCs.c $(LIBDARK_SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

clean:
	rm -f DarkARC DarkARCs

.PHONY: all clean
