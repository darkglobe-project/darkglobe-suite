# srs-milter/Makefile
CC = gcc
CFLAGS = -Wall -Wextra
LIBS = -lmilter -lssl -lcrypto -lpthread -ldb-5.3

DarkSRS: DarkSRS.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f DarkSRS
