CC = gcc
CFLAGS = -Wall -Wextra -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS = -lssl -lcrypto

TARGETS = clipboard_daemon clipboard_client

.PHONY: all clean

all: $(TARGETS)

clipboard_daemon: clipboard_daemon.c clipboard_common.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clipboard_client: clipboard_client.c clipboard_common.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS) *.o
