# Makefile — WhatsApp Backup (C / GCC)
CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c11
LDFLAGS = -lpthread

all: wa_backup_server wa_backup_client

wa_backup_server: wa_backup_server.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

wa_backup_client: wa_backup_client.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f wa_backup_server wa_backup_client

.PHONY: all clean