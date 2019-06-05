CC := gcc
CFLAGS ?= -Os -Wall -Wextra
ifeq ($(STATIC),1)
CFLAGS += -static
endif
ENCRYPTED_PASSWORDS ?= 1
ifeq ($(ENCRYPTED_PASSWORDS),1)
CFLAGS += -DENCRYPTED_PASSWORDS=1 -largon2
endif


all: sed-opal-unlocker

sed-opal-unlocker: sed-opal-unlocker.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f sed-opal-unlocker

.PHONY: all clean
