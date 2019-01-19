CC := gcc
CFLAGS := -Os -Wall -Wextra
ifeq ($(STATIC),1)
CFLAGS += -static
endif


all: sed-opal-unlocker

sed-opal-unlocker: sed-opal-unlocker.c
	$(CC) $(CFLAGS) $< -o $@

.PHONY: all
