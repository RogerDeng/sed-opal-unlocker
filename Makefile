
all: sed-opal-unlocker

sed-opal-unlocker: sed-opal-unlocker.c
	gcc $< -Wall -Wextra -Os -o $@

.PHONY: all
