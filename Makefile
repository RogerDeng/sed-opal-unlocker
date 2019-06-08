CC := gcc
CFLAGS ?= -Os -Wall -Wextra

override LIBS :=
ifeq ($(STATIC),1)
override CFLAGS += -static
endif
ENCRYPTED_PASSWORDS ?= 1
ifeq ($(ENCRYPTED_PASSWORDS),1)
override CFLAGS += -DENCRYPTED_PASSWORDS=1
override LIBS   += -largon2
ifeq ($(STATIC),1)
override LIBS   += -lpthread
endif
endif

SRCS := $(wildcard *.c)
OBJS := $(SRCS:%.c=%.o)


all: sed-opal-unlocker

%.o: %.c
	$(CC) $(CFLAGS) -MP -MMD -MT $@ -MF $(@:%.o=%.d) -c $< -o $@

sed-opal-unlocker: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

clean:
	rm -f *.[od] sed-opal-unlocker

# generic deps
-include $(SRCS:%.c=%.d)

.PHONY: all clean
