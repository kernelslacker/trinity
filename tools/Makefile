ifeq ($(CC),"")
CC := gcc
endif
CC := $(CROSS_COMPILE)$(CC)
LD := $(CROSS_COMPILE)$(LD)

CFLAGS ?= -g -O2 -D_FORTIFY_SOURCE=2
CFLAGS += -Wall -W -I. -Iinclude/ -Wimplicit -D_GNU_SOURCE -D__linux__
ifneq ($(SYSROOT),)
CFLAGS += --sysroot=$(SYSROOT)
endif
#CFLAGS += $(shell if $(CC) -m32 -S -o /dev/null -xc /dev/null >/dev/null 2>&1; then echo "-m32"; fi)
CFLAGS += -Wdeclaration-after-statement
CFLAGS += -Wformat=2
CFLAGS += -Winit-self
CFLAGS += -Wnested-externs
CFLAGS += -Wpacked
CFLAGS += -Wshadow
CFLAGS += -Wswitch-enum
CFLAGS += -Wundef
CFLAGS += -Wwrite-strings
CFLAGS += -Wno-format-nonliteral
CFLAGS += -Wstrict-prototypes -Wmissing-prototypes

# gcc only.
ifneq ($(shell $(CC) -v 2>&1 | grep -c "clang"), 1)
CFLAGS += -Wlogical-op
CFLAGS += -Wstrict-aliasing=3
endif

V	= @
Q	= $(V:1=)
QUIET_CC = $(Q:@=@echo    '  CC	'$@;)

all: analyze-sockets

analyze-sockets:
	$(QUIET_CC)$(CC) $(CFLAGS) analyze-sockets.c -o analyze-sockets

clean:
	@rm -f core.*
	@rm -f analyze-sockets
