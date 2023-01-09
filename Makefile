VERSION="2023.01"

INSTALL_PREFIX ?= $(DESTDIR)
INSTALL_PREFIX ?= $(HOME)
NR_CPUS := $(shell grep -c ^processor /proc/cpuinfo)

ifeq ($(CC),"")
CC := gcc
endif
CC := $(CROSS_COMPILE)$(CC)
LD := $(CROSS_COMPILE)$(LD)

CFLAGS ?= -g -O2 -D_FORTIFY_SOURCE=2
CFLAGS += -Wall -Wextra -I. -Iinclude/ -include config.h -Wimplicit -D_GNU_SOURCE -D__linux__

CCSTD := $(shell if $(CC) -std=gnu11 -S -o /dev/null -xc /dev/null >/dev/null 2>&1; then echo "-std=gnu11"; else echo "-std=gnu99"; fi)
CFLAGS += $(CCSTD)

ifneq ($(SYSROOT),)
CFLAGS += --sysroot=$(SYSROOT)
endif
#CFLAGS += $(shell if $(CC) -m32 -S -o /dev/null -xc /dev/null >/dev/null 2>&1; then echo "-m32"; fi)
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
CFLAGS += -fsigned-char
# BPF spew.
CFLAGS += -Wno-missing-field-initializers

# needed for show_backtrace() to work correctly.
LDFLAGS += -rdynamic

# glibc versions before 2.17 for clock_gettime
LDLIBS += -lrt

# gcc only.
ifneq ($(shell $(CC) -v 2>&1 | grep -c "clang"), 1)
CFLAGS += -Wlogical-op
CFLAGS += -Wstrict-aliasing=3
endif

# Sometimes useful for debugging. more useful with clang than gcc.
#CFLAGS += -fsanitize=address

V	= @
Q	= $(V:1=)
QUIET_CC = $(Q:@=@echo    '  CC	'$@;)


all: trinity

test:
	@if [ ! -f config.h ]; then  echo "[1;31mRun configure.sh first.[0m" ; exit; fi


MACHINE		:= $(shell $(CC) -dumpmachine)
SYSCALLS_ARCH	:= $(shell case "$(MACHINE)" in \
		   (sh*) echo syscalls/sh/*.c ;; \
		   (ia64*) echo syscalls/ia64/*.c ;; \
		   (ppc*|powerpc*) echo syscalls/ppc/*.c ;; \
		   (sparc*) echo syscalls/sparc/*.c ;; \
		   (x86_64*) echo syscalls/x86/*.c \
				  syscalls/x86/i386/*.c \
				  syscalls/x86/x86_64/*.c;; \
		   (i?86*) echo syscalls/x86/*.c \
				syscalls/x86/i386/*.c;; \
		   (s390x*) echo syscalls/s390x/*.c ;; \
		   esac)

VERSION_H	:= include/version.h

HEADERS		:= $(patsubst %.h,%.h,$(wildcard *.h)) $(patsubst %.h,%.h,$(wildcard syscalls/*.h)) $(patsubst %.h,%.h,$(wildcard ioctls/*.h))

SRCS		:= $(wildcard *.c) \
		   $(wildcard fds/*.c) \
		   $(wildcard ioctls/*.c) \
		   $(wildcard mm/*.c) \
		   $(wildcard net/*.c) \
		   $(wildcard rand/*.c) \
		   $(wildcard syscalls/*.c) \
		   $(SYSCALLS_ARCH)

OBJS		:= $(sort $(patsubst %.c,%.o,$(wildcard *.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard fds/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard ioctls/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard mm/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard net/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard rand/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(wildcard syscalls/*.c))) \
		   $(sort $(patsubst %.c,%.o,$(SYSCALLS_ARCH)))

DEPDIR= .deps

-include $(SRCS:%.c=$(DEPDIR)/%.d)

$(VERSION_H): scripts/gen-versionh.sh Makefile $(wildcard .git)
	@scripts/gen-versionh.sh

trinity: test $(OBJS) $(HEADERS)
	$(QUIET_CC)$(CC) $(CFLAGS) $(LDFLAGS) -o trinity $(OBJS) $(LDLIBS)
	@mkdir -p tmp

df = $(DEPDIR)/$(*D)/$(*F)

%.o : %.c | $(VERSION_H)
	$(QUIET_CC)$(CC) $(CFLAGS) -o $@ -c $<
	@mkdir -p $(DEPDIR)/$(*D)
	@$(CC) -MM $(CFLAGS) $*.c > $(df).d
	@mv -f $(df).d $(df).d.tmp
	@sed -e 's|.*:|$*.o:|' <$(df).d.tmp > $(df).d
	@sed -e 's/.*://' -e 's/\\$$//' < $(df).d.tmp | fmt -1 | \
	  sed -e 's/^ *//' -e 's/$$/:/' >> $(df).d
	@rm -f $(df).d.tmp

clean:
	@rm -f $(OBJS)
	@rm -f core.*
	@rm -f trinity
	@rm -f tags
	@rm -rf $(DEPDIR)/*
	@rm -rf trinity-coverity.tar.xz cov-int
	@rm -f $(VERSION_H)

tag:
	@git tag -a v$(VERSION) -m "$(VERSION) release."

tarball:
	@git archive --format=tar --prefix=trinity-$(VERSION)/ HEAD > trinity-$(VERSION).tar
	@xz -9 trinity-$(VERSION).tar

install: trinity
	install -d -m 755 $(INSTALL_PREFIX)/bin
	install trinity $(INSTALL_PREFIX)/bin

tags:	$(SRCS)
	@ctags -R --exclude=tmp

scan:
	@scan-build --use-analyzer=/usr/bin/clang make -j $(NR_CPUS)

coverity:
	@rm -rf cov-int trinity-coverity.tar.xz
	@cov-build --dir cov-int make -j $(NR_CPUS)
	@tar cJvf trinity-coverity.tar.xz cov-int

cppcheck:
	@scripts/cppcheck.sh
