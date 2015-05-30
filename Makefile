VERSION="1.6pre"

INSTALL_PREFIX ?= $(DESTDIR)
INSTALL_PREFIX ?= $(HOME)
NR_CPUS := $(shell grep ^processor /proc/cpuinfo | /usr/bin/wc -l)

ifeq ($(CC),"")
CC := gcc
endif
CC := $(CROSS_COMPILE)$(CC)
LD := $(CROSS_COMPILE)$(LD)

CFLAGS += -Wall -W -g -O2 -I. -Iinclude/ -Wimplicit -D_FORTIFY_SOURCE=2 -D_GNU_SOURCE -D__linux__

# Only enabled during development, and on gcc 4.9+
CPP_MAJOR := $(shell $(CPP) -dumpversion 2>&1 | cut -d'.' -f1)
CPP_MINOR := $(shell $(CPP) -dumpversion 2>&1 | cut -d'.' -f2)
DEVEL	:= $(shell grep VERSION Makefile | head -n1 | grep pre | wc -l)
CFLAGS	+= $(shell if [ $(CPP_MAJOR) -eq 4 -a $(CPP_MINOR) -ge 9 -a $(DEVEL) -eq 1 ] ; then echo "-Werror"; else echo ""; fi)

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

# needed for show_backtrace() to work correctly.
LDFLAGS += -rdynamic

# gcc only.
ifneq ($(shell $(CC) -v 2>&1 | grep -c "clang"), 1)
CFLAGS += -Wlogical-op
CFLAGS += -Wstrict-aliasing=3
CFLAGS += $(shell if [ $(DEVEL) -eq 0 ]; then echo "-Wno-maybe-uninitialized"; else echo ""; fi)
endif

# Sometimes useful for debugging. more useful with clang than gcc.
#CFLAGS += -fsanitize=address

V	= @
Q	= $(V:1=)
QUIET_CC = $(Q:@=@echo    '  CC	'$@;)


all: trinity

version:
	@scripts/gen-versionh.sh

test:
	@if [ ! -f config.h ]; then  echo "[1;31mRun configure.sh first.[0m" ; exit; fi


MACHINE		= $(shell $(CC) -dumpmachine)
SYSCALLS_ARCH	= $(shell case "$(MACHINE)" in \
		  (sh*) echo syscalls/sh/*.c ;; \
		  (ia64*) echo syscalls/ia64/*.c ;; \
		  (ppc*|powerpc*) echo syscalls/ppc/*.c ;; \
		  (sparc*) echo syscalls/sparc/*.c ;; \
		  esac)

HEADERS		= $(patsubst %.h,%.h,$(wildcard *.h)) $(patsubst %.h,%.h,$(wildcard syscalls/*.h)) $(patsubst %.h,%.h,$(wildcard ioctls/*.h))

SRCS		= $(wildcard *.c) \
		  $(wildcard children/*.c) \
		  $(wildcard fds/*.c) \
		  $(wildcard ioctls/*.c) \
		  $(wildcard net/*.c) \
		  $(wildcard syscalls/*.c) \
		  $(SYSCALLS_ARCH)

OBJS		= $(sort $(patsubst %.c,%.o,$(wildcard *.c))) \
		  $(sort $(patsubst %.c,%.o,$(wildcard children/*.c))) \
		  $(sort $(patsubst %.c,%.o,$(wildcard fds/*.c))) \
		  $(sort $(patsubst %.c,%.o,$(wildcard ioctls/*.c))) \
		  $(sort $(patsubst %.c,%.o,$(wildcard net/*.c))) \
		  $(sort $(patsubst %.c,%.o,$(wildcard syscalls/*.c))) \
		  $(sort $(patsubst %.c,%.o,$(SYSCALLS_ARCH)))

DEPDIR= .deps

-include $(SRCS:%.c=$(DEPDIR)/%.d)

trinity: version test $(OBJS) $(HEADERS)
	$(QUIET_CC)$(CC) $(CFLAGS) $(LDFLAGS) -o trinity $(OBJS)
	@mkdir -p tmp

df = $(DEPDIR)/$(*D)/$(*F)

%.o : %.c
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
	@rm -f include/version.h

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

