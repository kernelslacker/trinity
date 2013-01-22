VERSION=1.1

INSTALL_PREFIX ?= $(DESTDIR)
INSTALL_PREFIX ?= $(HOME)

CFLAGS = -Wall -W -g -O2 -I. -Wimplicit -D_FORTIFY_SOURCE=2 -D_GNU_SOURCE
#CFLAGS += $(shell if $(CC) -m32 -S -o /dev/null -xc /dev/null >/dev/null 2>&1; then echo "-m32"; fi)
CFLAGS += -Wdeclaration-after-statement
CFLAGS += -Wformat=2
CFLAGS += -Winit-self
CFLAGS += -Wlogical-op
CFLAGS += -Wnested-externs
CFLAGS += -Wpacked
CFLAGS += -Wshadow
CFLAGS += -Wstrict-aliasing=3
CFLAGS += -Wswitch-default
CFLAGS += -Wswitch-enum
CFLAGS += -Wundef
CFLAGS += -Wwrite-strings

# Only enabled during development.
#CFLAGS += -Werror

all: trinity

test:
	@if [ ! -f config.h ]; then  echo Run configure.sh first.; exit; fi


MACHINE		= $(shell $(CC) -dumpmachine)
SYSCALLS_ARCH	= $(patsubst %.c,%.o,$(shell case "$(MACHINE)" in \
		  (sh*) echo syscalls/sh/*.c ;; \
		  esac))

HEADERS		= $(patsubst %.h,%.h,$(wildcard *.h)) $(patsubst %.h,%.h,$(wildcard syscalls/*.h)) $(patsubst %.h,%.h,$(wildcard ioctls/*.h))

SRCS		= $(wildcard *.c) \
		  $(wildcard syscalls/*.c) \
		  $(SYSCALLS_ARCH) \
		  $(wildcard ioctls/*.c)

OBJS		= $(patsubst %.c,%.o,$(wildcard *.c)) \
		  $(patsubst %.c,%.o,$(wildcard syscalls/*.c)) \
		  $(SYSCALLS_ARCH) \
		  $(patsubst %.c,%.o,$(wildcard ioctls/*.c))

DEPDIR= .deps

-include $(SRCS:%.c=$(DEPDIR)/%.d)

trinity: test $(OBJS) $(HEADERS)
	$(CC) $(CFLAGS) -o trinity $(OBJS)
	@mkdir -p tmp

df = $(DEPDIR)/$(*F)

%.o : %.c
	$(CC) $(CFLAGS) -o $@ -c $<
	@gcc -MM $(CFLAGS) $*.c > $(df).d
	@mv -f $(df).d $(df).d.tmp
	@sed -e 's|.*:|$*.o:|' <$(df).d.tmp > $(df).d
	@sed -e 's/.*://' -e 's/\\$$//' < $(df).d.tmp | fmt -1 | \
	  sed -e 's/^ *//' -e 's/$$/:/' >> $(df).d
	@rm -f $(df).d.tmp

clean:
	@rm -f *.o syscalls/*.o syscalls/ia64/*.o syscalls/powerpc/*.o ioctls/*.o
	@rm -f core.*
	@rm -f trinity
	@rm -f tags
	@rm -f $(DEPDIR)/*.d

devel:
	@perl -p -i -e 's/^#CFLAGS \+\= -Werror/CFLAGS += -Werror/' Makefile
	git commit Makefile -m "Enable -Werror"

release:
	@perl -p -i -e 's/^CFLAGS \+\= -Werror/#CFLAGS += -Werror/' Makefile
	git commit Makefile -m "Disable -Werror"

tarball:
	git repack -a -d
	git prune-packed
	git archive --format=tar.gz --prefix=trinity-$(VERSION)/ HEAD > trinity-$(VERSION).tgz

install:
	install -d -m 755 $(INSTALL_PREFIX)/bin
	install trinity $(INSTALL_PREFIX)/bin

tags:
	@ctags -R --exclude=tmp

