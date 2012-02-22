VERSION=1.0

CFLAGS = -Wall -W -Wshadow -g -O2 -I. -Wimplicit -Werror -D_FORTIFY_SOURCE=2 -DVERSION="$(VERSION)"
#CFLAGS += $(shell if $(CC) -m32 -S -o /dev/null -xc /dev/null >/dev/null 2>&1; then echo "-m32"; fi)

all: trinity

SYSCALLS	= $(patsubst %.c,%.o,$(wildcard syscalls/*.c))
IOCTLS		= $(patsubst %.c,%.o,$(wildcard ioctls/*.c))
OBJS		= trinity.o \
			generic-sanitise.o \
			files.o sockets.o fds.o \
			syscall.o \
			maps.o \
			log.c \
			$(SYSCALLS) \
			$(SANITISE) \
			$(IOCTLS)

trinity: $(OBJS)
	$(CC) $(CFLAGS) -o trinity $(OBJS)
	mkdir -p tmp

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	@find . -name "*.o" -exec rm {} \;
	@find . -name "*~" -exec rm {} \;
	@rm -f trinity

splint:
	@splint -nullpass -immediatetrans -compmempass -predboolothers -retvalint -preproc +posixlib \
	 -badflag -fileextensions -type -nullassign -boolops -showcolumn -sysunrecog -fullinitblock \
	 -onlytrans -unrecog -usedef -statictrans -compdestroy -predboolint -D__`uname -m`__  files.c \
	 trinity.c  generic-sanitise.c

release:
	git repack -a -d
	git prune-packed
	git archive --format=tar.gz --prefix=trinity-$(VERSION)/ HEAD > trinity-$(VERSION).tgz
