VERSION=1.0

CFLAGS = -Wall -W -g -O2 -I. -Wimplicit -D_FORTIFY_SOURCE=2 -DVERSION="$(VERSION)" -D_GNU_SOURCE
#CFLAGS += $(shell if $(CC) -m32 -S -o /dev/null -xc /dev/null >/dev/null 2>&1; then echo "-m32"; fi)
CFLAGS += -Wdeclaration-after-statement
CFLAGS += -Wformat-security
CFLAGS += -Wformat-y2k
CFLAGS += -Winit-self
CFLAGS += -Wnested-externs
CFLAGS += -Wpacked
CFLAGS += -Wshadow
CFLAGS += -Wstrict-aliasing=3
CFLAGS += -Wswitch-default
CFLAGS += -Wswitch-enum
CFLAGS += -Wundef
CFLAGS += -Wwrite-strings
CFLAGS += -Wformat

all: trinity

HEADERS		= $(patsubst %.h,%.h,$(wildcard *.h)) syscalls/syscalls.h $(patsubst %.h,%.h,$(wildcard ioctls/*.h))
SYSCALLS	= $(patsubst %.c,%.o,$(wildcard syscalls/*.c))
IOCTLS		= $(patsubst %.c,%.o,$(wildcard ioctls/*.c))
OBJS		= trinity.o \
			child.o \
			main.o \
			fds.o \
			files.o \
			generic-sanitise.o \
			log.o \
			maps.o \
			sockets.o \
			syscall.o \
			params.o \
			tables.o \
			watchdog.o \
			$(SYSCALLS) \
			$(SANITISE) \
			$(IOCTLS)
-include $(OBJS:.o=.d)

trinity: $(OBJS) $(HEADERS)
	$(CC) $(CFLAGS) -o trinity $(OBJS)
	@rm -f *.d syscalls/*.d ioctls/*.d
	@mkdir -p tmp

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<
	gcc -MM $(CFLAGS) $*.c > $*.d
	@mv -f $*.d $*.d.tmp
	@sed -e 's|.*:|$*.o:|' < $*.d.tmp > $*.d
	@sed -e 's/.*://' -e 's/\\$$//' < $*.d.tmp | fmt -1 | \
	  sed -e 's/^ *//' -e 's/$$/:/' >> $*.d
	@rm -f $*.d.tmp

clean:
	@rm -f *.o syscalls/*.o syscalls/ia64/*.o syscalls/powerpc/*.o ioctls/*.o
	@rm -f *.d syscalls/*.d syscalls/ia64/*.d syscalls/powerpc/*.d ioctls/*.d
	@rm -f core.*
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
