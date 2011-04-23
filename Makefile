CFLAGS = -Wall -W -Wshadow -g -O2 -I. -Wimplicit -Werror
#CFLAGS += $(shell if $(CC) -m32 -S -o /dev/null -xc /dev/null >/dev/null 2>&1; then echo "-m32"; fi)

all: trinity

SANITISE	= $(patsubst %.c,%.o,$(wildcard sanitise/*.c))
IOCTLS		= $(patsubst %.c,%.o,$(wildcard ioctls/*.c))
OBJS		= trinity.o \
			generic-sanitise.o \
			files.o sockets.o fds.o \
			syscall.o \
			maps.o \
			log.c \
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
