CFLAGS = -Wall -W -Wshadow -g -O2 -I. -Wimplicit -Werror
#CFLAGS += $(shell if $(CC) -m32 -S -o /dev/null -xc /dev/null >/dev/null 2>&1; then echo "-m32"; fi)

all: scrashme

SANITISE	= $(patsubst %.c,%.o,$(wildcard sanitise/*.c))
OBJS		= scrashme.o generic-sanitise.o files.o $(SANITISE)

scrashme: $(OBJS)
	$(CC) $(CFLAGS) -o scrashme $(OBJS)
	mkdir -p tmp

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	@find . -name "*.o" -exec rm {} \;
	@find . -name "*~" -exec rm {} \;
	@rm -f scrashme

splint:
	@splint -nullpass -immediatetrans -compmempass -predboolothers -retvalint -preproc +posixlib \
	 -badflag -fileextensions -type -nullassign -boolops -showcolumn -sysunrecog -fullinitblock \
	 -onlytrans -unrecog -usedef -statictrans -compdestroy -predboolint -D__`uname -m`__  files.c \
	 scrashme.c  generic-sanitise.c
