CFLAGS = -Wall -W -Wshadow -g -O2
#CFLAGS += $(shell if $(CC) -m32 -S -o /dev/null -xc /dev/null >/dev/null 2>&1; then echo "-m32"; fi)

all: scrashme

OBJS =	scrashme.o sanitise.o files.o

scrashme: $(OBJS)
	$(CC) $(CFLAGS) -o scrashme $(OBJS)
	mkdir -p tmp
	dd if=/dev/urandom of=tmp/testfile bs=1M count=1
	dd if=/dev/urandom of=tmp/testfile2 bs=1M count=1

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	@find . -name "*.o" -exec rm {} \;
	@find . -name "*~" -exec rm {} \;
	@rm -f scrashme

splint:
	splint +posixlib -badflag -fileextensions -type -nullassign -boolops -showcolumn -sysunrecog -fullinitblock -onlytrans -unrecog -usedef -statictrans -compdestroy -predboolint -D__`uname -m`__  files.c scrashme.c  sanitise.c
