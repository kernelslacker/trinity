CFLAGS = -Wall -W -Wshadow -g -O2
#CFLAGS += $(shell if $(CC) -m32 -S -o /dev/null -xc /dev/null >/dev/null 2>&1; then echo "-m32"; fi)

all: scrashme

OBJS =	scrashme.o

scrashme: $(OBJS)
	$(CC) $(CFLAGS) -o scrashme $(OBJS)

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	@find . -name "*.o" -exec rm {} \;
	@find . -name "*~" -exec rm {} \;
	@rm -f scrashme

