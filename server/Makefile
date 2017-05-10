NR_CPUS := $(shell grep -c ^processor /proc/cpuinfo)

CFLAGS ?= -g -O2 -D_FORTIFY_SOURCE=2
CFLAGS += -Wall -Wextra -I. -I../include/ -Wimplicit -D_GNU_SOURCE -D__linux__

CCSTD := $(shell if $(CC) -std=gnu11 -S -o /dev/null -xc /dev/null >/dev/null 2>&1; then echo "-std=gnu11"; else echo "-std=gnu99"; fi)
CFLAGS += $(CCSTD)

CFLAGS += -Wdeclaration-after-statement
CFLAGS += -Wformat=2
CFLAGS += -Winit-self
CFLAGS += -Wnested-externs
CFLAGS += -Wpacked
CFLAGS += -Wshadow
CFLAGS += -Wundef
CFLAGS += -Wwrite-strings
CFLAGS += -Wno-format-nonliteral
CFLAGS += -Wstrict-prototypes -Wmissing-prototypes

# gcc only.
ifneq ($(shell $(CC) -v 2>&1 | grep -c "clang"), 1)
CFLAGS += -Wlogical-op
CFLAGS += -Wstrict-aliasing=3
ifeq ($(DEVEL), 0)
CFLAGS += -Wno-maybe-uninitialized
endif
endif

# Sometimes useful for debugging. more useful with clang than gcc.
#CFLAGS += -fsanitize=address

LDFLAGS = -lpthread

V	= @
Q	= $(V:1=)
QUIET_CC = $(Q:@=@echo    '  CC	'$@;)


all: trinityserver

HEADERS		:= $(patsubst %.h,%.h,$(wildcard *.h))

SRCS		:= $(wildcard *.c)

OBJS		:= $(sort $(patsubst %.c,%.o,$(wildcard *.c)))

DEPDIR= .deps

-include $(SRCS:%.c=$(DEPDIR)/%.d)

trinityserver: $(OBJS) $(HEADERS)
	$(QUIET_CC)$(CC) $(CFLAGS) $(LDFLAGS) -o trinityserver $(OBJS) $(LDLIBS)

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
	@rm -f trinityserver
