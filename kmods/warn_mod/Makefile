obj-m := warn.o
warn-objs:= warn_mod.o

KDIR := /lib/modules/`uname -r`/build/
PWD := $(shell pwd)

default:
	make -C $(KDIR) M=$(PWD) modules

clean:
	rm -rf *.o .* .cmd *.ko *.mod.c .tmp_versions
