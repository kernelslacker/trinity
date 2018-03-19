obj-m := lpm.o

KDIR := /usr/lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default:
	make -C $(KDIR) M=$(PWD) modules

clean:
	rm -rf *.o .* .cmd *.ko *.mod.c .tmp_versions
