obj-m := lpm.o

KDIR := /home/chuhu/Git/linux/
PWD := $(shell pwd)

default:
	make -C $(KDIR) M=$(PWD) modules

clean:
	rm -rf *.o .* .cmd *.ko *.mod.c .tmp_versions
