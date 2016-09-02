obj-m := base.o test_clobber.o
base-objs := base_lib.o

KDIR := /home/chuhu/Git/linux
PWD := $(shell pwd)

default:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
