KBUILD_EXTMOD += /home/chuhu/Git/yu/kmods/base_lib
KBUILD_EXTRA_SYMBOLS=/home/chuhu/Git/yu/kmods/base_lib/Module.symvers

obj-m := kinfo.o

KDIR := /home/chuhu/Git/linux
PWD := $(shell pwd)

default:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
