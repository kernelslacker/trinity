RELATIVE_PATH := /root
KBUILD_EXTMOD += $(RELATIVE_PATH)/yu/kmods/base_lib
KBUILD_EXTRA_SYMBOLS=$(RELATIVE_PATH)/yu/kmods/base_lib/Module.symvers
MY_PATH := /home/chuhu/Git

obj-m := kinfo.o

KDIR := /usr/lib/modules/$(shell uname -r)/build
KDIR_1 := /home/chuhu/Git/linux

PWD := $(shell pwd)

default:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
