RELATIVE_PATH := /root
KBUILD_EXTMOD += $(RELATIVE_PATH)/yu/kmods/base_lib
KBUILD_EXTRA_SYMBOLS=$(RELATIVE_PATH)/yu/kmods/base_lib/Module.symvers
MY_PATH := /home/chuhu/Git

obj-m := event_mod.o
event_mod-objs := pita.o

EXTRA_CFLAGS := -I$(PWD)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
