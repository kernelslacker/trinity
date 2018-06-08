obj-m := hung.o
hung-objs := hung_task.o

KDIR := /usr/lib/modules/$(shell uname -r)/build
#-KDIR := /home/chuhu/Git/linux

PWD := $(shell pwd)

default:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
