ifneq ($(KERNELRELEASE),)
obj-m :=nl.o
else
KERNELDIR ?= /mnt/tests/kernel/distribution/upstream-kernel/install/kernel/
PWD :=$(shell pwd)
default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
endif
