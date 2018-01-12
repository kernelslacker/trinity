obj-m := debug_pa.o walk_pg_table.o

KDIR := /usr/lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
default:
	make -C $(KDIR) M=$(PWD) modules
	gcc userpage.c -o userpage
	gcc userhugepage.c -o userhugepage
clean:
	make -C $(KDIR) M=$(PWD) clean
	rm -f userpage userhugepage

walk:
	dmesg -C
	insmod walk_pg_table.ko vaddr=$(vaddr)
	rmmod walk_pg_table
