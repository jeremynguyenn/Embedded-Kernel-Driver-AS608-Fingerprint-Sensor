# Makefile for AS608 kernel module

obj-m += as608.o
as608-objs := as608_core.o as608_ioctl.o as608_uart.o as608_commands.o as608_sysfs.o

KDIR := /lib/modules/$(shell uname -r)/build

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

install:
	sudo insmod as608.ko
	sudo mknod /dev/as608 c 10 $(shell grep as608 /proc/misc | awk '{print $$1}')

uninstall:
	sudo rmmod as608
	sudo rm /dev/as608