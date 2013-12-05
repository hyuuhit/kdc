obj-m := kdc.o
kdc-objs := udp_filter.o kdc_debug.o echo_simple.o dns_cache.o dns_filter.o util.o

PWD:=$(shell pwd)
KVER:=$(shell uname -r)
KDIR:=/lib/modules/$(KVER)/build


#EXTRA_CFLAGS += -DKDC_DEBUG
EXTRA_CFLAGS += -DKDC_OPS=dns_filter_ops -Wall -g

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
