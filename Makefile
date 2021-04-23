obj-m += tcpprobe_plus.o
tcpprobe_plus-y := hooks.o sysctl.o stat.o tcp_hash.o ftrace_hook.o tcp_cubic.o tcp_bbr.o tcp_bbr2.o main.o

all: modules

modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

modules_install:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules_install

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
