KDIR ?= /lib/modules/$(shell uname -r)/build
XTABLES_SO_DIR ?= $(shell pkg-config xtables --variable xtlibdir 2>/dev/null || echo /usr/lib/x86_64-linux-gnu/xtables)

CFLAGS_EXTRA := -Wall -Wextra -Werror

all: kernel libxt_AWG_WGOBFS.so

kernel:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

libxt_AWG_WGOBFS.so: libxt_AWG_WGOBFS.c awg_wgobfs.h
	$(CC) $(CFLAGS) $(CFLAGS_EXTRA) -fPIC -shared -o $@ $< $(shell pkg-config --cflags xtables 2>/dev/null)

install: all
	install -m 0644 awg_wgobfs.ko /lib/modules/$(shell uname -r)/extra/
	depmod -a
	install -m 0755 libxt_AWG_WGOBFS.so $(XTABLES_SO_DIR)/

uninstall:
	rm -f /lib/modules/$(shell uname -r)/extra/awg_wgobfs.ko
	depmod -a
	rm -f $(XTABLES_SO_DIR)/libxt_AWG_WGOBFS.so

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f *.so

.PHONY: all kernel install uninstall clean
