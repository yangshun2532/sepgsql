# Installation
PREFIX ?= $(DESTDIR)/usr/local/memcached
LIBDIR ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include

CFLAGS ?= -g -Wall
LDFLAGS ?= -rdynamic
LIBRARIES ?= -lpthread -lselinux -laudit

LIBSO = selinux_engine.so
HEADERS = selinux_engine.h
OBJS = mblock.o mbtree.o mcache.o interfaces.o selinux.o

all: $(LIBSO)

$(LIBSO): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(LIBRARIES) -shared -o $@ $^

.c.o:
	$(CC) -I $(INCLUDEDIR) -fPIC $(CFLAGS) -c -o $@ $<

install: $(LIBSO)
	test -d $(LIBDIR) || install -m 755 -d $(LIBDIR)
	install -m 755 $(LIBSO) $(LIBDIR)

clean:
	rm -rf $(OBJS) $(LIBSO)
