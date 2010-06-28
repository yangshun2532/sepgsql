# Installation
PREFIX ?= $(DESTDIR)/usr
LIBDIR ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include

CFLAGS ?= -Wall
LDFLAGS ?= -rdynamic
LIBRARIES ?= -lpthread -lselinux -laudit

LIBSO = selinux_engine.so
HEADERS = selinux_engine.h
OBJS = mblock.o mbtree.o selinux_engine.o

all: $(LIBSO)

$(LIBSO): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(LIBRARIES) -shared -o $@ $^

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -I include -fPIC -c -o $@ $<

install:
	test -d $(LIBDIR) || install -m 755 -d $(LIBDIR)
	install -m 755 $(LIBSO) $(LIBDIR)

clean:
	rm -rf $(OBJS) $(LIBSO)
