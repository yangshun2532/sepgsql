#
# src/backend/selinux/Makefile
#     Makefile for Security Enhanced PostgreSQL
#
# Copyright (c) 2006 - 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
#
ubdir = src/backend/security
top_builddir = ../../..
include $(top_builddir)/src/Makefile.global

OBJS := selinux.o bootstrap.o psid.o libselinux.o \
	create_relation.o copy.o

all: SUBSYS.o

SUBSYS.o: $(OBJS)
	$(LD) $(LDREL) $(LDOUT) $@ $^

depend dep:
	$(CC) -MM $(CFLAGS) *.c >depend

clean:
	rm -f SUBSYS.o $(OBJS)

ifeq (depend,$(wildcard depend))
include depend
endif
