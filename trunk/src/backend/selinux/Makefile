#
# src/backend/selinux/Makefile
#     Makefile for Security Enhanced PostgreSQL
#
# Copyright (c) 2006 - 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
#
ubdir = src/backend/security
top_builddir = ../../..
include $(top_builddir)/src/Makefile.global

OBJS := sepgsql.o bootstrap.o rewrite.o proxy.o expr.o labeling.o sqlfunc.o \
	database.o relation.o procedure.o copy.o

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
