#
# src/backend/security/Makefile
#   Makefile for Security Enhanced PostgreSQL
#
# Copyright (c) 2006 - 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
# 
ubdir = src/backend/security
top_builddir = ../../..
include $(top_builddir)/src/Makefile.global

ifeq ($(enable_selinux), yes)
OBJS := pgaceCommon.o \
	sepgsqlCore.o sepgsqlProxy.o sepgsqlHeap.o sepgsqlVerify.o \
	sepgsqlHooks.o sepgsqlExtStmt.o
else
OBJS := pgaceCommon.o
endif

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
