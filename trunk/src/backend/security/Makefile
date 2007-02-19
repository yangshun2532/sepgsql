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
OBJS := sepgsqlCore.o sepgsqlPsid.o sepgsqlProxy.o \
	sepgsqlHeap.o sepgsqlVerify.o sepgsqlHooks.o \
	sepgsqlRelation.o sepgsqlProcedure.o sepgsqlLargeObject.o
else
OBJS := dummy.o
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
