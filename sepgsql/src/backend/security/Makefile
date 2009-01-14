#
# src/backend/security/Makefile
#   Makefile for Security Purpose Extensions
#
# Copyright (c) 2006 - 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
#
subdir = src/backend/security
top_builddir = ../../..
include $(top_builddir)/src/Makefile.global


OBJS := pgaceCommon.o pgaceHooks.o

ifeq ($(enable_selinux), yes)
OBJS += sepgsql/avc.o sepgsql/core.o sepgsql/hooks.o	\
	sepgsql/permissions.o sepgsql/proxy.o
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
