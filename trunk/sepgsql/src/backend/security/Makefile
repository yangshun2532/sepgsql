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
OBJS += sepgsql/core.o sepgsql/hooks.o		\
	sepgsql/permissions.o sepgsql/proxy.o
endif

include $(top_builddir)/src/backend/common.mk
