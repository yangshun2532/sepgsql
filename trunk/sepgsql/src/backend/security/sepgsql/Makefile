#
# Makefile for SELinux support
#

subdir = src/backend/security/sepgsql
top_builddir = ../../../..
include $(top_builddir)/src/Makefile.global

ifeq ($(enable_selinux), yes)
OBJS = hooks.o label.o utils.o selinux.o checker.o
else
OBJS = dummy.o
endif

include $(top_srcdir)/src/backend/common.mk
