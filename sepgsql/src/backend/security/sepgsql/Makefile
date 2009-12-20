#
# Makefile
#    Makefile for utils/sepgsql : SE-PostgreSQL
#

subdir = src/backend/security/sepgsql
top_builddir = ../../../..
include $(top_builddir)/src/Makefile.global

OBJS = misc.o
ifeq ($(enable_selinux), yes)
OBJS += selinux.o checker.o bridge.o label.o
endif

include $(top_srcdir)/src/backend/common.mk
