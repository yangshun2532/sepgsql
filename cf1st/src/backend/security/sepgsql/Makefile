#
# Makefile
#    Makefile for utils/sepgsql : SE-PostgreSQL
#

subdir = src/backend/security/sepgsql
top_builddir = ../../../..
include $(top_builddir)/src/Makefile.global

ifeq ($(enable_selinux), yes)
OBJS = avc.o checker.o core.o hooks.o label.o perms.o
else
OBJS = dummy.o
endif

include $(top_srcdir)/src/backend/common.mk
