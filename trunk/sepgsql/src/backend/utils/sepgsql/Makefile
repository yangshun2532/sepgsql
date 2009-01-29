#
# Makefile
#    Makefile for utils/sepgsql : SE-PostgreSQL
#

subdir = src/backend/utils/sepgsql
top_builddir = ../../../..
include $(top_builddir)/src/Makefile.global

ifeq ($(enable_selinux), yes)
OBJS = core.o label.o avc.o hooks.o analyze.o perms.o
else
OBJS = dummy.o
endif

include $(top_srcdir)/src/backend/common.mk
