#
# Makefile
#    Makefile for utils/sepgsql : SE-PostgreSQL
#

subdir = src/backend/security/sepgsql
top_builddir = ../../../..
include $(top_builddir)/src/Makefile.global

ifeq ($(enable_selinux), yes)
OBJS = avc.o checker.o bridge.o hooks.o label.o misc.o perms.o
else
OBJS = dummy.o
endif

include $(top_srcdir)/src/backend/common.mk
