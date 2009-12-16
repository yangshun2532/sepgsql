#
# Makefile for enhanced security feature
#
subdir = src/backend/security
top_builddir = ../../..
include $(top_builddir)/src/Makefile.global

OBJS = pgace.o

ifeq ($(enable_selinux), yes)
SUBDIRS += sepgsql
endif

include $(top_srcdir)/src/backend/common.mk
