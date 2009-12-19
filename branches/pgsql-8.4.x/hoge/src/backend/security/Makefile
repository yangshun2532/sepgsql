#
# Makefile for the enhanced security subsystem
#

subdir = src/backend/security
top_builddir = ../../..
include $(top_builddir)/src/Makefile.global

SUBDIRS	= sepgsql

OBJS = pgace.o rowlevel.o

include $(top_srcdir)/src/backend/common.mk
