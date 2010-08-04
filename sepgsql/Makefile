#
# Makefile of the SE-PostgreSQL module
#
# Author: KaiGai Kohei <kaigai@ak.jp.nec.com>
#
# Copyright (c) 2007 - 2010, NEC Corporation
# Copyright (c) 2006 - 2007, KaiGai Kohei <kaigai@kaigai.gr.jp>
#
PG_CONFIG = $(shell env PATH=$$PATH:/usr/local/pgsql/bin which pg_config)

MODULE_big = sepgsql
OBJS = selinux.o label.o hooks.o
SHLIB_LINK = -lselinux

PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
