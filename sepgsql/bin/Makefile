#
# Makefile of the SE-PostgreSQL module
#
# Author: KaiGai Kohei <kaigai@ak.jp.nec.com>
#
# Copyright (c) 2007 - 2010, NEC Corporation
# Copyright (c) 2006 - 2007, KaiGai Kohei <kaigai@kaigai.gr.jp>
#
PG_CONFIG = $(shell env PATH=$$PATH:/usr/local/pgsql/bin which pg_config)

PROGRAM = initdb.sepgsql
OBJS = initdb_sepgsql.o
SHLIB_LINK = -lselinux

PGXS := $(shell $(PG_CONFIG) --pgxs)
PG_BINDIR := $(shell $(PG_CONFIG) | awk '/^BINDIR/ {print $$3;}')
ifneq ($(PG_BINDIR), )
PG_CPPFLAGS = -DPG_BINDIR=\"$(PG_BINDIR)\"
endif
include $(PGXS)
