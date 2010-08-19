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
OBJS = selinux.o label.o relation.o
SCRIPTS = initdb.sepgsql
SCRIPTS_built = initdb.sepgsql
SHLIB_LINK = -lselinux

SEPG_BIN=$(shell $(PG_CONFIG) | awk '/^BINDIR/ {print $$3;}' | sed 's/\//\\\//g')
SEPG_VERSION=$(shell $(PG_CONFIG) | awk '/^VERSION/ {print $$4;}' | sed 's/^\([0-9]*\.[0-9]*\).*$$/\1/')

PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

initdb.sepgsql: initdb.sepgsql.in
	cat initdb.sepgsql.in |				\
	sed -e "s/@@__SEPG_BIN__@@/$(SEPG_BIN)/g"	\
	    -e "s/@@__SEPG_VERSION__@@/$(SEPG_VERSION)/g" > $@
	chmod 755 $@
