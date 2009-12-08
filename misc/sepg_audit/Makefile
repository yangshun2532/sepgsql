#
# SE-PostgreSQL audit integration
# ---------------------------------------

MODULE_big = sepg_audit
OBJS = sepg_audit.o
SHLIB_LINK := -laudit

PG_CONFIG = $(shell which pg_config)
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
