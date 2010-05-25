# ----------------------------------------------------
# Makefile for SE-PostgreSQL testcases
# ----------------------------------------------------
PSQL      := $(shell which psql)
DIFF      := $(shell which diff)
RUNCON    := $(shell which runcon)
GETSEBOOL := $(shell which getsebool)
DBNAME	  := test

TESTCASES = $(wildcard sql/*.sql)

test:
	$(MAKE) init
	$(MAKE) launch_psql
	$(MAKE) check
	$(MAKE) results.diff

init:
	rm -f results.diff results/*.out results/*.diff

clean: init
	rm -f launch_psql

launch_psql: launch_psql.c
	$(CC) $< -o $@ -lselinux

results.diff: $(TESTCASES:sql/%.sql=results/%.diff)
	@for x in $^; do cat $$x >> $@; done
	@test -s $@ && echo "HINT: See $(shell pwd)/$@ to confirm errors" || :

results/%.diff: sql/%.sql
	@./launch_psql $(PSQL) -Xaq -P linestyle=ascii $(DBNAME) < $< >& $(@:%.diff=%.out)
	@$(DIFF) -u $(<:sql/%.sql=expected/%.out)	\
	            $(<:sql/%.sql=results/%.out) >& $@	\
		&& echo -n "PASS: " || echo -n "FAIL: "
	@echo $(notdir $(@:.diff=))

setup: launch_psql
	@echo "PASS: setup system environment"

check:
	@test -x $(PSQL) || \
		(echo "HINT: $(PSQL) is not available"; exit 1)
	@$(PSQL) -qt -c 'SHOW selinux_support' -d $(DBNAME) 2>/dev/null | grep -q enforcing || \
		(echo "HINT: database \"$(DBNAME)\" is not available"; \
		 echo "      or, SELinux support may not be enforcing mode"; exit 1)
	@$(GETSEBOOL) allow_user_postgresql_connect | grep -q 'on$$' || \
		(echo "HINT: check allow_user_postgresql_connect boolean"; exit 1)
	@$(GETSEBOOL) sepgsql_regression_test_mode | grep -q 'on$$' || \
		(echo "HINT: check sepgsql_regression_test_mode boolean"; \
		 echo "HINT: check sepostgresql-devel.pp installed"; exit 1)
	@$(RUNCON) -t sepgsql_test_t -l s0-s0:c0.c15 \
		$(PSQL) -c 'SELECT sepgsql_getcon()' $(DBNAME) >& /dev/null || \
		(echo "HINT: run restorecon -R <prefix>"; \
		 echo "          chcon -t postgresql_db_t -R <data dir>"; \
		 echo "          and, pg_ctl restart"; \
		 echo "HINT: user shell should have 's0-s0:c0.c15' range, at least"; \
		 echo "      semanage enables to set up it"; exit 1)
	@echo "PASS: check runtime environment"
