# ----------------------------------------------------
# Makefile for SE-PostgreSQL testcases
# ----------------------------------------------------
PSQL      := $(shell which psql)
DIFF      := $(shell which diff)
RUNCON    := $(shell which runcon)
GETSEBOOL := $(shell which getsebool)
DBNAME	  := test

TESTCASES = $(wildcard sql/*.sql)

test: init check setup results.diff

init:
	rm -f results.diff results/*.out results/*.diff

clean: init
	rm -f launch_psql

launch_psql: launch_psql.c
	$(CC) $< -o $@ -lselinux

results.diff: $(TESTCASES:sql/%.sql=results/%.diff)
	@for x in $^; do cat $$x >> $@; done
	@test -s $@ && echo "HINT: See $@ to confirm errors" || :

results/%.diff: sql/%.sql
	@./launch_psql $(PSQL) -a $(DBNAME) < $< >& $(@:%.diff=%.out)
	@$(DIFF) -u $(<:sql/%.sql=expected/%.out)	\
	            $(<:sql/%.sql=results/%.out) >& $@	\
		&& echo -n "PASS: " || echo -n "FAIL: "
	@echo $(notdir $(@:.diff=))

setup: launch_psql
	@test -e /tmp/sepgsql_test_copy_1 && rm -f /tmp/sepgsql_test_copy_1 || :
	@test -e /tmp/sepgsql_test_copy_2 && rm -f /tmp/sepgsql_test_copy_2 || :
	@test -e /tmp/sepgsql_test_blob && rm -f /tmp/sepgsql_test_blob || :
	@touch /tmp/sepgsql_test_copy_1 /tmp/sepgsql_test_copy_2
	@dd if=/dev/zero of=/tmp/sepgsql_test_blob bs=1024 count=20 >& /dev/null
	@chcon -t postgresql_db_t  -l s0 /tmp/sepgsql_test_copy_1
	@chcon -t postgresql_tmp_t -l s0 /tmp/sepgsql_test_copy_2
	@chcon -t postgresql_tmp_t -l s0 /tmp/sepgsql_test_blob
	@echo "PASS: setup filesystem objects"

check:
	@test -x $(PSQL) || \
		(echo "HINT: $(PSQL) is not available"; exit 1)
	@$(PSQL) -qt -c 'SHOW pgace_feature' -d $(DBNAME) | grep -q selinux || \
		(echo "HINT: database $(PSQL) is not available"; \
		 echo "HINT: SE-PostgreSQL is not available on server"; exit 1)
	@$(GETSEBOOL) allow_user_postgresql_connect | grep -q on || \
		(echo "HINT: check allow_user_postgresql_connect boolean"; exit 1)
	@$(GETSEBOOL) sepgsql_regression_test_mode | grep -q on || \
		(echo "HINT: check sepgsql_regression_test_mode boolean"; \
		 echo "HINT: check sepostgresql-devel.pp installed"; exit 1)
	@$(RUNCON) -t sepgsql_test_t -l s0-s0:c0.c15 \
		$(PSQL) -c 'SELECT sepgsql_getcon()' $(DBNAME) >& /dev/null || \
		(echo "HINT: /sbin/restorecon -R <prefix> and restart"; \
		 echo "HINT: user shell should have 's0-s0:c0.c15' range, at least" \
		 echo "      semanage enables to set up it"; exit 1)
	@test -x /etc/init.d/mcstrans && /etc/init.d/mcstrans status >& /dev/null && \
		(echo "HINT: stop mcstrans daemon"; exit 1) || \
		(test $$? -eq 3 && exit 0 || exit 1)
	@echo "PASS: check runtime environment"
