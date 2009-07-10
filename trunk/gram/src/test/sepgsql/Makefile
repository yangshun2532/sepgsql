# ----------------------------------------------------
# Makefile for SE-PostgreSQL testcases
# ----------------------------------------------------
PSQL      := $(shell which psql)
DIFF      := $(shell which diff)
RUNCON    := $(shell which runcon)
GETSEBOOL := $(shell which getsebool)
GETENFORCE:= $(shell which getenforce)
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
	@test -s $@ && echo "HINT: See $(shell pwd)/$@ to confirm errors" || :

results/%.diff: sql/%.sql
	@./launch_psql $(PSQL) -a $(DBNAME) < $< >& $(@:%.diff=%.out)
	@$(DIFF) -u $(<:sql/%.sql=expected/%.out)	\
	            $(<:sql/%.sql=results/%.out) >& $@	\
		&& echo -n "PASS: " || echo -n "FAIL: "
	@echo "[SQL] $(notdir $(@:.diff=))"

setup: launch_psql
	@cp -f /dev/null /tmp/sepgsql_test_copy_1
	@cp -f /dev/null /tmp/sepgsql_test_copy_2
	@chcon -t postgresql_tmp_t -l s0 /tmp/sepgsql_test_copy_1
	@chcon -t postgresql_db_t  -l s0 /tmp/sepgsql_test_copy_2
	@chmod 0666 /tmp/sepgsql_test_*
	@echo "PASS: [SETUP] data files"

check:
	@test -x $(PSQL) || \
		(echo "ERROR: $(PSQL) is not available"; exit 1)
	@$(GETENFORCE) | grep Enforcing || \
		(echo "ERROR: SELinux is disabled, or permissive mode"; exit 1)
	@$(GETSEBOOL) allow_user_postgresql_connect | grep -q 'on$$' ||		\
		(echo "ERROR: allow_user_postgresql_connect is disabled";	\
		 echo;								\
		 echo "HINT: setsebool -P allow_user_postgresql_connect 1";	\
		 exit 1)
	@$(GETSEBOOL) sepgsql_regression_test_mode | grep -q 'on$$' ||		\
		(echo "ERROR: sepgsql_regression_test_mode is disabled";	\
		 echo;								\
		 echo "HINT: semodule -i /path/to/sepostgresql-devel.pp";	\
		 echo "HINT: setsebool -P sepgsql_regression_test_mode 1";	\
		 exit 1)
	@$(PSQL) -qt -c '' -d $(DBNAME) >& /dev/null ||				\
		(echo "ERROR: database \"$(DBNAME)\" unavailable."; exit 1)
	@$(PSQL) -qt -c 'SHOW sepostgresql' -d $(DBNAME) 2>/dev/null | grep -q on || \
		(echo "ERROR: SE-PostgreSQL unavailable."; 			\
		 echo;								\
		 echo "HINT: initdb --enable-selinux -D /path/to/database";	\
		 exit 1)
	@$(RUNCON) -t sepgsql_test_t -l s0-s0:c0.c15 \
		$(PSQL) -c 'SELECT sepgsql_getcon()' $(DBNAME) >& /dev/null ||	\
		(echo "ERROR: unable to connect with \"sepgsql_test_t\" domain"; \
		 echo;								\
		 echo "HINT: /sbin/restorecon -R /path/to/install and restart";	\
		 echo "HINT: User shell must have \"s0-s0:c0.c15\" range.";	\
		 echo "      semanage login -a -r s0-s0:c0.c15 <username>";	\
		 exit 1)
	@echo "PASS: [CHECK] runtime environment"
