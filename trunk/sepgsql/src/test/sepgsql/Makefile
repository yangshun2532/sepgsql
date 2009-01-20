PSQL	:= $(shell which psql)
RUNCON	:= $(shell which runcon)
DBNAME	:= test

RUN_DBA  = $(RUNCON) unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15 $(PSQL) -aq $(DBNAME)
RUN_USER = $(RUNCON) unconfined_u:unconfined_r:sepgsql_test_t:s0-s0:c0   $(PSQL) -aq $(DBNAME)

TESTCASES = $(notdir $(wildcard sql/*.sql))

test: clean run_test

clean:
	@rm -f whole_results.diff results/*.out results/*.diff

run_test: environment filesystem $(TESTCASES:.sql=.test)

%.test: sql/%.sql
	@touch results/$*.out
	@test -r sql/$*.init && $(RUN_DBA) -f sql/$*.init >> results/$*.out 2>&1 || :
	@$(RUN_USER) -f sql/$*.sql >> results/$*.out 2>&1 || :
	@test -r sql/$*.fini && $(RUN_DBA) -f sql/$*.fini >> results/$*.out 2>&1 || :
	@diff -u expected/$*.out results/$*.out > results/$*.diff 2>/dev/null && echo -n "PASS: " || echo -n "FAIL: "
	@echo $@
	@cat results/$*.diff >> whole_results.diff

filesystem:
	@test -e /tmp/sepgsql_test_copy_1 && rm -f /tmp/sepgsql_test_copy_1 || :
	@test -e /tmp/sepgsql_test_copy_2 && rm -f /tmp/sepgsql_test_copy_2 || :
	@test -e /tmp/sepgsql_test_blob && rm -f /tmp/sepgsql_test_blob || :
	@touch /tmp/sepgsql_test_copy_1 /tmp/sepgsql_test_copy_2
	@dd if=/dev/zero of=/tmp/sepgsql_test_blob bs=1024 count=20 >& /dev/null
	@chcon -t postgresql_db_t  -l s0 /tmp/sepgsql_test_copy_1
	@chcon -t postgresql_tmp_t -l s0 /tmp/sepgsql_test_copy_2
	@chcon -t postgresql_tmp_t -l s0 /tmp/sepgsql_test_blob

environment:
	@test -x $(PSQL) || (echo "$(PSQL) is not available"; exit 1)
	@test -x $(RUNCON) || (echo "$(RUNCON) is not available"; exit 1)
	@$(PSQL) -qt -c '' -d $(DBNAME) || \
		(echo "HINT: connection to $(DBNAME) is not available"; exit 1)
	@$(PSQL) -qt -c 'SHOW pgace_feature' -d $(DBNAME) | grep -q selinux || \
		(echo "HINT: daemon is not SE-PostgreSQL"; exit 1)
	@/usr/sbin/selinuxenabled || \
		(echo "HINT: SELinux is disabled!"; exit 1)
	@$(RUNCON) -t sepgsql_test_t -l s0-s0:c0.c15 id -Z > /dev/null || \
		(echo "HINT: install sepostgresql-devel.pp"; exit 1)
	@$(RUN_DBA) -c 'SELECT sepgsql_getcon()' >& /dev/null || \
		(echo "HINT: do /sbin/restorecon -R and restart"; exit 1)
	@$(RUN_USER) -c 'SELECT sepgsql_getcon()' >& /dev/null || \
		(echo "HINT: do /sbin/restorecon -R and restart"; \
		 echo "HINT: do /usr/sbin/setsebool -P allow_user_postgresql_connect=1"; \
		 exit 1)
	@/etc/init.d/mcstrans status > /dev/null && \
		(echo "HINT: stop 'mcstrans' daemon!"; exit 1) || \
		(test $$? -eq 3 && exit 0 || exit 1)
	@echo "PASS: platform environment for the test"
