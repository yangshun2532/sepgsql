PSQL	:= $(shell which psql)
RUNCON	:= $(shell which runcon)
DBNAME	:= test

RUN_DBA  = $(RUNCON) unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15 $(PSQL) -aq $(DBNAME)
RUN_USER = $(RUNCON) unconfined_u:unconfined_r:sepgsql_test_t:s0-s0:c0   $(PSQL) -aq $(DBNAME)

TESTCASES = $(notdir $(wildcard sql/*.sql))

test: clean run_test

clean:
	@rm -f results/*.out results/*.diff

run_test: environment $(TESTCASES:.sql=.test)

%.test: sql/%.sql
	@touch results/$*.out
	@test -r sql/$*.init && $(RUN_DBA) -f sql/$*.init >> results/$*.out 2>&1 || :
	@$(RUN_USER) -f sql/$*.sql >> results/$*.out 2>&1 || :
	@test -r sql/$*.fini && $(RUN_DBA) -f sql/$*.fini >> results/$*.out 2>&1 || :
	@diff -u expected/$*.out results/$*.out > results/$*.diff 2>/dev/null && echo -n "PASS: " || echo -n "FAIL: "
	@echo $@

environment:
	@test -x $(PSQL) || (echo "$(PSQL) is not available"; exit 1)
	@test -x $(RUNCON) || (echo "$(RUNCON) is not available"; exit 1)
	@$(PSQL) -qt -c '' -d $(DBNAME) || \
		(echo "HINT: connection to $(DBNAME) is not available"; exit 1)
	@$(PSQL) -qt -c 'SHOW pgace_security' -d $(DBNAME) | grep -q selinux || \
		(echo "HINT: daemon is not SE-PostgreSQL"; exit 1)
	@/usr/sbin/selinuxenabled || \
		(echo "HINT: SELinux is disabled!"; exit 1)
	@$(RUNCON) -t sepgsql_test_t -l s0-s0:c0.c15 id -Z > /dev/null || \
		(echo "HINT: install sepostgresql-devel.pp"; exit 1)
	@$(RUN_USER) -c 'SELECT sepgsql_getcon()' >& /dev/null || \
		(echo "HINT: do /sbin/restorecon -R and restart"; exit 1)
	@/etc/init.d/mcstrans status > /dev/null && \
		(echo "HINT: stop 'mcstrans' daemon!"; exit 1) || :
	@echo "PASS: platform environment for the test"
