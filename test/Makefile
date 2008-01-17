PSQL=$(shell which psql)

test:	verify_server verify_client \
	security_sysattr

verify_server:
	@echo "CHECK: server type"
	@$(PSQL) -a -c "show SECURITY_SYSATTR_NAME"

verify_client:
	@echo "CHECK: client environment"
	@! /sbin/service mcstrans status
	@runcon -l s0-s0:c0.c15 /bin/true

security_sysattr: security_sysattr.sql
	echo hoge
	$(PSQL) -a -f $< 2>&1
