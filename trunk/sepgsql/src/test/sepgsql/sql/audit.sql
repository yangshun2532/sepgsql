--@SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

-- cleanup previous tests
SET client_min_messages TO 'error';

DROP TABLE IF EXISTS t1 CASCADE;
DROP TABLE IF EXISTS t2 CASCADE;

RESET client_min_messages;

-- CREATE TABLE for DML basic tests

CREATE TABLE t1
(
	a	int,
	b	text
) SECURITY CONTEXT 'system_u:object_r:sepgsql_ro_table_t:s0';
INSERT INTO t1 VALUES (1, 'aaa'), (2, 'bbb'), (3, 'ccc');

CREATE TABLE t2
(
	x	int,
	y	text
) SECURITY CONTEXT 'system_u:object_r:sepgsql_secret_table_t:s0';
INSERT INTO t2 VALUES (1, 'xxx'), (2, 'yyy'), (3, 'zzz');

--@SECURITY_CONTEXT=unconfined_u:unconfined_r:sepgsql_test_t:s0-s0:c0

SET client_min_messages TO 'log';

UPDATE t1 SET b = b || '_updt';

SELECT * FROM t2;

--@SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

-- cleanups
SET client_min_messages TO 'error';

DROP TABLE IF EXISTS t1 CASCADE;
DROP TABLE IF EXISTS t2 CASCADE;

RESET client_min_messages;
