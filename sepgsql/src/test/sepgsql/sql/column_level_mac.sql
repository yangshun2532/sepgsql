:SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

SELECT sepgsql_getcon();

-- cleanup previous tests
SET client_min_messages TO 'error';

DROP TABLE IF EXISTS t1 CASCADE;
DROP FUNCTION IF EXISTS f1(integer);

RESET client_min_messages;

CREATE TABLE t1
(
	a	int,
	b	text
		SECURITY_LABEL = 'system_u:object_r:sepgsql_ro_table_t:s0',
	c	text
		SECURITY_LABEL = 'system_u:object_r:sepgsql_secret_table_t:s0'
);

INSERT INTO t1 VALUES (1, 'aaa', '0000-1111-2222'),
       (2, 'bbb', '3333-4444-5555'),
       (3, 'ccc', '6666-7777-8888');

SELECT security_label, attname FROM pg_attribute
       WHERE attrelid IN (SELECT tableoid FROM t1);

CREATE OR REPLACE FUNCTION f1(integer) RETURNS TEXT
       LANGUAGE 'sql'
       SECURITY_LABEL = 'system_u:object_r:sepgsql_trusted_proc_exec_t:s0'
       AS 'SELECT substring(c FROM ''^[0-9]+-'') || ''xxxx-xxxx'' FROM t1 WHERE a = $1';


:SECURITY_CONTEXT=unconfined_u:unconfined_r:sepgsql_test_t:s0:c0

SELECT sepgsql_getcon();

SELECT * FROM t1;	-- to be failed

SELECT a, b FROM t1;

SELECT a, b FROM t1 WHERE c = 'abc';	-- to be failed

SELECT a, b FROM t1 WHERE c is null;	-- to be failed

SELECT a, b FROM t1 ORDER BY c;		-- to be failed

UPDATE t1 SET a = 4, b = 'ddd', c = '1234-5678-9012';	-- to be failed

UPDATE t1 SET a = 4, b = 'ddd';		-- to be failed

UPDATE t1 SET a = 4 WHERE b = 'bbb';

SELECT security_label, * FROM t1;

INSERT INTO t1 (a, b, c) VALUES (5, 'eee', '1234-5678-9012');	-- to be failed

INSERT INTO t1 (a, b) VALUES (5, 'eee');	-- to be failed

INSERT INTO t1 (a) VALUES (5);

SELECT security_label, a, b FROM t1;

DELETE FROM t1 RETURNING a, b, c;		-- to be failed

BEGIN;
DELETE FROM t1 RETURNING a, b;
ABORT;

BEGIN;
DELETE FROM t1 RETURNING a;
ABORT;

SELECT a, b, f1(a) FROM t1;