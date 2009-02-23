--@SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

-- cleanup previous tests
SET client_min_messages TO 'error';

DROP TABLE IF EXISTS t4 CASCADE;
DROP TABLE IF EXISTS t3 CASCADE;
DROP TABLE IF EXISTS t2 CASCADE;
DROP TABLE IF EXISTS t1 CASCADE;

DROP FUNCTION IF EXISTS f1(int) CASCADE;
DROP FUNCTION IF EXISTS f2(int) CASCADE;

RESET client_min_messages;

-- test begins here
CREATE TABLE t1 (
       a int primary key,
       b text
);

CREATE TABLE t2 (
       x int references t1 (a) on update cascade,
       y text
);

INSERT INTO t1 (security_label, a, b) VALUES
       ('system_u:object_r:sepgsql_table_t:s0',		1, 'aaa'),
       ('system_u:object_r:sepgsql_table_t:s0:c0',	2, 'bbb'),
       ('system_u:object_r:sepgsql_table_t:s0:c1',	3, 'ccc'),
       ('system_u:object_r:sepgsql_ro_table_t:s0',	4, 'ddd'),
       ('system_u:object_r:sepgsql_ro_table_t:s0:c0',	5, 'eee'),
       ('system_u:object_r:sepgsql_ro_table_t:s0:c1',	6, 'fff');

INSERT INTO t2 (security_label, x, y) VALUES
       ('system_u:object_r:sepgsql_table_t:s0:c1',	1, 'xxx'),
       ('system_u:object_r:sepgsql_table_t:s0:c0',	2, 'yyy'),
       ('system_u:object_r:sepgsql_table_t:s0',		3, 'zzz');

SELECT security_label, * FROM t1;
SELECT security_label, * FROM t2;

--@SECURITY_CONTEXT=unconfined_u:unconfined_r:sepgsql_test_t:s0:c0
SELECT security_label, * FROM t1;
SELECT security_label, * FROM t2;

COPY t1 TO stdout;
COPY t2 (security_label, x, y) TO stdout;

UPDATE t1 SET a = 99 WHERE a = 1 RETURNING *;	-- to be failed
UPDATE t1 SET a = 99 WHERE a = 2 RETURNING *;
UPDATE t1 SET a = 99 WHERE a = 4 RETURNING *;	-- to be denied

INSERT INTO t1 VALUES (3, 'ccc');	-- to be failed
INSERT INTO t1 VALUES (7, 'ggg');
INSERT INTO t2 VALUES (3, 'XXX');	-- to be failed
INSERT INTO t2 VALUES (4, 'XXX');

DELETE FROM t1;		-- to be failed
DELETE FROM t1 WHERE a not in (SELECT x FROM t2);	-- to be failed
DELETE FROM t1 WHERE a = 7;

