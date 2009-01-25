:SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

-- Row-level access controls and PK/FK constraint
-- ================================================


SELECT sepgsql_getcon();

SET client_min_messages TO 'error';

DROP TABLE IF EXISTS t4 CASCADE;
DROP TABLE IF EXISTS t3 CASCADE;
DROP TABLE IF EXISTS t2 CASCADE;
DROP TABLE IF EXISTS t1 CASCADE;

RESET client_min_messages;

CREATE TABLE t1
(
	x	int primary key,
	y	text
);

INSERT INTO t1 (security_label, x, y)
       VALUES ('system_u:object_r:sepgsql_table_t:s0',    1, 'aaa'),
       	      ('system_u:object_r:sepgsql_table_t:s0',    2, 'bbb'),
       	      ('system_u:object_r:sepgsql_table_t:s0:c1', 3, 'ccc'),
       	      ('system_u:object_r:sepgsql_table_t:s0:c1', 4, 'ddd');

CREATE TABLE t2
(
	x	int primary key,
	y	text
);
INSERT INTO t2 (security_label, x, y)
       (SELECT security_label, x, y FROM t1);

CREATE TABLE t3
(
	a	int references t1(x)
);
INSERT INTO t3 (security_label, a)
       VALUES ('system_u:object_r:sepgsql_table_t:s0',    1),
       	      ('system_u:object_r:sepgsql_table_t:s0:c1', 2),
	      ('system_u:object_r:sepgsql_table_t:s0',    3),
	      ('system_u:object_r:sepgsql_table_t:s0:c1', 4);

CREATE TABLE t4
(
	b	int references t2(x)
			ON UPDATE CASCADE ON DELETE SET NULL
);
INSERT INTO t4 (security_label, b)
       VALUES ('system_u:object_r:sepgsql_table_t:s0:c1', 1),
       	      ('system_u:object_r:sepgsql_table_t:s0',    2),
	      ('system_u:object_r:sepgsql_table_t:s0:c1', 3),
	      ('system_u:object_r:sepgsql_table_t:s0',    4);

SELECT security_label, * FROM t1;
SELECT security_label, * FROM t2;
SELECT security_label, * FROM t3;
SELECT security_label, * FROM t4;

:SECURITY_CONTEXT=unconfined_u:unconfined_r:sepgsql_test_t:s0-s0:c0

SELECT sepgsql_getcon();

SELECT security_label, * FROM t1;
SELECT security_label, * FROM t2;
SELECT security_label, * FROM t3;
SELECT security_label, * FROM t4;

INSERT INTO t1 VALUES (4, 'ddd');	-- to be failed
INSERT INTO t1 VALUES (5, 'eee');

INSERT INTO t3 VALUES (2);
INSERT INTO t3 VALUES (3);	-- to be failed

DELETE FROM t1 WHERE x = 5 RETURNING *;
DELETE FROM t1 WHERE x = 2 RETURNING *;	-- to be failed

UPDATE t2 SET x = x + 10 RETURNING *;	-- to be failed
UPDATE t2 SET x = x + 10 WHERE x = 2 RETURNING *;

DELETE FROM t2 WHERE x = 1 RETURNING *;	-- to be failed
DELETE FROM t2 WHERE x = 12 RETURNING *;