:SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15
-- Basic Row-level Access Controls
-- ====================================

SELECT sepgsql_getcon();

-- cleanup previous tests
SET client_min_messages TO 'error';

DROP TABLE IF EXISTS t2 CASCADE;
DROP TABLE IF EXISTS t1 CASCADE;

RESET client_min_messages;

CREATE TABLE t1
(
	a	int primary key,
	b	text
);

CREATE TABLE t2
(
	x	int references t1(a),
	y	text
);

INSERT INTO t1 (security_label, a, b) VALUES
       ('system_u:object_r:sepgsql_table_t:s0',            1, 'aaa'),
       ('system_u:object_r:sepgsql_table_t:s0:c0',         2, 'bbb'),
       ('system_u:object_r:sepgsql_table_t:s0:c1',         3, 'ccc'),
       ('system_u:object_r:sepgsql_ro_table_t:s0',         4, 'ddd'),
       ('system_u:object_r:sepgsql_ro_table_t:s0:c0',      5, 'eee'),
       ('system_u:object_r:sepgsql_ro_table_t:s0:c1',      6, 'fff');

INSERT INTO t2 (x, y) VALUES
       (1, 'red'), (2, 'blue'), (3, 'yellow'),
       (4, 'green'), (5, 'orange'), (6, 'white');
UPDATE t2 SET security_label = sepgsql_set_range(security_label, 's0:c1')
       WHERE x IN (1, 3, 4)

:SECURITY_CONTEXT=unconfined_u:unconfined_r:sepgsql_test_t:s0-s0:c0

SELECT sepgsql_getcon();

SELECT security_label, * FROM t1;
SELECT security_label, * FROM t2;

COPY t1 (security_label, a, b) TO stdout;
COPY t2 (security_label, x, y) TO stdout;

SELECT t1.security_label, t2.security_label, * FROM t1 JOIN t2 ON t1.a = t2.x;

BEGIN;
UPDATE t1 SET b = b || '_updt';
SELECT security_label, * FROM t1;
ABORT;

BEGIN;
DELETE FROM t2 RETURNING *;
ABORT;

INSERT INTO t1 VALUES (6, 'fff');	-- to be failed
DELETE FROM t1 WHERE a = 1;		-- to be failed
