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
       a     int,
       b     text
);

CREATE TABLE t2 (
       x     int,
       y     text
);

CREATE TABLE t3 (
       s     int,
       t     text
) SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_fixed_table_t:s0';

INSERT INTO t1 VALUES (1, 'aaa');
INSERT INTO t1 (security_label, a, b) VALUES ('unconfined_u:object_r:sepgsql_ro_table_t:s0', 2, 'bbb');
INSERT INTO t1 (security_label, a, b) VALUES ('unconfined_u:object_r:sepgsql_table_t:s0:c1', 3, 'ccc');
INSERT INTO t1 VALUES (4, 'ddd'), (5, 'eee');
INSERT INTO t1 (security_label, a, b) VALUES ('invalid security context', 6, 'fff');	-- to be failed
INSERT INTO t1 (security_label, a, b) VALUES ('system_u:object_r:sepgsql_table_t:s0:c20', 6, 'fff');	-- to be denied
SELECT security_label, * FROM t1;

INSERT INTO t2 (security_label, x, y)
       (SELECT sepgsql_set_user(security_label, 'system_u'), a + 5, b || '_cpy' FROM t1);
SELECT security_label, * FROM t2;

INSERT INTO t3 VALUES (98, 'xxx');
INSERT INTO t3 (security_label, s, t) VALUES ('system_u:object_r:sepgsql_ro_table_t:s0', 99, 'yyy');
INSERT INTO t3 (SELECT * FROM t1);
INSERT INTO t3 (security_label, s, t) (SELECT security_label, x, y FROM t2);
SELECT security_label, * FROM t3;

SELECT sepgsql_set_range(security_label, 's0:c' || s) AS security_label, * INTO t4 FROM t3;	-- partially denied
SELECT security_label, * FROM t4;

COPY t1 (security_label, a, b) FROM stdin;	-- partially denied
system_u:object_r:sepgsql_table_t:s0:c2	10	kkk
system_u:object_r:sepgsql_table_t:s0:c3	11	lll
system_u:object_r:sepgsql_table_t:s0:c20	12	mmm
system_u:object_r:sepgsql_table_t:s0:c4	13	nnn
\.

COPY t1 (security_label, a, b) TO stdout;
