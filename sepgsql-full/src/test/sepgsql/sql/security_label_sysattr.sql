:SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15
--
-- input/output security labels via 'security_label' system column
--


SELECT sepgsql_getcon();

-- cleanup previous tests
SET client_min_messages TO 'error';

DROP TABLE IF EXISTS t4 CASCADE;
DROP TABLE IF EXISTS t3 CASCADE;
DROP TABLE IF EXISTS t2 CASCADE;
DROP TABLE IF EXISTS t1 CASCADE;

RESET client_min_messages;

-- test proper begins here
CREATE TABLE t1
(
	a	int,
	b	text
);

CREATE TABLE t2
(
	x	int,
	y	text
);

INSERT INTO t1 VALUES (1, 'aaa'), (2, 'bbb');
INSERT INTO t1 (security_label, a, b) VALUES ('system_u:object_r:sepgsql_ro_table_t:s0', 3, 'ccc');
INSERT INTO t1 (security_label, a, b)
       (SELECT sepgsql_set_range(security_label, 's0:c' || a) AS security_label, a+3 AS a, b || '_ins' AS b FROM t1);
INSERT INTO t1 (security_label, a, b) VALUES ('invalid label', 99, 'zzz');	-- to be failed
INSERT INTO t1 (security_label, a, b) VALUES ('system_u:object_r:sepgsql_table_t:s0:c99', 99, 'zzz');	-- to be failed
SELECT security_label, * FROM t1;

INSERT INTO t2 (security_label, x, y) (SELECT security_label, a * 2, security_label || '_ins' FROM t1);
SELECT security_label, * FROM t2;

UPDATE t1 SET security_label = sepgsql_set_range(security_label, 's0:c' || a);
SELECT security_label, * FROM t1;
UPDATE t1 SET security_label = sepgsql_set_type(security_label, 'sepgsql_ro_table_t') WHERE a IN (1,3,5);

UPDATE t1 SET security_label = sepgsql_set_range(security_label, 's0:c' || (a+11));	-- partial success
SELECT security_label, * FROM t1;
UPDATE t1 SET security_label = 'invalid label';	-- to be failed

SELECT security_label, a+10 AS a, b || '_t3' INTO t3 FROM t1;
SELECT security_label, * FROM t3;

SELECT a+20 AS a, b || '_t4' INTO t4 FROM t1;
SELECT security_label, * FROM t4;

TRUNCATE t2;

COPY t2 (security_label, x, y) FROM stdin;
system_u:object_r:sepgsql_table_t:s0	1	aaa
system_u:object_r:sepgsql_table_t:s0:c1	2	bbb
system_u:object_r:sepgsql_table_t:s0:c2	3	ccc
\.

COPY t2 TO stdout;
COPY t2 (security_label, x, y) TO stdout;
COPY t2 (security_label, x, y) TO stdout CSV FORCE QUOTE security_label,y;