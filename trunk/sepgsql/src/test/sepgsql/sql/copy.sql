--@SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

-- cleanup previous tests
SET client_min_messages TO 'error';

DROP TABLE IF EXISTS t1 CASCADE;
DROP TABLE IF EXISTS t2 CASCADE;
DROP TABLE IF EXISTS t3 CASCADE;
DROP TABLE IF EXISTS t4 CASCADE;

RESET client_min_messages;

-- CREATE TABLE for COPY TO/FROM test

CREATE TABLE t1
(
	a	int,
	b	text,
	c	text
);
INSERT INTO t1 VALUES (1, 'xxx', 'aaa'), (2, 'yyy', 'bbb'), (3, 'zzz', 'ccc');

CREATE TABLE t2
(
	x	int,
	y	text,
	z	text
		AS SECURITY CONTEXT 'system_u:object_r:sepgsql_ro_table_t:s0'
);
INSERT INTO t2 VALUES (1, 'XXX', 'AAA'), (2, 'YYY', 'BBB'), (3, 'ZZZ', 'CCC');

CREATE TABLE t3
(
	s	int,
	t	text
		AS SECURITY CONTEXT 'system_u:object_r:sepgsql_fixed_table_t:s0',
	u	text
		AS SECURITY CONTEXT 'system_u:object_r:sepgsql_secret_table_t:s0'
);
INSERT INTO t3 VALUES (1, 'AAA', 'BBB'), (2, 'CCC', 'DDD'), (3, 'EEE', 'FFF');

--@SECURITY_CONTEXT=unconfined_u:unconfined_r:sepgsql_test_t:s0-s0:c0

COPY t1 TO stdout;
COPY t1 FROM stdin;
4	xyz	ddd
\.

COPY t2 TO stdout;
COPY t2 FROM stdin;	-- to be denied
\.

COPY t2 (x, y) FROM stdin;
4	XYZ
\.

COPY t3 TO stdout;	-- to be denied
COPY t3 (s, t) TO stdout;
COPY t3 FROM stdin;	-- to be denied
COPY t3 (s, t) FROM stdin;
4	GGG
\.

COPY (SELECT * FROM t2) TO stdout;
COPY (SELECT * FROM t3) TO stdout;	-- to be denied
COPY (SELECT s, t FROM t3) TO stdout;

--@SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

-- cleanups
SET client_min_messages TO 'error';

DROP TABLE IF EXISTS t1 CASCADE;
DROP TABLE IF EXISTS t2 CASCADE;
DROP TABLE IF EXISTS t3 CASCADE;

RESET client_min_messages;
