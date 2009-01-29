:SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

SELECT sepgsql_getcon();

-- cleanup previous tests
SET client_min_messages TO 'error';

DROP TABLE IF EXISTS t1 CASCADE;
DROP TABLE IF EXISTS t2 CASCADE;

RESET client_min_messages;

CREATE TABLE t1
(
	a	int,
	b	text
);

COPY t1 (security_label, a, b) FROM stdin;
system_u:object_r:sepgsql_table_t:s0	1	aaa
system_u:object_r:sepgsql_table_t:s0:c0	2	bbb
system_u:object_r:sepgsql_table_t:s0:c1	3	ccc
system_u:object_r:sepgsql_table_t:s0	4	ddd
system_u:object_r:sepgsql_table_t:s0:c0	5	eee
system_u:object_r:sepgsql_table_t:s0:c1	6	fff
\.

COPY t1 (security_label, a, b) TO stdout;
COPY t1 (security_label, a, b) TO '/tmp/sepgsql_test_copy_1';
COPY t1 (security_label, a, b) TO '/tmp/sepgsql_test_copy_2';

CREATE TABLE t2
(
	x	int,
	y	text
		SECURITY_LABEL = 'system_u:object_r:sepgsql_ro_table_t:s0',
	z	text
		SECURITY_LABEL = 'system_u:object_r:sepgsql_secret_table_t:s0'
);

COPY t2 FROM stdin;
1	xxx	red
2	yyy	blue
3	zzz	green
\.

:SECURITY_CONTEXT=unconfined_u:unconfined_r:sepgsql_test_t:s0-s0:c0

SELECT sepgsql_getcon();

COPY t1 TO stdout;
COPY t2 TO stdout;	-- to be failed

COPY t1 (security_label, a, b) TO stdout;
COPY t2 (security_label, x, y) TO stdout;
COPY t2 (security_label, y, z) TO stdout;	-- to be failed

COPY t1 FROM stdin;
98	yyy
99	zzz
\.

COPY t1 (security_label, a, b) FROM stdin;
system_u:object_r:sepgsql_table_t:s0	97	xxx
\.
COPY t2 (security_label, x, y) FROM stdin;	-- to be failed

COPY t1 (security_label, a, b) FROM '/tmp/sepgsql_test_copy_1';	-- to be failed
COPY t1 (security_label, a, b) FROM '/tmp/sepgsql_test_copy_2';	-- partial success
COPY t1 (security_label, a, b) TO stdout;
