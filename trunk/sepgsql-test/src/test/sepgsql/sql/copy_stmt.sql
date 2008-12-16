-- COPY TO/FROM statement
-- ======================

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
