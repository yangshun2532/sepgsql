--
-- SE-PostgreSQL testcases : COPY FROM/TO statement
--
-- selinux_user: unconfined_u
-- selinux_role: unconfined_r
-- selinux_type: sepgsql_test_t
-- selinux_range: s0:c0

-- simple copy to
COPY g1 TO stdout;
COPY g2 TO stdout;	-- to be failed

-- column specified copy to
COPY g1 (security_context, a, b) TO stdout;
COPY g2 (security_context, x, y) TO stdout;
COPY g2 (security_context, x, z) TO stdout;	-- to be failed

-- copy to/from file
COPY g1 TO '/tmp/sepgsql_test_copy';		-- to be failed
COPY g1 FROM '/tmp/sepgsql_test_copy';		-- to be failed

-- copy from
COPY g1 FROM stdin;
24	xxx
25	yyy
\.

COPY g2 FROM stdin;		-- to be failed
COPY g2 (x, y) FROM stdin;	-- to be failed
COPY g2 (x) FROM stdin;
99
98
97
\.
