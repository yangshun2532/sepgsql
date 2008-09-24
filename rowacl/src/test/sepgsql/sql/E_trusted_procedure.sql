--
-- SE-PostgreSQL testcases : trusted procedure
--
-- selinux_user: unconfined_u
-- selinux_role: unconfined_r
-- selinux_type: sepgsql_test_t
-- selinux_range: s0

SELECT * FROM e1;	-- to be failed

SELECT id, E2(id) FROM e1;

SELECT sepgsql_getcon();

SELECT e3();
