-- 
-- testcases for row-level access controls (cleanups)
-- 
-- selinux_user: unconfined_u
-- selinux_role: unconfined_r
-- selinux_type: unconfined_t
-- selinux_range: s0-s0:c0.c15

DROP TABLE t3;
DROP TABLE t2;
DROP TABLE t1;
