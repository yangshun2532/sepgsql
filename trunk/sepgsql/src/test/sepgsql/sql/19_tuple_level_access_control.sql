-- 
-- cleanup of tuple level access control
-- 
-- selinux_user: unconfined_u
-- selinux_role: unconfined_r
-- selinux_type: unconfined_t
-- selinux_range: s0-s0:c0.c15

-- see the result of UPDATE/DELETE
SELECT security_context, * FROM t1;

SELECT security_context, * FROM t2;

DROP TABLE t2;
DROP TABLE t1;
