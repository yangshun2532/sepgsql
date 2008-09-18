-- 
-- testcases for row-level access controls (weak user)
-- 
-- selinux_user: unconfined_u
-- selinux_role: unconfined_r
-- selinux_type: unconfined_t
-- selinux_range: s0

SELECT security_context, * FROM t1;

SELECT security_context, * FROM t2;

SELECT security_context, * FROM t3;

BEGIN;
UPDATE t3 SET t = t || '_updt' RETURNING security_context, *;
SELECT security_context, * FROM t3;
ROLLBACK;

BEGIN;
DELETE FROM t3 WHERE s < 12 RETURNING security_context, *;
SELECT security_context, * FROM t3;
ROLLBACK;

-- invisible PK exists
INSERT INTO t1 VALUES (8, 'green tea');

-- invisible FK referes visible PK
DELETE FROM t1 WHERE x = 3;

