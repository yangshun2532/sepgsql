-- 
-- testcases of tuple level access control
-- 
-- selinux_user: unconfined_u
-- selinux_role: unconfined_r
-- selinux_type: unconfined_t
-- selinux_range: s0:c0

-- SELECT, COPY
SELECT security_context, * FROM t1;
SELECT security_context, * FROM t2;

COPY t1 TO stdout;
COPY t2 TO stdout;

-- TABLE JOIN
SELECT * FROM t1 JOIN t2 ON t1.x = t2.a;

SELECT * FROM t1 LEFT OUTER JOIN t2 ON t1.x = t2.a;

SELECT * FROM t1 RIGHT OUTER JOIN t2 ON t1.x = t2.a;

SELECT * FROM t1 FULL OUTER JOIN t2 ON t1.x = t2.a;

-- UPDATE
UPDATE t1 SET y = y || '_updated' RETURNING security_context, *;
SELECT security_context, * FROM t1;

-- DELETE
DELETE FROM t2;
SELECT security_context, * FROM t2;

-- INSERT
INSERT INTO t1 VALUES (10, 'soda');

INSERT INTO t2 VALUES (10, 'orange');
