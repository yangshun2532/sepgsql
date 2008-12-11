-- 
-- SE-PostgreSQL testcases : row-level access control
-- 
-- selinux_user: unconfined_u
-- selinux_role: unconfined_r
-- selinux_type: sepgsql_test_t
-- selinux_range: s0:c0

-- SELECT, COPY
SELECT security_context, * FROM b1;
SELECT security_context, * FROM b2;

COPY b1 TO stdout;
COPY b2(security_context,a,b) TO stdout;

-- TABLE JOIN
SELECT * FROM b1 JOIN b2 ON b1.x = b2.a;

SELECT * FROM b1 LEFT OUTER JOIN b2 ON b1.x = b2.a;

SELECT * FROM b1 RIGHT OUTER JOIN b2 ON b1.x = b2.a;

SELECT * FROM b1 FULL OUTER JOIN b2 ON b1.x = b2.a;

-- UPDATE
UPDATE b1 SET y = y || '_updated' RETURNING security_context, *;
SELECT security_context, * FROM b1;

-- DELETE
DELETE FROM b2 RETURNING security_context, *;
SELECT security_context, * FROM b2;

-- INSERT
INSERT INTO b1 VALUES (10, 'soda');

INSERT INTO b2 VALUES (10, 'orange');
