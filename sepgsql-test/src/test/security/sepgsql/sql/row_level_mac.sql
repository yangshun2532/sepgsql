-- Basic Row-level Access Controls
-- ====================================

SELECT sepgsql_getcon();

SELECT security_label, * FROM t1;
SELECT security_label, * FROM t2;

COPY t1 (security_label, a, b) TO stdout;
COPY t2 (security_label, x, y) TO stdout;

SELECT t1.security_label, t2.security_label, * FROM t1 JOIN t2 ON t1.a = t2.x;

BEGIN;
UPDATE t1 SET b = b || '_updt';
SELECT security_label, * FROM t1;
ABORT;

BEGIN;
DELETE FROM t2 RETURNING *;
ABORT;

INSERT INTO t1 VALUES (6, 'fff');	-- to be failed
DELETE FROM t1 WHERE a = 1;		-- to be failed
