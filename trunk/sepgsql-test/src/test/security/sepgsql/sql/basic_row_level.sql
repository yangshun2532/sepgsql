-- Basic Row-level Access Controls
-- ====================================

SELECT sepgsql_getcon();

SELECT security_label, * FROM t1;

COPY t1 (security_label, a, b) TO stdout;

BEGIN;
UPDATE t1 SET b = b || '_updt';
SELECT security_label, * FROM t1;
ABORT;

BEGIN;
DELETE FROM t1;
SELECT security_label, * FROM t1;
ABORT;

