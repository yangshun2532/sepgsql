-- Basic column-level access controls
-- ==================================

SELECT sepgsql_getcon();

SELECT * FROM t1;	-- to be failed

SELECT a, b FROM t1;

SELECT a, b FROM t1 WHERE c = 'abc';	-- to be failed

SELECT a, b FROM t1 WHERE c is null;	-- to be failed

SELECT a, b FROM t1 ORDER BY c;		-- to be failed

UPDATE t1 SET a = 4, b = 'ddd', c = '1234-5678-9012';	-- to be failed

UPDATE t1 SET a = 4, b = 'ddd';		-- to be failed

UPDATE t1 SET a = 4 WHERE b = 'bbb';

SELECT security_label, * FROM t1;

INSERT INTO t1 (a, b, c) VALUES (5, 'eee', '1234-5678-9012');	-- to be failed

INSERT INTO t1 (a, b) VALUES (5, 'eee');	-- to be failed

INSERT INTO t1 (a) VALUES (5);

SELECT security_label, a, b FROM t1;

DELETE FROM t1 RETURNING a, b, c;		-- to be failed

BEGIN;
DELETE FROM t1 RETURNING a, b;
ABORT;

BEGIN;
DELETE FROM t1 RETURNING a;
ABORT;

SELECT a, b, f1(a) FROM t1;