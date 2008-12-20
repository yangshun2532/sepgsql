-- PK/FK constraint test
-- =====================

SELECT sepgsql_getcon();

SELECT security_label, * FROM t1;
SELECT security_label, * FROM t2;
SELECT security_label, * FROM t3;
SELECT security_label, * FROM t4;

INSERT INTO t1 VALUES (4, 'ddd');	-- to be failed
INSERT INTO t1 VALUES (5, 'eee');

INSERT INTO t3 VALUES (2);
INSERT INTO t3 VALUES (3);	-- to be failed

DELETE FROM t1 WHERE x = 5 RETURNING *;
DELETE FROM t1 WHERE x = 2 RETURNING *;	-- to be failed

UPDATE t2 SET x = x + 10 RETURNING *;	-- to be failed
UPDATE t2 SET x = x + 10 WHERE x = 2 RETURNING *;

DELETE FROM t2 WHERE x = 1 RETURNING *;	-- to be failed
DELETE FROM t2 WHERE x = 12 RETURNING *;