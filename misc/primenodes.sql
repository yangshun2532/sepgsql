-- =================== primenodes.sql ===================
-- This test checks whether any primenodes are checked in
-- SE-PostgreSQL module.

-- INITIAL SETUP
DROP TABLE t1;
CREATE TABLE t1 (
       x integer,
       y text,
       z boolean
);

DROP TABLE t2;
CREATE TABLE t2 (
       a integer,
       b integer,
       c text
);

DROP TABLE t3;
CREATE TABLE t3 (
       n integer,
       m text
);

DROP TABLE t4;
CREATE TABLE t4 (
       i integer[],
       j text
);

INSERT INTO t1 VALUES(1, 'aaa', true), (2, 'bbb', false), (3, 'ccc', true),
       	       	     (4, 'ddd', null), (5, 'eee', true), (6, 'fff', null),
		     (7, 'ggg', false), (8, 'hhh', true);
INSERT INTO t2 VALUES(0, 1, 'car'), (2, 2, 'train'), (4, 3, 'plane'), (6, 4, 'ship');
INSERT INTO t3 VALUES(1, 'one'), (3, 'three'), (5, 'five'), (7, 'seven'), (9, 'nine');
INSERT INTO t4 VALUES('{1,3,5,7,9}', 'red'), ('{2,4,6,8}', 'blue'), ('{1,2,3,4}', 'yellow');

-- TEST: (01) T_Var
SELECT x, y FROM t1;
SELECT y, (SELECT b FROM t2 where a = t1.x) from t1;

-- TEST: (02) T_Const
SELECT x FROM t1 WHERE y = 'aaa';

-- TEST: (03) T_FuncExpr
SELECT n, POSITION('e' IN m) FROM t3;

-- TEST: (04) T_AggRef
SELECT SUM(x) FROM t1;
SELECT COUNT(y) FROM t1;

-- TEST: (05) T_CoalesceExpr
SELECT a, b, COALESCE(a, b) FROM t2;

-- TEST: (06) T_NullIfExpr
SELECT a, b, NULLIF(a, b) FROM t2;

-- TEST: (07) T_OpExpr
SELECT x, y, x || y FROM t1;

-- TEST: (08) T_ArrayRef
SELECT i[2], j FROM t4;
SELECT i[2:3], j FROM t4;

-- TEST: (09) T_DistinctExpr
SELECT * FROM t2 WHERE a IS DISTINCT FROM b;
SELECT * FROM t2 WHERE a IS NOT DISTINCT FROM b;

-- TEST: (10) T_BooleanTest
SELECT * FROM t1 WHERE z IS TRUE;
SELECT * FROM t1 WHERE z IS NOT TRUE;
SELECT * FROM t1 WHERE z IS FALSE;
SELECT * FROM t1 WHERE z IS NOT FALSE;
SELECT * FROM t1 WHERE z IS UNKNOWN;
SELECT * FROM t1 WHERE z IS NOT UNKNOWN;

-- TEST: (11) T_ScalarArrayOpExpr
SELECT * FROM t1 WHERE y IN ('aaa', 'bbb', 'ddd');

-- TEST: (12) T_NullTest
SELECT * FROM t1 WHERE z IS NULL;
SELECT * FROM t1 WHERE z IS NOT NULL;

-- TEST: (13) T_BoolExpr
SELECT * FROM t1 WHERE y = 'aaa' AND z = true;
SELECT * FROM t1 WHERE y = 'bbb' OR y = 'eee';
SELECT * FROM t1 WHERE NOT y = 'ccc';

-- TEST: (14) T_SubLink/T_RowCompareExpr
SELECT a, (SELECT x FROM t1 WHERE y = t2.c) FROM t2;
SELECT ROW(2, 'bbb') = ANY (SELECT a, c FROM t2 );

-- TEST: (15) 
SELECT * FROM t1 WHERE EXISTS(SELECT * FROM t2 WHERE a = t1.x);
SELECT * FROM t1 WHERE NOT EXISTS(SELECT * FROM t2 WHERE a = t1.x);
SELECT * FROM t1 WHERE x IN(SELECT a FROM t2 WHERE c = t1.y);
SELECT * FROM t1 WHERE x NOT IN(SELECT a FROM t2 WHERE c = t1.y);
SELECT * FROM t1 WHERE x = ANY(SELECT a FROM t2 WHERE a = t1.x);
SELECT * FROM t1 WHERE x > ALL (SELECT a FROM t2 WHERE a = t1.x);

-- TEST: (16)
SELECT CASE WHEN y = 'bbb' THEN 'case-a'
          WHEN 5 > 10 THEN 'case-b'
	       ELSE 'case-c'
	       END FROM t1;
SELECT CASE x
     WHEN 1 THEN 'case-a'
          WHEN 2 THEN 'case-b'
	       ELSE 'case-c'
	       END FROM t1;

-- TEST: (17) any other contribution packages
SELECT GREATEST(a, b) FROM t2;
SELECT LEAST(a, b) FROM t2;
-- INSERT INTO t4 VALUES(ROW(1,2,3,4), 'hoge');
-- SELECT (item).name, (item).testid, count FROM t4;
-- INSERT INTO tbl4 (item.name, item.testid, count) VALUES('aaa', 1, 100);
-- SELECT x::text, y, z FROM tbl1;
-- SELECT i_tbl1::tbl6 from i_tbl1;
-- SELECT x, y FROM tbl5;
-- select func_record(tbl_record) from tbl_record;
