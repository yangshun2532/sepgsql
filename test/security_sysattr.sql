-- =================== security_sysattr.sql ===================
-- This test pattern checks accesses security attribute
-- of each tuples via security_context system column.

-- INITIAL SETUPS
DROP TABLE t1;
DROP TABLE t2;
DROP TABLE t3;

CREATE TABLE t1 (
       x     integer,
       y     text
);

CREATE TABLE t2 (
       a     integer,
       b     float
);

INSERT INTO t1 VALUES (1, 'aaa'), (2, 'bbb'), (3, 'ccc'),
       	       	      (4, 'ddd'), (5, 'eee'), (6, 'fff');
INSERT INTO t2 VALUES (2, 0.22), (3, 0.33), (5, 0.55);

-- TEST: (01) obtain security_sysattr_name
SHOW security_sysattr_name;

-- TEST: (02) access security_context via SELECT
SELECT security_context, * FROM t1;

SELECT '(' || security_context::text || ')', * FROM t1;

SELECT t1.security_context, t2.security_context, * FROM t1, t2;

SELECT security_context::text || y FROM t1;

-- TEST: (03) access security_context via COPY
COPY t1 TO stdout;

COPY t1 (security_context, x, y) TO stdout;

-- TEST: (04) update security_context via UPDATE
UPDATE t1 SET security_context = 'system_u:object_r:sepgsql_table_t:s0:c0' WHERE x in (2, 3);
SELECT security_context, * FROM t1;

UPDATE t1 SET security_context = security_context::text || ':c1' WHERE x in (4, 5);
SELECT security_context, * FROM t1;

-- TEST: (05) insert a tuple with explicit labeling
INSERT INTO t1 (security_context, x, y)
       VALUES ('system_u:object_r:sepgsql_table_t:s0:c3', 7, 'ggg')
       VALUES ('system_u:object_r:sepgsql_table_t:s0:c3', 8, 'hhh');
SELECT security_context, * FROM t1;

-- TEST: (06) SELECT INTO with explicit labeling
SELECT security_context, * INTO t3 FROM t1 WHERE x in (2, 5, 6);
SELECT security_context, * FROM t3;
DROP TABLE t3;

-- TEST: (07) CREATE TABLE AS with explicit labeling
CREATE TABLE t3 AS SELECT security_context, x AS v, y AS w FROM t1;
SELECT security_context, * FROM t3;
DROP TABLE t3;
CREATE TABLE t3 AS SELECT security_context AS z, * FROM t1;
SELECT security_context, * FROM t3;
DROP TABLE t3;

-- CLEANUPS
DROP TABLE t1;
DROP TABLE t2;