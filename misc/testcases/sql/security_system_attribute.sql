-- 
-- testcases for security system attribute
-- 
-- selinux_user: unconfined_u
-- selinux_role: unconfined_r
-- selinux_type: unconfined_t
-- selinux_range: s0-s0:c0.c15

-- initial setups
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

-- access security_context via SELECT
SELECT security_context, * FROM t1;

SELECT '(' || security_context::text || ')', * FROM t1;

SELECT security_context::text || y FROM t1;

-- access security_context via COPY
COPY t1 TO stdout;

COPY t1 (security_context, x, y) TO stdout;

-- update security_context via UPDATE
UPDATE t1 SET security_context = 'system_u:object_r:sepgsql_table_t:s0:c0'
       WHERE x in (2, 3);
UPDATE t1 SET security_context = sepgsql_set_range(security_context, 's0:c1')
       WHERE x in (1, 5);
UPDATE t1 SET security_context = security_context || ':c2'
       WHERE x in (4, 6);
SELECT security_context, * FROM t1;

UPDATE t2 SET security_context = sepgsql_set_type(security_context, 'sepgsql_ro_table_t');
SELECT t1.security_context, t2.security_context, * FROM t1, t2;

-- insert a tuple with explicit labeling
INSERT INTO t1 (security_context, x, y)
       VALUES ('unconfined_u:object_r:sepgsql_table_t:s0:c3', 7, 'ggg'),
       	      ('unconfined_u:object_r:sepgsql_table_t:s0:c3', 8, 'hhh');
SELECT security_context, * FROM t1;

-- SELECT INTO with explicit labeling
SELECT security_context, * INTO t3 FROM t1 WHERE x in (2, 5, 6);
SELECT security_context, * FROM t3;

-- CREATE TABLE AS with explicit labeling
CREATE TABLE t4 AS SELECT security_context, x AS v, y AS w FROM t1;
SELECT security_context, * FROM t3;
CREATE TABLE t5 AS SELECT security_context AS z, * FROM t1;
SELECT security_context, * FROM t3;

-- cleanups
DROP TABLE t1;
DROP TABLE t2;
DROP TABLE t3;
DROP TABLE t4;
DROP TABLE t5;