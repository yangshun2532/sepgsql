-- 
-- testcases for row-level access controls (initial setup)
-- 
-- selinux_user: unconfined_u
-- selinux_role: unconfined_r
-- selinux_type: unconfined_t
-- selinux_range: s0-s0:c0.c15

CREATE TABLE t1
(
	x	integer primary key,
	y	text
);

CREATE TABLE t2
(
	a	integer references t1(x),	
	b	text
);

CREATE TABLE t3
(
	s	integer,
	t	text
);

INSERT INTO t1 VALUES	(1, 'water'), (2, 'coke'), (3, 'juice'), (4, 'coffee'),
       	       		(5, 'sake'), (6, 'beer'), (7, 'wine'), (8, 'red tea');
INSERT INTO t2 VALUES	(2, 'aaa'), (3, 'bbb'), (4, 'ccc');
INSERT INTO t3 VALUES	(10, 'red'), (11, 'green'), (12, 'blue'), (13, 'orange'),
       	       		(14, 'yellow'), (15, 'white'), (16, 'black');

UPDATE t1 SET security_context = sepgsql_set_range(security_context, 's0:c0')
       WHERE x IN (2, 4, 6, 8);
UPDATE t2 SET security_context = sepgsql_set_range(security_context, 's0:c0')
       WHERE a IN (2, 3);
UPDATE t3 SET security_context = sepgsql_set_range(security_context, 's0:c0')
       WHERE s IN (10, 13, 14);
UPDATE t3 SET security_context = sepgsql_set_range(security_context, 's0:c1')
       WHERE s IN (15, 16);

SELECT security_context, * FROM t1;

SELECT security_context, * FROM t2;

SELECT security_context, * FROM t3;
