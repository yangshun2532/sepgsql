-- 
-- initial setup of tuple level access control
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
	a	integer primary key,
	b	text
);

INSERT INTO t1 VALUES	(1, 'water'),  (2, 'coke'),  (3, 'juice'),
			(4, 'coffee'), (5, 'beer'),  (6, 'wine');
INSERT INTO t2 VALUES	(1, 'red'),    (2, 'blue'),  (3, 'green'),
			(4, 'yellow'), (5, 'black'), (6, 'white');
UPDATE t1 SET security_context = sepgsql_set_range(security_context, 's0:c1')
	WHERE x IN (2, 3, 4);
UPDATE t2 SET security_context = sepgsql_set_range(security_context, 's0:c1')
	WHERE a IN (1, 4, 5);

SELECT security_context, * FROM t1;

SELECT security_context, * FROM t2;
