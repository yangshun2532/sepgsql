--
-- Initial setup of SE-PostgreSQL testcases
--
-- selinux_user: unconfined_u
-- selinux_role: unconfined_r
-- selinux_type: unconfined_t
-- selinux_range: s0-s0:c0.c15

-- -------------------------------------------------------
-- Test B : Row-Level Access Control
-- -------------------------------------------------------

CREATE TABLE b1
(
	x	integer primary key,
	y	text
);

CREATE TABLE b2
(
	a	integer primary key,
	b	text
);

INSERT INTO b1 VALUES	(1, 'water'),  (2, 'coke'),  (3, 'juice'),
			(4, 'coffee'), (5, 'beer'),  (6, 'wine');
INSERT INTO b2 VALUES	(1, 'red'),    (2, 'blue'),  (3, 'green'),
			(4, 'yellow'), (5, 'black'), (6, 'white');
UPDATE b1 SET security_context = sepgsql_set_range(security_context, 's0:c1')
	WHERE x IN (3, 4);
UPDATE b1 SET security_context = sepgsql_set_type(security_context, 'sepgsql_fixed_table_t')
	WHERE x IN (2, 3);
UPDATE b2 SET security_context = sepgsql_set_range(security_context, 's0:c1')
	WHERE a IN (4, 5);
UPDATE b2 SET security_context = sepgsql_set_type(security_context, 'sepgsql_ro_table_t')
	WHERE a IN (5, 6);

SELECT security_context, * FROM b1;

SELECT security_context, * FROM b2;

-- -------------------------------------------------------
-- Test C : Column-Level Access Control
-- -------------------------------------------------------

CREATE TABLE c1
(
	a  INTEGER
	   SECURITY_CONTEXT = 'system_u:object_r:sepgsql_secret_table_t:s0',
	b  TEXT,
	c  TEXT
) SECURITY_CONTEXT = 'system_u:object_r:sepgsql_ro_table_t:s0';

SELECT security_context, relname FROM pg_class
       WHERE relname ='c1' and relnamespace = 2200;

SELECT security_context, attname FROM pg_attribute
       WHERE attrelid in (SELECT oid FROM pg_class WHERE relname ='c1' and relnamespace = 2200);

CREATE TABLE c2
(
	a	TEXT,
	b	TEXT,
	c	TEXT,
	d	TEXT
);

ALTER TABLE c2 ALTER b SECURITY_CONTEXT = 'system_u:object_r:sepgsql_ro_table_t:s0';
ALTER TABLE c2 ALTER c SECURITY_CONTEXT = 'system_u:object_r:sepgsql_secret_table_t:s0';
ALTER TABLE c2 ALTER d SECURITY_CONTEXT = 'system_u:object_r:sepgsql_fixed_table_t:s0';

SELECT security_context, relname FROM pg_class
       WHERE relname ='c2' and relnamespace = 2200;

SELECT security_context, attname FROM pg_attribute
       WHERE attrelid in (SELECT oid FROM pg_class WHERE relname ='c2' and relnamespace = 2200);

-- -------------------------------------------------------
-- Test D : PK/FK constraint
-- -------------------------------------------------------

CREATE TABLE d1 (
       id     integer primary key,
       name   text
);

CREATE TABLE d2 (
       id    integer references d1(id),
       tag   text
);

INSERT INTO d1 VALUES (1, 'aaa'), (2, 'bbb'), (3, 'ccc'), (4, 'ddd');

INSERT INTO d2 VALUES (2, 'xxx'), (3, 'yyy'), (4, 'zzz');

UPDATE d1 SET security_context = sepgsql_set_range(security_context, 's0:c1')
       WHERE id IN (2, 3);
UPDATE d2 SET security_context = sepgsql_set_range(security_context, 's0:c1')
       WHERE id IN (3, 4);

-- -------------------------------------------------------
-- Test E : Trusted Procedure
-- -------------------------------------------------------

CREATE TABLE e1 (
       id    integer primary key,
       tag   text
       	     SECURITY_CONTEXT = 'system_u:object_r:sepgsql_secret_table_t:s0'
);
INSERT INTO e1 VALUES (10, 'abcd'), (20, 'efgh');

CREATE OR REPLACE FUNCTION e2 (integer) RETURNS text
       LANGUAGE 'sql'
       SECURITY_CONTEXT = 'system_u:object_r:sepgsql_trusted_proc_exec_t:s0'
       AS 'SELECT tag FROM e1 WHERE id = $1';

CREATE OR REPLACE FUNCTION e3 () RETURNS text
       LANGUAGE 'sql'
       SECURITY_CONTEXT = 'system_u:object_r:sepgsql_trusted_proc_exec_t:s0'
       AS 'SELECT sepgsql_getcon()';

-- -------------------------------------------------------
-- Test F : Large Object
-- -------------------------------------------------------

SELECT lo_import('/tmp/sepgsql_test_blob', 6001);
SELECT lo_import('/tmp/sepgsql_test_blob', 6002);
SELECT lo_import('/tmp/sepgsql_test_blob', 6003);

SELECT lo_set_security(6001, 'system_u:object_r:sepgsql_blob_t:s0');
SELECT lo_set_security(6002, 'system_u:object_r:sepgsql_ro_blob_t:s0');
SELECT lo_set_security(6003, 'system_u:object_r:sepgsql_secret_blob_t:s0');

-- -------------------------------------------------------
-- Test G : Copy To/From
-- -------------------------------------------------------

CREATE TABLE g1 (
       a     integer,
       b     text
);

COPY g1 (security_context, a, b) FROM stdin;
system_u:object_r:sepgsql_table_t:s0	1	aaa
system_u:object_r:sepgsql_table_t:s0:c0	2	bbb
system_u:object_r:sepgsql_table_t:s0	3	ccc
system_u:object_r:sepgsql_table_t:s0:c1	4	ddd
system_u:object_r:sepgsql_table_t:s0:c0	5	eee
system_u:object_r:sepgsql_table_t:s0	6	fff
system_u:object_r:sepgsql_table_t:s0:c1	7	ggg
\.

CREATE TABLE g2 (
       x     integer,
       y     text SECURITY_CONTEXT = 'system_u:object_r:sepgsql_ro_table_t:s0',
       z     text SECURITY_CONTEXT = 'system_u:object_r:sepgsql_secret_table_t:s0'
);

COPY g2 FROM stdin;
1	aaa	AAA
2	bbb	BBB
3	ccc	CCC
4	ddd	DDD
\.

-- -------------------------------------------------------
-- Test H : Set Operations/With Recursive
-- -------------------------------------------------------

CREATE TABLE h1 (
	id	integer primary key,
	pid	integer references h1(id),
	name	text
);

CREATE TABLE h2 (
	s	integer SECURITY_CONTEXT = 'system_u:object_r:sepgsql_secret_table_t:s0',
	t	integer
);

CREATE TABLE h3 (
	a	integer,
	b	text
);

CREATE TABLE h4 (
	x	integer,
	y	text
);

COPY h1 (security_context,id,pid,name) FROM stdin;
system_u:object_r:sepgsql_table_t:s0	0	\N	/
system_u:object_r:sepgsql_table_t:s0	1	0	/a
system_u:object_r:sepgsql_table_t:s0	11	1	/a/a
system_u:object_r:sepgsql_table_t:s0	111	11	/a/a/a
system_u:object_r:sepgsql_table_t:s0:c1	112	11	/a/a/b
system_u:object_r:sepgsql_table_t:s0	113	11	/a/a/c
system_u:object_r:sepgsql_table_t:s0:c1	12	1	/a/b
system_u:object_r:sepgsql_table_t:s0	121	12	/a/b/a
system_u:object_r:sepgsql_table_t:s0	122	12	/a/b/c
system_u:object_r:sepgsql_table_t:s0:c1	2	0	/b
system_u:object_r:sepgsql_table_t:s0	21	2	/b/a
system_u:object_r:sepgsql_table_t:s0	22	2	/b/b
\.

COPY h3 (security_context,a,b) FROM stdin;
system_u:object_r:sepgsql_table_t:s0	1	aaa
system_u:object_r:sepgsql_table_t:s0	2	bbb
system_u:object_r:sepgsql_table_t:s0:c1	3	ccc
system_u:object_r:sepgsql_table_t:s0:c1	4	ddd
system_u:object_r:sepgsql_table_t:s0	5	eee
system_u:object_r:sepgsql_table_t:s0:c1	6	fff
\.

COPY h4 (security_context,x,y) FROM stdin;
system_u:object_r:sepgsql_table_t:s0:c1	1	aaa
system_u:object_r:sepgsql_table_t:s0	2	bbb
system_u:object_r:sepgsql_table_t:s0	3	ccc
system_u:object_r:sepgsql_table_t:s0:c1	4	ddd
system_u:object_r:sepgsql_table_t:s0	5	eee
system_u:object_r:sepgsql_table_t:s0	6	fff
\.
