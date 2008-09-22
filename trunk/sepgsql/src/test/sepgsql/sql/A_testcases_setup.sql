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
-- Test F : Extended SQL Grammer
-- -------------------------------------------------------


-- -------------------------------------------------------
-- Test G : Large Object
-- -------------------------------------------------------
