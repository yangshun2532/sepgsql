--@SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

-- cleanup previous tests
SET client_min_messages TO 'error';

DROP TABLE IF EXISTS t4 CASCADE;
DROP TABLE IF EXISTS t3 CASCADE;
DROP TABLE IF EXISTS t2 CASCADE;
DROP TABLE IF EXISTS t1 CASCADE;

DROP FUNCTION IF EXISTS f1(int) CASCADE;
DROP FUNCTION IF EXISTS f2(int) CASCADE;

RESET client_min_messages;

-- CREATE TABLE with SECURITY_LABEL clause
CREATE TABLE t1 (
       a int,
       b text
);
SELECT security_label, relname FROM pg_class WHERE oid = 't1'::regclass;
SELECT security_label, attname FROM pg_attribute WHERE attrelid = 't1'::regclass and attnum > 0;

CREATE TABLE t2 (
       a int,
       b text
) SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_ro_table_t:s0';
SELECT security_label, relname FROM pg_class WHERE oid = 't2'::regclass;
SELECT security_label, attname FROM pg_attribute WHERE attrelid = 't2'::regclass and attnum > 0;

CREATE TABLE t3 (
       a int,
       b text SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_fixed_table_t:s0',
       c bool SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_secret_table_t:s0',
       d int
) SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_table_t:s0:c0';
SELECT security_label, relname FROM pg_class WHERE oid = 't3'::regclass;
SELECT security_label, attname FROM pg_attribute WHERE attrelid = 't3'::regclass and attnum > 0;

CREATE TABLE t4 (
       a int,
       b text
) SECURITY_LABEL = 'unconfined_u:object_r:invalid_label_t:s0';	-- to be failed

CREATE TABLE t4 (
       a int,
       b text
) SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_proc_t:s0';	-- to be denied

-- ALTER TABLE with SECURITY_LABEL clause
ALTER TABLE t2 SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_secret_table_t:s0';
ALTER TABLE t2 ADD COLUMN c bool;	-- it inherits table's one
SELECT security_label, relname FROM pg_class WHERE oid = 't2'::regclass;
SELECT security_label, attname FROM pg_attribute WHERE attrelid = 't2'::regclass and attnum > 0;

ALTER TABLE t3 ALTER b SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_table_t:s0';
SELECT security_label, relname FROM pg_class WHERE oid = 't3'::regclass;
SELECT security_label, attname FROM pg_attribute WHERE attrelid = 't3'::regclass and attnum > 0;

-- CREATE FUNCTION with SECURITY_LABEL clause
CREATE FUNCTION f1 (int) RETURNS int
       LANGUAGE 'sql'
       SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_proc_t:s0:c0'
       AS 'SELECT $1 * 2';
SELECT security_label, proname FROM pg_proc WHERE oid = 'f1'::regproc;

CREATE FUNCTION f2 (int) RETURNS int
       LANGUAGE 'sql'
       SECURITY_LABEL = 'unconfined_u:object_r:invalid_label_t:s0'
       AS 'SELECT $1 + $1';	 -- to be failed

CREATE FUNCTION f2 (int) RETURNS int
       LANGUAGE 'sql'
       SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_proc_t:s0:c16'
       AS 'SELECT $1 + $1';	 -- to be denied

CREATE FUNCTION f2 (int) RETURNS int
       LANGUAGE 'sql'
       AS 'SELECT $1 + $1';
SELECT security_label, proname FROM pg_proc WHERE oid = 'f2'::regproc;

-- ALTER FUNCTION with SECURITY_LABEL clause
ALTER FUNCTION f1(int)
      SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_proc_t:s0:c1';
SELECT security_label, proname FROM pg_proc WHERE oid = 'f1'::regproc;

ALTER FUNCTION f2(int)
      SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_proc_t:s0:c16';	-- to be denied
SELECT security_label, proname FROM pg_proc WHERE oid = 'f2'::regproc;
