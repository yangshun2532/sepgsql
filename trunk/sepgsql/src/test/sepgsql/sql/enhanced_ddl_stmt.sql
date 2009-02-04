--@SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

-- cleanup previous tests
SET client_min_messages TO 'error';

DROP TABLE IF EXISTS t4 CASCADE;
DROP TABLE IF EXISTS t3 CASCADE;
DROP TABLE IF EXISTS t2 CASCADE;
DROP TABLE IF EXISTS t1 CASCADE;

DROP FUNCTION IF EXISTS f1(int,int) CASCADE;
DROP FUNCTION IF EXISTS f2(int,int) CASCADE;

RESET client_min_messages;

-- CREATE TABLE with SECURITY_LABEL clause
CREATE TABLE t1 (
       a int,
       b text
);
SELECT sepgsql_table_getcon('t1');
SELECT sepgsql_column_getcon('t1', 'a');
SELECT sepgsql_column_getcon('t1', 'b');

CREATE TABLE t2 (
       a int,
       b text
) SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_ro_table_t:s0';
SELECT sepgsql_table_getcon('t2');
SELECT sepgsql_column_getcon('t2', 'a');
SELECT sepgsql_column_getcon('t2', 'b');

CREATE TABLE t3 (
       a int,
       b text SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_fixed_table_t:s0',
       c bool SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_secret_table_t:s0',
       d int
) SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_table_t:s0:c0';
SELECT sepgsql_table_getcon('t3');
SELECT sepgsql_column_getcon('t3', 'a');
SELECT sepgsql_column_getcon('t3', 'b');
SELECT sepgsql_column_getcon('t3', 'c');
SELECT sepgsql_column_getcon('t3', 'd');

CREATE TABLE t4 (
       a int,
       b text
) SECURITY_LABEL = 'unconfined_u:object_r:invalid_label_t:s0';	-- to be failed

CREATE TABLE t4 (
       a int,
       b text
) SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_proc_t:s0';	-- to be denied

-- ALTER TABLE with SECURITY_LABEL clause
ALTER TABLE t2 SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_ro_table_t:s0';
ALTER TABLE t2 ADD COLUMN c bool;
SELECT sepgsql_table_getcon('t2');
SELECT sepgsql_column_getcon('t2', 'a');	-- keep previous setting
SELECT sepgsql_column_getcon('t2', 'c');	-- new column inherits table's one

ALTER TABLE t3 ALTER b SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_table_t:s0';
SELECT sepgsql_table_getcon('t3');
SELECT sepgsql_column_getcon('t3', 'a');
SELECT sepgsql_column_getcon('t3', 'b');

-- CREATE FUNCTION with SECURITY_LABEL clause
CREATE FUNCTION f1 (int, int) RETURNS int
       LANGUAGE 'sql'
       SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_proc_t:s0:c0'
       AS 'SELECT $1 + $2';
SELECT sepgsql_procedure_getcon('f1');

CREATE FUNCTION f2 (int, int) RETURNS int
       LANGUAGE 'sql'
       SECURITY_LABEL = 'unconfined_u:object_r:invalid_label_t:s0'
       AS 'SELECT $1 - $2';	 -- to be failed

CREATE FUNCTION f2 (int, int) RETURNS int
       LANGUAGE 'sql'
       SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_proc_t:s0:c16'
       AS 'SELECT $1 - $2';	 -- to be denied

CREATE FUNCTION f2 (int, int) RETURNS int
       LANGUAGE 'sql'
       AS 'SELECT $1 - $2';
SELECT sepgsql_procedure_getcon('f2');

-- ALTER FUNCTION with SECURITY_LABEL clause
ALTER FUNCTION f1(int, int)
      SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_proc_t:s0:c1';
SELECT sepgsql_procedure_getcon('f1');

ALTER FUNCTION f2(int, int)
      SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_proc_t:s0:c16';	-- to be denied
SELECT sepgsql_procedure_getcon('f2');
