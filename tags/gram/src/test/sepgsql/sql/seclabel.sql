--@SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

-- cleanup previous tests
SET client_min_messages TO 'error';

DROP DATABASE IF EXISTS d1;
DROP SCHEMA   IF EXISTS s1 CASCADE;
DROP TABLE    IF EXISTS t2 CASCADE;
DROP TABLE    IF EXISTS t1 CASCADE;
DROP SEQUENCE IF EXISTS q1 CASCADE;
DROP FUNCTION IF EXISTS f1() CASCADE;
DROP FUNCTION IF EXISTS f2() CASCADE;

RESET client_min_messages;

-- DATABASE
CREATE DATABASE d1
    SECURITY_LABEL = 'system_u:object_r:sepgsql_db_t:s0:c0';
ALTER DATABASE d1
    SECURITY_LABEL = 'system_u:object_r:sepgsql_db_t:s0:c1';
ALTER DATABASE d1
    SECURITY_LABEL = 'invalid security context';		-- to be failed
ALTER DATABASE d1
    SECURITY_LABEL = 'system_u:object_r:sepgsql_db_t:s0:c16';	-- to be denied

-- SCHEMA
CREATE SCHEMA s1
    SECURITY_LABEL = 'system_u:object_r:sepgsql_db_t:s0:c0';
ALTER SCHEMA s1
    SECURITY_LABEL = 'system_u:object_r:sepgsql_db_t:s0:c1';
ALTER SCHEMA s1
    SECURITY_LABEL = 'invalid security context';		-- to be failed
-- ALTER SCHEMA s1
--     SECURITY_LABEL = 'system_u:object_r:sepgsql_db_t:s0:c16'; -- to be denied

-- TABLE and COLUMNS
CREATE TABLE t1 (
    a   int,
    b   int,
    c   int
        SECURITY_LABEL = 'system_u:object_r:sepgsql_ro_table_t:s0'
) SECURITY_LABEL = 'system_u:object_r:sepgsql_fixed_table_t:s0';

ALTER TABLE t1 SECURITY_LABEL = 'system_u:object_r:sepgsql_table_t:s0:c0';

ALTER TABLE t1 ALTER b SECURITY_LABEL = 'system_u:object_r:sepgsql_table_t:s0:c1';

ALTER TABLE t1 ADD d int SECURITY_LABEL = 'system_u:object_r:sepgsql_table_t:s0:c2';

CREATE TABLE t2 (x int)
    SECURITY_LABEL = 'invalid security context';	-- to be failed
CREATE TABLE t2 (x int)
    SECURITY_LABEL = 'system_u:object_r:sepgsql_table_t:s0:c16';	-- to be failed
CREATE TABLE t2 (
    x int SECURITY_LABEL = 'invalid security context'	-- to be failed
);
CREATE TABLE t2 (
    x int SECURITY_LABEL = 'system_u:object_r:sepgsql_table_t:s0:c16'	-- to be failed
);

-- SEQUENCE

CREATE SEQUENCE q1
    SECURITY_LABEL = 'system_u:object_r:sepgsql_db_t:s0';
ALTER SEQUENCE q1
    SECURITY_LABEL = 'system_u:object_r:sepgsql_db_t:s0:c0';
ALTER SEQUENCE q1
    SECURITY_LABEL = 'invalid security context';	-- to be failed
-- ALTER SEQUENCE q1
--     SECURITY_LABEL = 'system_u:object_r:sepgsql_db_t:s0:c0';

-- FUNCTION

CREATE FUNCTION f1() RETURNS int LANGUAGE 'sql'
    SECURITY_LABEL = 'system_u:object_r:sepgsql_proc_exec_t:s0:c0'
    AS 'SELECT 1';
ALTER FUNCTION f1()
    SECURITY_LABEL = 'system_u:object_r:sepgsql_proc_exec_t:s0:c1';
ALTER FUNCTION f1()
    SECURITY_LABEL = 'invalid security context';	-- to be failed
ALTER FUNCTION f1()
    SECURITY_LABEL = 'system_u:object_r:sepgsql_proc_exec_t:s0:c16';	-- to be denied
