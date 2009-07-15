--@SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

-- cleanup previous tests
SET client_min_messages TO 'error';

DROP DATABASE IF EXISTS test_dat_1;
DROP DATABASE IF EXISTS test_dat_2;
DROP DATABASE IF EXISTS test_dat_3;

DROP SCHEMA IF EXISTS test_nsp_1 CASCADE;
DROP SCHEMA IF EXISTS test_nsp_2 CASCADE;
DROP SCHEMA IF EXISTS test_nsp_3 CASCADE;

DROP FUNCTION IF EXISTS test_func_1(int) CASCADE;
DROP FUNCTION IF EXISTS test_func_2(int) CASCADE;
DROP FUNCTION IF EXISTS test_func_3(int) CASCADE;

RESET client_min_messages;

CREATE DATABASE test_dat_1;
SELECT datname, datseclabel FROM pg_database WHERE datname = 'test_dat_1';

CREATE DATABASE test_dat_2 SECURITY LABEL 'system_u:object_r:sepgsql_db_t:s0:c0';
SELECT datname, datseclabel FROM pg_database WHERE datname = 'test_dat_2';

CREATE DATABASE test_dat_3 SECURITY LABEL 'invalid security context';	-- to be failed

ALTER DATABASE test_dat_1
      SECURITY LABEL 'system_u:object_r:sepgsql_db_t:s0:c1';
SELECT datname, datseclabel FROM pg_database WHERE datname = 'test_dat_1';

ALTER DATABASE test_dat_2
      SECURITY LABEL 'invalid security context';	-- to be failed

CREATE SCHEMA test_nsp_1;
SELECT nspname, nspseclabel FROM pg_namespace WHERE nspname = 'test_nsp_1';

CREATE SCHEMA test_nsp_2 SECURITY LABEL 'system_u:object_r:sepgsql_db_t:s0:c0';
SELECT nspname, nspseclabel FROM pg_namespace WHERE nspname = 'test_nsp_2';

CREATE SCHEMA test_nsp_3 SECURITY LABEL 'invalid security context';	-- to be failed

ALTER SCHEMA test_nsp_1
      SECURITY LABEL 'system_u:object_r:sepgsql_db_t:s0:c1';
SELECT nspname, nspseclabel FROM pg_namespace WHERE nspname = 'test_nsp_1';

ALTER SCHEMA test_nsp_2
      SECURITY LABEL 'invalid security context';	-- to be failed

CREATE TEMP TABLE t1 (a int);
SELECT nspname, nspseclabel FROM pg_namespace WHERE nspname like 'pg_temp_%';

CREATE FUNCTION test_func_1(int) RETURNS int
       LANGUAGE 'sql' AS 'SELECT $1 + $1';
SELECT proname, proseclabel FROM pg_proc WHERE oid = 'test_func_1'::regproc;

CREATE FUNCTION test_func_2(int) RETURNS int
       LANGUAGE 'sql'
       SECURITY LABEL 'system_u:object_r:sepgsql_proc_exec_t:s0:c0'
       AS 'SELECT $1 + $1';
SELECT proname, proseclabel FROM pg_proc WHERE oid = 'test_func_2'::regproc;

CREATE FUNCTION test_func_3(int) RETURNS int
       LANGUAGE 'sql'
       SECURITY LABEL 'invalid security context'
       AS 'SELECT $1 + $1';				-- to be failed

ALTER FUNCTION test_func1(int)
      SECURITY LABEL 'system_u:object_r:sepgsql_proc_exec_t:s0:c1';

ALTER FUNCTION test_func2(int)
      SECURITY LABEL 'invalid security context'		-- to be failed
