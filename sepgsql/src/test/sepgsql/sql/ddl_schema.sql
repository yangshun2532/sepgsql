--@SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

-- Note that the current standard security policy does not contains
-- the definitions of db_schema object class (It is waiting for the
-- SE-PgSQL patch getting merged). SELinux allows all the requests
-- on the undefined object class, so we don't check any valid permission
-- checks here. It only checks default security context (inherited from
-- the db_database class) and statement support.

-- cleanup previous tests
SET client_min_messages TO 'error';

DROP SCHEMA IF EXISTS scm1 CASCADE;
DROP SCHEMA IF EXISTS scm2 CASCADE;
DROP SCHEMA IF EXISTS scm3 CASCADE;
DROP SCHEMA IF EXISTS scm4 CASCADE;
DROP SCHEMA IF EXISTS scm5 CASCADE;

RESET client_min_messages;

-- CREATE SCHEMA with SECURITY_CONTEXT option
CREATE SCHEMA scm1;
CREATE SCHEMA scm2
       CREATE TABLE t2 (a int);
CREATE SCHEMA scm3
       SECURITY CONTEXT 'system_u:object_r:sepgsql_db_t:s0:c0';
CREATE SCHEMA scm4
       SECURITY CONTEXT 'system_u:object_r:sepgsql_db_t:s0:c1'
       CREATE TABLE t4 (x int);
CREATE SCHEMA scm4
       SECURITY CONTEXT 'invalid security context';			-- to be failed

SELECT nspname, sepgsql_schema_getcon(oid), nspsecon FROM pg_namespace
       WHERE nspname in ('scm1', 'scm2', 'scm3', 'scm4', 'scm5')
       ORDER BY nspname;

-- ALTER SCHEMA with SECURITY_CONTEXT option

ALTER SCHEMA scm1
      SECURITY CONTEXT TO 'system_u:object_r:sepgsql_db_t:s0:c2';
ALTER SCHEMA scm2
      SECURITY CONTEXT TO 'invalid security context';			-- to be failed
ALTER SCHEMA scm4
      SECURITY CONTEXT TO 'system_u:object_r:sepgsql_db_t:s0:c3';	-- no such schema

SELECT nspname, sepgsql_schema_getcon(oid), nspsecon FROM pg_namespace
       WHERE nspname in ('scm1', 'scm2', 'scm3', 'scm4', 'scm5')
       ORDER BY nspname;

-- disallow to modify system catalog by hand

UPDATE pg_namespace SET nspsecon = NULL
       WHERE nspname = 'scm1';						-- to be denied

-- cleanups
SET client_min_messages TO 'error';

DROP SCHEMA IF EXISTS scm1 CASCADE;
DROP SCHEMA IF EXISTS scm2 CASCADE;
DROP SCHEMA IF EXISTS scm3 CASCADE;
DROP SCHEMA IF EXISTS scm4 CASCADE;
DROP SCHEMA IF EXISTS scm5 CASCADE;

RESET client_min_messages;
