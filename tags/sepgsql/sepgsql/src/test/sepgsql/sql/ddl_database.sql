--@SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

-- cleanup previous tests
SET client_min_messages TO 'error';

DROP DATABASE IF EXISTS sepgsql_regress_db_1;
DROP DATABASE IF EXISTS sepgsql_regress_db_2;
DROP DATABASE IF EXISTS sepgsql_regress_db_3;
DROP DATABASE IF EXISTS sepgsql_regress_db_4;

RESET client_min_messages;

-- CREATE DATABASE with SECURITY_CONTEXT option

CREATE DATABASE sepgsql_regress_db_1;
CREATE DATABASE sepgsql_regress_db_2
       SECURITY CONTEXT ('system_u:object_r:sepgsql_db_t:s0:c0');
CREATE DATABASE sepgsql_regress_db_3
       SECURITY CONTEXT ('system_u:object_r:sepgsql_db_t:s0:c16');	-- to be denied
CREATE DATABASE sepgsql_regress_db_4
       SECURITY CONTEXT ('invalid security context');			-- to be failed

SELECT datname, sepgsql_database_getcon(oid), datsecon FROM pg_database
       WHERE datname like 'sepgsql_regress_db_%';

-- ALTER DATABASE with SECURITY_CONTEXT option

ALTER DATABASE sepgsql_regress_db_1
      SECURITY CONTEXT TO 'system_u:object_r:sepgsql_db_t:s0:c1';
ALTER DATABASE sepgsql_regress_db_1
      SECURITY CONTEXT TO 'system_u:object_r:sepgsql_db_t:s0:c20';	-- to be deined
ALTER DATABASE sepgsql_regress_db_2
      SECURITY CONTEXT TO 'invalid security context';			-- to be failed
ALTER DATABASE sepgsql_regress_db_3
      SECURITY CONTEXT TO 'system_u:object_r:sepgsql_db_t:s0:c2';	-- no such database

SELECT datname, sepgsql_database_getcon(oid), datsecon FROM pg_database
       WHERE datname like 'sepgsql_regress_db_%'
       ORDER BY datname;

-- disallow to modify system catalog by hand

UPDATE pg_database SET datsecon = NULL
       WHERE datname like 'sepgsql_regress_db_%';			-- to be failed

-- cleanups
SET client_min_messages TO 'error';

DROP DATABASE IF EXISTS sepgsql_regress_db_1;
DROP DATABASE IF EXISTS sepgsql_regress_db_2;
DROP DATABASE IF EXISTS sepgsql_regress_db_3;
DROP DATABASE IF EXISTS sepgsql_regress_db_4;

RESET client_min_messages;
