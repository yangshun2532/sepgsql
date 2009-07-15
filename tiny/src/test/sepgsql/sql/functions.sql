--@SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

-- cleanup previous tests
SET client_min_messages TO 'error';

DROP FUNCTION IF EXISTS test_func_1(int) CASCADE;
DROP FUNCTION IF EXISTS test_func_2(int) CASCADE;

RESET client_min_messages;
-- setup test object

CREATE OR REPLACE FUNCTION test_func_1(int) RETURNS int
       LANGUAGE 'sql'
       SECURITY LABEL 'system_u:object_r:sepgsql_proc_exec_t:s0'
       AS 'SELECT $1 + 1';

CREATE OR REPLACE FUNCTION test_func_2(int) RETURNS int
       LANGUAGE 'sql'
       SECURITY LABEL 'system_u:object_r:sepgsql_proc_exec_t:s0:c0'
       AS 'SELECT $1 + 2';

SELECT test_func_1(10);
SELECT test_func_2(10);

--@SECURITY_CONTEXT=unconfined_u:unconfined_r:sepgsql_test_t:s0
SELECT test_func_1(10);
SELECT test_func_2(10);			-- to be failed
