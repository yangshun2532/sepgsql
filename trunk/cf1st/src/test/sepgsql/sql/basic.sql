--@SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

-- cleanup previous tests
SET client_min_messages TO 'error';

DROP TABLE IF EXISTS t1 CASCADE;
DROP TABLE IF EXISTS t2 CASCADE;
DROP TABLE IF EXISTS t3 CASCADE;
DROP TABLE IF EXISTS t4 CASCADE;

DROP FUNCTION IF EXISTS f1(int) CASCADE;

RESET client_min_messages;

-- SETUP

CREATE TABLE t1
(
    a   int,
    b   int
        SECURITY_LABEL = 'system_u:object_r:sepgsql_fixed_table_t:s0',
    c   int
        SECURITY_LABEL = 'system_u:object_r:sepgsql_ro_table_t:s0',
    d   int
        SECURITY_LABEL = 'system_u:object_r:sepgsql_secret_table_t:s0'
);

INSERT INTO t1 VALUES (1,2,3,4), (5,6,7,8);

CREATE TABLE t2
(
    x   int,
    y   int
) SECURITY_LABEL = 'system_u:object_r:sepgsql_table_t:s0:c0';

CREATE TABLE t3
(
    z   int
) SECURITY_LABEL = 'system_u:object_r:sepgsql_table_t:s0:c1';

CREATE TABLE t4
(
    a   int primary key,
    b   text
        SECURITY_LABEL = 'system_u:object_r:sepgsql_secret_table_t:s0'
);

INSERT INTO t4 VALUES (1, '1111-2222-3333-4444'),
                      (2, '5555-6666-7777-8888');

CREATE OR REPLACE FUNCTION f1(int) RETURNS TEXT
    LANGUAGE 'sql'
    SECURITY_LABEL = 'system_u:object_r:sepgsql_trusted_proc_exec_t:s0'
    AS 'SELECT regexp_replace(b, ''-[0-9]+'', ''-xxxx'',''g'') FROM t4 WHERE a = $1';

SELECT * FROM t1;

--@SECURITY_CONTEXT=unconfined_u:unconfined_r:sepgsql_test_t:s0-s0:c0
SELECT * FROM t1;		-- to be denied
SELECT t1 FROM t1;		-- to be denied
SELECT a,b,c FROM t1;
SELECT a,b,c FROM t1 FOR UPDATE;

INSERT INTO t1 (a,b,c,d) VALUES (3,3,3,3);	-- to be denied
INSERT INTO t1 (a,b,c) VALUES (4,4,4);		-- to be denied
INSERT INTO t1 (a,b) VALUES (5,5);
SELECT a,b,c FROM t1;

UPDATE t1 SET a=6, b=6, c=6, d=6;		-- to be denied
UPDATE t1 SET a=6, b=6, c=6;			-- to be denied
UPDATE t1 SET a=6, b=6;				-- to be denied
UPDATE t1 SET a=6;
SELECT a,b,c FROM t1;

SELECT * FROM t2;
SELECT * FROM t3;		-- to be denied
SELECT 1 FROM t3;		-- to be denied
SELECT count(*) FROM t3;	-- to be denied

SELECT * FROM t4;	-- to be denied
SELECT a, f1(a) FROM t4;

--@SECURITY_CONTEXT=unconfined_u:unconfined_r:sepgsql_test_t:s0-s0:c1
SELECT * FROM t2;	-- to be denied
SELECT t2 FROM t2;	-- to be denied
SELECT t3 FROM t3;
