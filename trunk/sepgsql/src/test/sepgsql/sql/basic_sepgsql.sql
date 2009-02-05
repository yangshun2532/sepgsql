--@SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

-- cleanup previous tests
SET client_min_messages TO 'error';

DROP TABLE IF EXISTS t4 CASCADE;
DROP TABLE IF EXISTS t3 CASCADE;
DROP TABLE IF EXISTS t2 CASCADE;
DROP TABLE IF EXISTS t1 CASCADE;

DROP FUNCTION IF EXISTS f1(int) CASCADE;

RESET client_min_messages;

-- SETUP

CREATE TABLE t1
(
    a   int,
    b   text
        SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_ro_table_t:s0',
    c   bool
        SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_secret_table_t:s0'
);
INSERT INTO t1 VALUES (1, 'aaa', false), (2, 'bbb', true);

CREATE TABLE t2
(
    s   int,
    t   int,
    u   int
) SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_table_t:s0:c0';
ALTER TABLE t2 DROP COLUMN t;	-- disturbing factor

CREATE TABLE t3
(
    x   text
        SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_table_t:s0:c1'
) inherits(t2);

--@SECURITY_CONTEXT=unconfined_u:unconfined_r:sepgsql_test_t:s0-s0:c0

SELECT * FROM t1;			-- to be denied
SELECT a, b FROM t1;
SELECT COUNT(*) FROM t1 WHERE c;	-- to be denied
UPDATE t1 SET b = 'ccc';		-- to be denied
UPDATE t1 SET a = a + 2;
INSERT INTO t1 VALUES (5, 'eee', true);	-- to be denied
INSERT INTO t1 VALUES (5);

SELECT * FROM t2;
SELECT t2 FROM t2;
SELECT t3 FROM t3;	-- to be denied
SELECT 1 FROM t3;

--@SECURITY_CONTEXT=unconfined_u:unconfined_r:sepgsql_test_t:s0-s0:c1
SELECT * FROM t2;	-- to be denied
SELECT t2 FROM t2;	-- to be denied
SELECT t3 FROM t3;
