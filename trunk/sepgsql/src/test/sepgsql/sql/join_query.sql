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
    b   text,
    c   int
        SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_secret_table_t:s0'
);
INSERT INTO t1 VALUES (1, 'aaa'), (2, 'bbb'), (3, 'ccc');

CREATE TABLE t2
(
    x   int,
    y   text
);
INSERT INTO t2 VALUES (2, 'xxx'), (3, 'yyy'), (4,'zzz');

CREATE TABLE t3
(
    d   int
) INHERITS (t1);
INSERT INTO t3 VALUES (4, 'ddd'), (5, 'eee');

CREATE TABLE t4
(
    z   int
        SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_secret_table_t:s0'
) INHERITS (t2);
INSERT INTO t2 VALUES (1, 'sss'), (5, 'ttt');

--@SECURITY_CONTEXT=unconfined_u:unconfined_r:sepgsql_test_t:s0-s0:c0
SELECT * FROM t1 JOIN t2 ON a = x;		-- to be denied
SELECT a, b, y FROM t1 JOIN t2 ON a = x;
SELECT a, b, y FROM t1 JOIN t2 ON c = x;	-- to be denied
SELECT COUNT(*) FROM t1 JOIN t2 ON a = x;
SELECT j FROM (t1 JOIN t2 ON a = x) AS j;	-- to be denied
