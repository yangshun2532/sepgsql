--@SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

-- cleanup previous tests
SET client_min_messages TO 'error';

DROP TABLE IF EXISTS t3 CASCADE;
DROP TABLE IF EXISTS t2 CASCADE;
DROP TABLE IF EXISTS t1 CASCADE;

DROP FUNCTION IF EXISTS f1(int) CASCADE;

RESET client_min_messages;

-- setup tables

CREATE TABLE t1
(
    a    int,
    b    text
);

INSERT INTO t1 VALUES (1, 'aaa'), (2, 'bbb');

CREATE TABLE t2
(
    x    int,
    y    text
         SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_secret_table_t:s0'
);
SELECT sepgsql_column_getcon('t2','y');
INSERT INTO t2 VALUES (1, 'xxx'), (2, 'yyy');

CREATE TABLE t3	      -- read only table
(
    s    int,
    t    text
) SECURITY_LABEL = 'unconfined_u:object_r:sepgsql_ro_table_t:s0';
INSERT INTO t2 VALUES (1, 'sss'), (2, 'ttt');

--@SECURITY_CONTEXT=unconfined_u:unconfined_r:sepgsql_test_t:s0-s0:c0
COPY t1 TO stdout;
COPY t1 FROM stdin;
3	ccc
4	ddd
\.

COPY t1 TO '/tmp/sepgsql_test_copy_1';
COPY t1 TO '/tmp/sepgsql_test_copy_2';	-- to be denied

COPY t2 TO stdout;	-- to be denied
COPY t2 FROM stdin;	-- to be denied
COPY t2 (x) TO stdout;

COPY t3 TO stdout;
COPY t3 FROM '/tmp/sepgsql_test_copy_1';	-- to be denied

COPY t1 FROM '/tmp/sepgsql_test_copy_1';
COPY t1 TO stdout;
