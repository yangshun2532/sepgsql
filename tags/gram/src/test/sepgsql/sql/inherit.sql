--@SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

-- cleanup previous tests
SET client_min_messages TO 'error';

DROP TABLE IF EXISTS t1 CASCADE;
DROP TABLE IF EXISTS t2 CASCADE;
DROP TABLE IF EXISTS t3 CASCADE;

RESET client_min_messages;
-- SETUPS
CREATE TABLE t1
(
    a   int,
    b   int
);
INSERT INTO t1 VALUES (1,1), (2,2);

CREATE TABLE t2
(
    c   text
) INHERITS(t1)
    SECURITY_LABEL = 'system_u:object_r:sepgsql_ro_table_t:s0';
INSERT INTO t2 VALUES (3,3,'ccc');

CREATE TABLE t3
(
    d   text
) INHERITS(t1)
    SECURITY_LABEL = 'system_u:object_r:sepgsql_secret_table_t:s0';
INSERT INTO t3 VALUES (4,4,'ddd');

--@SECURITY_CONTEXT=unconfined_u:unconfined_r:sepgsql_test_t:s0-s0:c0
SELECT * FROM t1;	-- to be denied
SELECT * FROM ONLY t1;
SELECT * FROM t2;
SELECT * FROM t3;	-- to be denied

UPDATE t1 SET b = b + 1;		-- to be denied
UPDATE ONLY t1 SET b = b + 1;
UPDATE t2 SET c = c || '_updt';		-- to be denied

INSERT INTO t2 VALUES (5,5,'eee');	-- to be denied

DELETE FROM t3;		-- to be denied
DELETE FROM t1;		-- to be denied
DELETE FROM ONLY t1;
