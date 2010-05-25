--@SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

-- cleanup previous tests
SET client_min_messages TO 'error';

DROP TABLE IF EXISTS t1 CASCADE;
DROP TABLE IF EXISTS t2 CASCADE;
DROP TABLE IF EXISTS t3 CASCADE;
DROP TABLE IF EXISTS t4 CASCADE;

RESET client_min_messages;

-- CREATE TABLE for DML basic tests

CREATE TABLE t1		-- regular table
(
	a	int,
	b	text
);
INSERT INTO t1 VALUES (1, 'xxx'), (2, 'yyy'), (3, 'zzz');

CREATE TABLE t2		-- read-only table (from sepgsql_test_t)
(
	c	int,
	d	text
) SECURITY CONTEXT ('system_u:object_r:sepgsql_ro_table_t:s0');
INSERT INTO t2 VALUES (1, 'XXX'), (2, 'YYY'), (3, 'ZZZ');

CREATE TABLE t3		-- unaccessable table (from sepgsql_test_t)
(
	e	int,
	f	text
) SECURITY CONTEXT ('system_u:object_r:sepgsql_secret_table_t:s0');
INSERT INTO t3 VALUES (1, 'aaa'), (2, 'bbb'), (3, 'ccc');

CREATE TABLE t4
(
	g	int,
	h	text,
	i	text
) SECURITY CONTEXT (h='system_u:object_r:sepgsql_ro_table_t:s0',
                    i='system_u:object_r:sepgsql_secret_table_t:s0');
INSERT INTO t4 VALUES (1, 'AAA', 'BBB'), (2, 'CCC', 'DDD'), (3, 'EEE', 'FFF');

--@SECURITY_CONTEXT=unconfined_u:unconfined_r:sepgsql_test_t:s0-s0:c0

SELECT * FROM t1;
INSERT INTO t1 VALUES (4, 'test');
UPDATE t1 SET b = b || '_updt';
DELETE FROM t1 WHERE a = 4;

SELECT * FROM t2;
INSERT INTO t2 VALUES (4, 'test');			-- to be denied
UPDATE t2 SET d = d || '_updt';				-- to be denied
DELETE FROM t2 WHERE c = 4;				-- to be denied
SELECT COUNT(*) FROM t2;

SELECT * FROM t3;					-- to be denied
INSERT INTO t3 VALUES (4, 'test');			-- to be denied
UPDATE t3 SET f = f || '_updt';				-- to be denied
DELETE FROM t3 WHERE e = 4;				-- to be denied
SELECT COUNT(*) FROM t3;				-- to be denied

SELECT * FROM t4;					-- to be denied
SELECT g, h FROM t4;
SELECT g, h FROM t4 ORDER BY i;				-- to be denied
SELECT g, h FROM t4 WHERE g in (SELECT c FROM t2);
SELECT g, h FROM t4 WHERE g in (SELECT e FROM t3);	-- to be denied
INSERT INTO t4 (g,h,i) VALUES (4, 'GGG', 'HHH');	-- to be denied
INSERT INTO t4 (g,h) VALUES (4, 'GGG');			-- to be denied
INSERT INTO t4 (g) VALUES (4);
UPDATE t4 SET h = h || '_updt';				-- to be denied
UPDATE t4 SET g = 5 WHERE g = 1;

--@SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

-- cleanups
SET client_min_messages TO 'error';

DROP TABLE IF EXISTS t1 CASCADE;
DROP TABLE IF EXISTS t2 CASCADE;
DROP TABLE IF EXISTS t3 CASCADE;
DROP TABLE IF EXISTS t4 CASCADE;

RESET client_min_messages;
