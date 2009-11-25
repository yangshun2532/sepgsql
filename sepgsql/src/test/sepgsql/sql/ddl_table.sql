--@SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

-- cleanup previous tests
SET client_min_messages TO 'error';

DROP TABLE IF EXISTS t1 CASCADE;
DROP TABLE IF EXISTS t2 CASCADE;
DROP TABLE IF EXISTS t3 CASCADE;
DROP TABLE IF EXISTS t4 CASCADE;
DROP TABLE IF EXISTS t5 CASCADE;
DROP TABLE IF EXISTS t6 CASCADE;

DROP TABLE IF EXISTS tx CASCADE;
DROP TABLE IF EXISTS ty CASCADE;
DROP TABLE IF EXISTS txx CASCADE;
DROP TABLE IF EXISTS tyy CASCADE;
DROP TABLE IF EXISTS txy CASCADE;

RESET client_min_messages;

-- CREATE TABLE with SECURITY_CONTEXT option
CREATE TABLE t1
(
    a   int,
    b   int
);

CREATE TABLE t2
(
    c   int,
    d   int
) SECURITY CONTEXT 'system_u:object_r:sepgsql_ro_table_t:s0:c0';

CREATE TABLE t3
(
    e   int,
    f   int
) SECURITY CONTEXT 'system_u:object_r:sepgsql_ro_table_t:s0:c20';	-- to be denied

CREATE TABLE t4
(
    g   int,
    h   int
) SECURITY CONTEXT 'invalid security context';				-- to be failed

CREATE TABLE t5
(
    i   int,
    j   int
        AS SECURITY CONTEXT 'system_u:object_r:sepgsql_ro_table_t:s0'
);

CREATE TABLE t6
(
    k   int,
    l   int
        AS SECURITY CONTEXT 'system_u:object_r:sepgsql_secret_table_t:s0'
) SECURITY CONTEXT 'system_u:object_r:sepgsql_ro_table_t:s0';

SELECT relname, sepgsql_relation_getcon(oid), relsecon FROM pg_class
       WHERE relname in ('t1', 't2', 't3', 't4', 't5', 't6')
       ORDER BY relname;

SELECT relname, attname, attnum,
       sepgsql_attribute_getcon(attrelid, attnum), attsecon
       FROM pg_class c JOIN pg_attribute a ON c.oid = a.attrelid
       WHERE c.relname IN ('t1', 't2', 't3', 't4', 't5', 't6')
       ORDER BY relname, attnum;

-- ALTER TABLE with SECURITY_CONTEXT option
ALTER TABLE t1 SECURITY CONTEXT
      TO 'system_u:object_r:sepgsql_table_t:s0:c0';
ALTER TABLE t2 ADD COLUMN x int;
ALTER TABLE t2 SECURITY CONTEXT
      TO 'system_u:object_r:sepgsql_table_t:s0:c20';	-- to be denied
ALTER TABLE t2 SECURITY CONTEXT
      TO 'invalid security context';			-- to be failed

ALTER TABLE t1 ALTER COLUMN a SECURITY CONTEXT
      TO 'system_u:object_r:sepgsql_table_t:s0:c1';
ALTER TABLE t1 ALTER COLUMN b SECURITY CONTEXT
      TO 'system_u:object_r:sepgsql_table_t:s0:c20';	-- to be denied
ALTER TABLE t1 ALTER COLUMN b SECURITY CONTEXT
      TO 'invalid security context';			-- to be failed
ALTER TABLE t1 ALTER COLUMN tableoid SECURITY CONTEXT
      TO 'system_u:object_r:sepgsql_ro_table_t:s0';	-- to be failed

SELECT relname, sepgsql_relation_getcon(oid), relsecon FROM pg_class
       WHERE relname IN ('t1', 't2')
       ORDER BY relname;

SELECT relname, attname, attnum,
       sepgsql_attribute_getcon(attrelid, attnum), attsecon
       FROM pg_class c JOIN pg_attribute a ON c.oid = a.attrelid
       WHERE c.relname IN ('t1', 't2')
       ORDER BY relname, attnum;

-- Table inheritance and column's security context
CREATE TABLE tx
(
	x	int
		AS SECURITY CONTEXT 'system_u:object_r:sepgsql_table_t:s0:c1',
	z	text
);

CREATE TABLE ty
(
	y	int,
	z	text
);

CREATE TABLE txx
(
	xx	int
) INHERITS(tx);

CREATE TABLE tyy
(
	yy	int
) INHERITS(ty);

ALTER TABLE tyy ALTER COLUMN y
      SECURITY CONTEXT TO 'system_u:object_r:sepgsql_table_t:s0:c2';	-- to be failed

ALTER TABLE ty ALTER COLUMN y
      SECURITY CONTEXT TO 'system_u:object_r:sepgsql_table_t:s0:c2';

-- inherited column shares same security context
SELECT relname, attname, attnum,
       sepgsql_attribute_getcon(attrelid, attnum)
       FROM pg_class c JOIN pg_attribute a ON c.oid = a.attrelid
       WHERE c.relname IN ('tx', 'ty', 'txx', 'tyy')
       ORDER BY relname, attnum;

CREATE TABLE txy
(
	xy	int
) INHERITS(txx, tyy);

ALTER TABLE tx ALTER COLUMN x
      SECURITY CONTEXT TO 'system_u:object_r:sepgsql_table_t:s0:c3';
ALTER TABLE tx ALTER COLUMN z
      SECURITY CONTEXT TO 'system_u:object_r:sepgsql_table_t:s0:c4';	-- to be failed

ALTER TABLE txy NO INHERIT tyy;

ALTER TABLE tx ALTER COLUMN z
      SECURITY CONTEXT TO 'system_u:object_r:sepgsql_table_t:s0:c4';

ALTER TABLE txy INHERIT tyy;						-- to be failed

ALTER TABLE tx SECURITY CONTEXT TO 'system_u:object_r:sepgsql_ro_table_t:s0';
ALTER TABLE tx SET WITH OIDS;

SELECT relname, attname, attnum,
       sepgsql_attribute_getcon(attrelid, attnum)
       FROM pg_class c JOIN pg_attribute a ON c.oid = a.attrelid
       WHERE c.relname IN ('tx', 'ty', 'txx', 'tyy')
       ORDER BY relname, attnum;

-- disallow to modify system catalog by hand

UPDATE pg_class SET relsecon = NULL
       WHERE relname = 't1';						-- to be denied
UPDATE pg_attribute SET attsecon = NULL
       WHERE attrelid = 't1'::regclass;					-- to be denied

-- cleanups
SET client_min_messages TO 'error';

DROP TABLE IF EXISTS t1 CASCADE;
DROP TABLE IF EXISTS t2 CASCADE;
DROP TABLE IF EXISTS t3 CASCADE;
DROP TABLE IF EXISTS t4 CASCADE;
DROP TABLE IF EXISTS t5 CASCADE;
DROP TABLE IF EXISTS t6 CASCADE;

DROP TABLE IF EXISTS tx CASCADE;
DROP TABLE IF EXISTS ty CASCADE;
DROP TABLE IF EXISTS txx CASCADE;
DROP TABLE IF EXISTS tyy CASCADE;
DROP TABLE IF EXISTS txy CASCADE;

RESET client_min_messages;
