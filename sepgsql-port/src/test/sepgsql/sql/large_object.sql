--@SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

-- cleanup previous tests
SET client_min_messages TO 'error';

DROP TABLE IF EXISTS t1 CASCADE;

RESET client_min_messages;

CREATE TABLE t1 (
       loid	oid,
       key	varchar(24)
);

INSERT INTO t1 (SELECT lo_import('/tmp/sepgsql_test_blob1'), 'normal');
INSERT INTO t1 (SELECT lo_import('/tmp/sepgsql_test_blob1'), 'readonly');
INSERT INTO t1 (SELECT lo_import('/tmp/sepgsql_test_blob1'), 'secret');

SELECT lo_set_security(loid, 'system_u:object_r:sepgsql_blob_t:s0')
       FROM t1 WHERE key = 'normal';
SELECT lo_set_security(loid, 'system_u:object_r:sepgsql_ro_blob_t:s0')
       FROM t1 WHERE key = 'readonly';
SELECT lo_set_security(loid, 'system_u:object_r:sepgsql_secret_blob_t:s0')
       FROM t1 WHERE key = 'secret';

--@SECURITY_CONTEXT=unconfined_u:unconfined_r:sepgsql_test_t:s0:c0

SELECT lo_get_security(loid) FROM t1;

SELECT security_context, (SELECT key FROM t1 WHERE t1.loid = l.loid) AS key, COUNT(*)
       FROM pg_largeobject l GROUP BY security_context, loid ORDER BY security_context;

-- read large object
BEGIN;
SELECT lo_open(loid, x'40000'::int) FROM t1 WHERE key = 'normal';
SELECT loread(0, 32);
ROLLBACK;

BEGIN;
SELECT lo_open(loid, x'40000'::int) FROM t1 WHERE key = 'readonly';
SELECT loread(0, 32);
ROLLBACK;

BEGIN;
SELECT lo_open(loid, x'40000'::int) FROM t1 WHERE key = 'secret';
SELECT loread(0, 32);		-- to be denied
ROLLBACK;

-- write large object
BEGIN;
SELECT lo_open(loid, x'20000'::int) FROM t1 WHERE key = 'normal';
SELECT lowrite(0, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');
ROLLBACK;

BEGIN;
SELECT lo_open(loid, x'20000'::int) FROM t1 WHERE key = 'readonly';
SELECT lowrite(0, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');	-- to be denied
ROLLBACK;

BEGIN;
SELECT lo_open(loid, x'20000'::int) FROM t1 WHERE key = 'secret';
SELECT lowrite(0, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');	-- to be denied
ROLLBACK;

-- create large object
BEGIN;
INSERT INTO t1 (SELECT lo_create(6004), 'local');
SELECT lo_open(loid, x'20000'::int) FROM t1 WHERE key = 'local';
SELECT lowrite(0, 'abcdefghijklmnopqrstuvwxyz');
SELECT lo_close(0);
COMMIT;

-- getattr/setattr
BEGIN;
SELECT lo_open(loid, x'20000'::int) FROM t1 WHERE key = 'local';
SELECT lo_lseek(0, 0, 2);	-- seek to end
SELECT lowrite(0, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');
SELECT lo_tell(0);
SELECT lo_lseek(0, 0, 0);	-- seek to head
SELECT loread(0, 50);
SELECT lo_close(0);
COMMIT;

-- import/export large object
INSERT INTO t1 (SELECT lo_import('/tmp/sepgsql_test_blob2'), 'import');	-- to be failed
INSERT INTO t1 (SELECT lo_import('/tmp/sepgsql_test_blob1'), 'import');

SELECT lo_export(loid, '/tmp/sepgsql_test_blob2') FROM t1 WHERE key = 'normal';	-- to be failed
SELECT lo_export(loid, '/tmp/sepgsql_test_blob1') FROM t1 WHERE key = 'normal';	-- to be failed
SELECT lo_export(loid, '/tmp/sepgsql_test_blob1') FROM t1 WHERE key = 'local';
SELECT lo_export(loid, '/dev/null') FROM t1 WHERE key = 'local';

--@SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

-- change security label
BEGIN;
SELECT lo_open(loid, x'40000'::int) FROM t1;	-- a seed of trouble
SELECT lo_set_security(loid, 'system_u:object_r:sepgsql_blob_t:s0:c4') FROM t1 WHERE key in ('normal', 'readonly');
SELECT lo_get_security(loid) FROM t1;
SELECT security_context, (SELECT key FROM t1 WHERE t1.loid = l.loid), count(*)
       FROM pg_largeobject l WHERE loid in (SELECT loid FROM t1)
       GROUP BY security_context, loid ORDER BY security_context;
ROLLBACK;
