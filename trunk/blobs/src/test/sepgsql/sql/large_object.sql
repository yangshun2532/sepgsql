--@SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

SELECT lo_import('/tmp/sepgsql_test_blob1', 6001);
SELECT lo_import('/tmp/sepgsql_test_blob1', 6002);
SELECT lo_import('/tmp/sepgsql_test_blob1', 6003);

SELECT lo_set_security(6001, 'system_u:object_r:sepgsql_blob_t:s0');
SELECT lo_set_security(6002, 'system_u:object_r:sepgsql_ro_blob_t:s0');
SELECT lo_set_security(6003, 'system_u:object_r:sepgsql_secret_blob_t:s0');

--@SECURITY_CONTEXT=unconfined_u:unconfined_r:sepgsql_test_t:s0:c0

SELECT lo_get_security(6001);
SELECT lo_get_security(6002);
SELECT lo_get_security(6003);

SELECT security_label, loid, COUNT(*) FROM pg_largeobject
       GROUP BY security_label, loid;

-- read large object
BEGIN;
SELECT lo_open(6001, x'40000'::int);
SELECT loread(0, 32);
ROLLBACK;

BEGIN;
SELECT lo_open(6002, x'40000'::int);
SELECT loread(0, 32);
ROLLBACK;

BEGIN;
SELECT lo_open(6003, x'40000'::int);	-- to be denied
SELECT loread(0, 32);
ROLLBACK;

-- write large object
BEGIN;
SELECT lo_open(6001, x'20000'::int);
SELECT lowrite(0, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');
ROLLBACK;

BEGIN;
SELECT lo_open(6002, x'20000'::int);
SELECT lowrite(0, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');	-- to be denied
ROLLBACK;

BEGIN;
SELECT lo_open(6003, x'20000'::int);
SELECT lowrite(0, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');	-- to be denied
ROLLBACK;

-- create large object
BEGIN;
SELECT lo_create(6004);
SELECT lo_open(6004, x'20000'::int);
SELECT lowrite(0, 'abcdefghijklmnopqrstuvwxyz');
SELECT lo_close(0);
COMMIT;

-- getattr/setattr
BEGIN;
SELECT lo_open(6004, x'20000'::int);
SELECT lo_lseek(0, 0, 2);	-- seek to end
SELECT lowrite(0, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');
SELECT lo_tell(0);
SELECT lo_lseek(0, 0, 0);	-- seek to head
SELECT loread(0, 50);
SELECT lo_close(0);
COMMIT;

-- import/export large object
SELECT lo_import('/tmp/sepgsql_test_blob2', 6005);	-- to be failed
SELECT lo_import('/tmp/sepgsql_test_blob1', 6005);

SELECT lo_export(6001, '/tmp/sepgsql_test_blob2');	-- to be failed
SELECT lo_export(6001, '/tmp/sepgsql_test_blob1');	-- to be failed
SELECT lo_export(6005, '/tmp/sepgsql_test_blob1');
SELECT lo_export(6005, '/dev/null');

--@SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

-- change security label
BEGIN;
SELECT lo_open(6001, x'40000'::int);	-- a seed of trouble
SELECT lo_set_security(6001, 'system_u:object_r:sepgsql_blob_t:s0:c4');
SELECT lo_get_security(6001);
SELECT security_label, loid, count(*) FROM pg_largeobject
       WHERE loid = 6001
       GROUP BY security_label, loid;
ROLLBACK;
