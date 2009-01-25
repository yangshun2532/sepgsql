:SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15
-- Binary Large Object
-- ===================

SELECT sepgsql_getcon();

SELECT lo_import('/tmp/sepgsql_test_blob', 6001);
SELECT lo_import('/tmp/sepgsql_test_blob', 6002);
SELECT lo_import('/tmp/sepgsql_test_blob', 6003);

SELECT lo_set_security(6001, 'system_u:object_r:sepgsql_blob_t:s0');
SELECT lo_set_security(6002, 'system_u:object_r:sepgsql_ro_blob_t:s0');
SELECT lo_set_security(6003, 'system_u:object_r:sepgsql_secret_blob_t:s0');

:SECURITY_CONTEXT=unconfined_u:unconfined_r:sepgsql_test_t:s0-s0:c0

SELECT sepgsql_getcon();

SELECT lo_get_security(6001);
SELECT lo_get_security(6002);
SELECT lo_get_security(6003);

SELECT security_label, loid, COUNT(*) FROM pg_largeobject
       GROUP BY security_label, loid;

-- read large object
BEGIN;
SELECT lo_open(6001, x'40000'::int);
SELECT loread(0, 24);
ROLLBACK;

BEGIN;
SELECT lo_open(6002, x'40000'::int);
SELECT loread(0, 24);
ROLLBACK;

BEGIN;
SELECT lo_open(6003, x'40000'::int);
SELECT loread(0, 24);			-- to be failed
ROLLBACK;

-- write large object
BEGIN;
SELECT lo_open(6001, x'20000'::int);
SELECT lowrite(0, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');
COMMIT;

BEGIN;
SELECT lo_open(6002, x'20000'::int);
SELECT lowrite(0, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');	-- to be failed
COMMIT;

BEGIN;
SELECT lo_open(6003, x'20000'::int);
SELECT lowrite(0, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');	-- to be failed
COMMIT;

-- create large object
BEGIN;
SELECT lo_create(6004);
SELECT lo_open(6004, x'20000'::int);
SELECT lowrite(0, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');
SELECT lo_close(0);
COMMIT;

-- append large object
BEGIN;
SELECT lo_open(6001, x'60000'::int);
SELECT lo_lseek(0, 0, 2);       -- seek to end
SELECT lowrite(0, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');
SELECT lo_close(0);
COMMIT;

-- import/export large object
SELECT lo_import('/tmp/sepgsql_test_blob', 6005);

SELECT lo_export(6001, '/tmp/sepgsql_test_blob');

-- check result
SELECT security_label, loid, COUNT(*) FROM pg_largeobject
       GROUP BY security_label, loid;

:SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15
SELECT sepgsql_getcon();

SELECT lo_unlink(6001);
SELECT lo_unlink(6002);
SELECT lo_unlink(6003);
SELECT lo_unlink(6004);
SELECT lo_unlink(6005);
