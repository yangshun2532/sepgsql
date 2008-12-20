--
-- SE-PostgreSQL testcases : Largeobjects
--
-- selinux_user: unconfined_u
-- selinux_role: unconfined_r
-- selinux_type: sepgsql_test_t
-- selinux_range: s0:c0

SELECT lo_get_security(6001);
SELECT lo_get_security(6002);
SELECT lo_get_security(6003);

SELECT security_context, loid, COUNT(*) FROM pg_largeobject GROUP BY security_context, loid;

-- read large object
BEGIN;
SELECT lo_open(6001, 4 * 65536);
SELECT loread(0, 24);
ROLLBACK;

BEGIN;
SELECT lo_open(6002, 4 * 65536);
SELECT loread(0, 24);
ROLLBACK;

BEGIN;
SELECT lo_open(6003, 4 * 65536);
SELECT loread(0, 24);					-- to be failed
ROLLBACK;

-- write large object
BEGIN;
SELECT lo_open(6001, 2 * 65536);
SELECT lowrite(0, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');
COMMIT;

BEGIN;
SELECT lo_open(6002, 2 * 65536);
SELECT lowrite(0, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');	-- to be failed
COMMIT;

BEGIN;
SELECT lo_open(6003, 2 * 65536);
SELECT lowrite(0, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');	-- to be failed
COMMIT;

-- create large object
BEGIN;
SELECT lo_create(6004);
SELECT lo_open(6004, 2 * 65536);
SELECT lowrite(0, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');
SELECT lo_close(0);
COMMIT;

-- append large object
BEGIN;
SELECT lo_open(6001, 6 * 65536);
SELECT lo_lseek(0, 0, 2);	-- seek to end
SELECT lowrite(0, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');
SELECT lo_close(0);
COMMIT;

-- confirm results
SELECT security_context, loid, COUNT(*) FROM pg_largeobject GROUP BY security_context, loid;
