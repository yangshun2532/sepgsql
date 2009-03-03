--@SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

-- cleanup previous tests
SET client_min_messages TO 'error';

DROP TABLE IF EXISTS lolabel CASCADE;
DROP FUNCTION IF EXISTS lo_label(oid) CASCADE;

RESET client_min_messages;

CREATE TABLE lolabel(
       loid	oid,
       label	text
);

CREATE OR REPLACE FUNCTION lo_label(oid)
       RETURNS TEXT LANGUAGE 'sql'
       AS 'SELECT label FROM lolabel WHERE loid = $1';

INSERT INTO lolabel (SELECT lo_import('/tmp/sepgsql_test_blob1'), 'normal');
INSERT INTO lolabel (SELECT lo_import('/tmp/sepgsql_test_blob1'), 'readonly');
INSERT INTO lolabel (SELECT lo_import('/tmp/sepgsql_test_blob1'), 'secret');

SELECT lo_set_security(loid, 'system_u:object_r:sepgsql_blob_t:s0')
       FROM lolabel WHERE label = 'normal';
SELECT lo_set_security(loid, 'system_u:object_r:sepgsql_ro_blob_t:s0')
       FROM lolabel WHERE label = 'readonly';
SELECT lo_set_security(loid, 'system_u:object_r:sepgsql_secret_blob_t:s0')
       FROM lolabel WHERE label = 'secret';

--@SECURITY_CONTEXT=unconfined_u:unconfined_r:sepgsql_test_t:s0:c0

SELECT lo_get_security(loid) FROM lolabel;

SELECT security_context, lo_label(loid) AS label, COUNT(*)
       FROM pg_largeobject GROUP BY security_context, loid ORDER by label;

-- read large object
BEGIN;
SELECT lo_open(loid, x'40000'::int) FROM lolabel WHERE label = 'normal';
SELECT loread(0, 32);
ROLLBACK;

BEGIN;
SELECT lo_open(loid, x'40000'::int) FROM lolabel WHERE label = 'readonly';
SELECT loread(0, 32);
ROLLBACK;

BEGIN;
SELECT lo_open(loid, x'40000'::int) FROM lolabel WHERE label = 'secret';
SELECT loread(0, 32);           -- to be denied
ROLLBACK;

-- write large object
BEGIN;
SELECT lo_open(loid, x'20000'::int) FROM lolabel WHERE label = 'normal';
SELECT lowrite(0, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');
ROLLBACK;

BEGIN;
SELECT lo_open(loid, x'20000'::int) FROM lolabel WHERE label = 'readonly';
SELECT lowrite(0, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');        -- to be denied
ROLLBACK;

BEGIN;
SELECT lo_open(loid, x'20000'::int) FROM lolabel WHERE label = 'secret';
SELECT lowrite(0, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');        -- to be denied
ROLLBACK;

-- create large object
BEGIN;
INSERT INTO lolabel (SELECT lo_create(6004), 'local');
SELECT lo_open(loid, x'20000'::int) FROM lolabel WHERE label = 'local';
SELECT lowrite(0, 'abcdefghijklmnopqrstuvwxyz');
SELECT lo_close(0);
COMMIT;

-- getattr/setattr
BEGIN;
SELECT lo_open(loid, x'20000'::int) FROM lolabel WHERE label = 'local';
SELECT lo_lseek(0, 0, 2);	-- seek to end
SELECT lowrite(0, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');
SELECT lo_tell(0);
SELECT lo_lseek(0, 0, 0);	-- seek to head
SELECT loread(0, 50);
SELECT lo_close(0);
COMMIT;

--@SECURITY_CONTEXT=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c15

-- change security label
BEGIN;
SELECT lo_open(loid, x'40000'::int) FROM lolabel;    -- a seed of trouble
SELECT lo_set_security(loid, 'system_u:object_r:sepgsql_blob_t:s0:c4')
	FROM lolabel WHERE label in ('normal', 'readonly');
SELECT lo_get_security(loid) FROM lolabel;
SELECT security_context, lo_label(loid) AS label, count(*)
	FROM pg_largeobject WHERE loid in (SELECT loid FROM lolabel)
	GROUP BY security_context, loid ORDER BY label;
ROLLBACK;

-- cleanup
SELECT lo_unlink(loid) FROM lolabel;
