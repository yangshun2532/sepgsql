--
-- Test row-level access control list
--

-- Suppress NOTICE messages when users/groups don't exist
SET client_min_messages TO 'error';
DROP TABLE IF EXISTS ROWACL_TBL_F;
DROP TABLE IF EXISTS ROWACL_TBL_P;

DROP ROLE IF EXISTS ragroup;
DROP ROLE IF EXISTS rausr_o;
DROP ROLE IF EXISTS rausr_x;
DROP ROLE IF EXISTS rausr_y;
DROP ROLE IF EXISTS rausr_z;

RESET client_min_messages;

-- initial setups
CREATE USER rausr_o;	-- owner
CREATE USER rausr_x;
CREATE USER rausr_y;
CREATE USER rausr_z;
CREATE GROUP ragroup WITH USER rausr_x, rausr_y;

SET SESSION AUTHORIZATION rausr_o;

CREATE TABLE ROWACL_TBL_P (a int primary key, b text)
	WITH (row_level_acl=on);
GRANT all ON ROWACL_TBL_P TO public;
CREATE TABLE ROWACL_TBL_F (x int references ROWACL_TBL_P(a) ON UPDATE CASCADE, y text)
	WITH (row_level_acl=on);
GRANT all ON ROWACL_TBL_F TO public;

INSERT INTO ROWACL_TBL_P VALUES (1, 'aaa'), (2, 'bbb'), (3, 'ccc');
INSERT INTO ROWACL_TBL_P (tuple_acl, a, b) VALUES ('{ragroup=w/rausr_o}', 4, 'ddd');
COPY ROWACL_TBL_P (tuple_acl, a, b) FROM stdin;
{ragroup=wd/rausr_o}	5	eee
{ragroup=d/rausr_o}	6	fff
	7	ggg
{}	8	hhh
\.
SELECT tuple_acl, * FROM ROWACL_TBL_P;

UPDATE ROWACL_TBL_P SET tuple_acl = rowacl_revoke(tableoid, tuple_acl, 'public', 'all')
	WHERE a in (1, 3, 5, 7);

UPDATE ROWACL_TBL_P SET tuple_acl = rowacl_grant(tableoid, tuple_acl, 'rausr_x', 'select')
	WHERE a in (1, 2, 3, 4, 5);
UPDATE ROWACL_TBL_P SET tuple_acl = rowacl_grant(tableoid, tuple_acl, 'rausr_x', 'references')
	WHERE a in (3, 4, 5, 6, 7);

UPDATE ROWACL_TBL_P SET tuple_acl = rowacl_grant(tableoid, tuple_acl, 'rausr_y', 'select,update')
	WHERE a in (2, 4, 6);
UPDATE ROWACL_TBL_P SET tuple_acl = rowacl_grant(tableoid, tuple_acl, 'rausr_y', 'delete')
	WHERE a in (3, 5, 7);

SELECT tuple_acl, * FROM ROWACL_TBL_P;

INSERT INTO ROWACL_TBL_F (tuple_acl, x, y) VALUES ('', 1, 'red');
INSERT INTO ROWACL_TBL_F (tuple_acl, x, y) VALUES ('{ragroup=rw/rausr_o}', 2, 'blue');
INSERT INTO ROWACL_TBL_F (tuple_acl, x, y) VALUES ('{ragroup=wdx/rausr_o}', 3, 'green');
INSERT INTO ROWACL_TBL_F (tuple_acl, x, y) VALUES ('{ragroup=rd/rausr_o}', 4, 'yellow');
INSERT INTO ROWACL_TBL_F (tuple_acl, x, y) VALUES ('{ragroup=rx/rausr_o}', 5, 'orange');
SELECT tuple_acl, * FROM ROWACL_TBL_F;

\c -
-- test rausr_x privileges
SET SESSION AUTHORIZATION rausr_x;

SELECT tuple_acl, * FROM ROWACL_TBL_P;
SELECT tuple_acl, * FROM ROWACL_TBL_F;

BEGIN;
DELETE FROM ROWACL_TBL_F;
SELECT * FROM ROWACL_TBL_F;
ROLLBACK;

BEGIN;
DELETE FROM ROWACL_TBL_F RETURNING *;
ROLLBACK;

BEGIN;
UPDATE ROWACL_TBL_F SET y = y || '_updt';
SELECT * FROM ROWACL_TBL_F;
ROLLBACK;

BEGIN;
UPDATE ROWACL_TBL_F SET y = y || '_updt' RETURNING *;
ROLLBACK;

BEGIN;
INSERT INTO ROWACL_TBL_F VALUES (1, 'gold');	-- to be failed
SELECT * FROM ROWACL_TBL_F;
ROLLBACK;

BEGIN;
INSERT INTO ROWACL_TBL_F VALUES (7, 'gold');
SELECT * FROM ROWACL_TBL_F;
ROLLBACK;

BEGIN;
UPDATE ROWACL_TBL_P SET a = 99 WHERE a = 2;
SELECT * FROM ROWACL_TBL_P;
ROLLBACK;

BEGIN;
UPDATE ROWACL_TBL_P SET a = 99 WHERE a = 4;	-- to be failed
SELECT * FROM ROWACL_TBL_P;
ROLLBACK;


\c -
-- test rausr_y privileges
SET SESSION AUTHORIZATION rausr_y;

SELECT tuple_acl, * FROM ROWACL_TBL_P;
SELECT tuple_acl, * FROM ROWACL_TBL_F;

BEGIN;
DELETE FROM ROWACL_TBL_F;
SELECT * FROM ROWACL_TBL_F;
ROLLBACK;

BEGIN;
DELETE FROM ROWACL_TBL_F RETURNING *;
ROLLBACK;

BEGIN;
UPDATE ROWACL_TBL_F SET y = y || '_updt';
SELECT * FROM ROWACL_TBL_F;
ROLLBACK;

BEGIN;
UPDATE ROWACL_TBL_F SET y = y || '_updt' RETURNING *;
ROLLBACK;

SELECT * FROM ROWACL_TBL_P JOIN ROWACL_TBL_F ON a = x;
SELECT * FROM ROWACL_TBL_P LEFT OUTER JOIN ROWACL_TBL_F ON a = x;

\c -
-- test rausr_z privileges
SET SESSION AUTHORIZATION rausr_z;

SELECT tuple_acl, * FROM ROWACL_TBL_P;
SELECT tuple_acl, * FROM ROWACL_TBL_F;

\c -
-- clean up
SET client_min_messages TO 'error';
DROP TABLE IF EXISTS ROWACL_TBL_F;
DROP TABLE IF EXISTS ROWACL_TBL_P;

DROP ROLE IF EXISTS ragroup;
DROP ROLE IF EXISTS rausr_o;
DROP ROLE IF EXISTS rausr_x;
DROP ROLE IF EXISTS rausr_y;
DROP ROLE IF EXISTS rausr_z;

RESET client_min_messages;
