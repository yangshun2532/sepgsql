--
-- Test row-level access control list
--

-- Suppress NOTICE messages when users/groups don't exist
SET client_min_messages TO 'error';
DROP TABLE IF EXISTS ROWACL_TBL_X;
DROP TABLE IF EXISTS ROWACL_TBL_Y;
DROP TABLE IF EXISTS ROWACL_TBL_Z;
DROP TABLE IF EXISTS ROWACL_TBL_A;

DROP ROLE IF EXISTS ragroup;
DROP ROLE IF EXISTS rausr_o;
DROP ROLE IF EXISTS rausr_x;
DROP ROLE IF EXISTS rausr_y;

RESET client_min_messages;

-- test proper begins here
CREATE USER rausr_o;	-- owner
CREATE USER rausr_x;
CREATE USER rausr_y;
CREATE GROUP ragroup WITH USER rausr_x, rausr_y;

-- test owner privileges
SET SESSION AUTHORIZATION rausr_o;

CREATE TABLE ROWACL_TBL_A (a int primary key, b text)
	WITH (row_level_acl=on);
GRANT all ON ROWACL_TBL_A TO public;
CREATE TABLE ROWACL_TBL_X (x int references ROWACL_TBL_A(a), xx text)
	WITH (row_level_acl=on);
GRANT all ON ROWACL_TBL_X TO public;
CREATE TABLE ROWACL_TBL_Y (y int references ROWACL_TBL_A(a), yy text)
	WITH (row_level_acl=on,default_row_acl='{ragroup=rx/rausr_o}');
GRANT all ON ROWACL_TBL_Y TO public;
CREATE TABLE ROWACL_TBL_Z (z int references ROWACL_TBL_A(a), zz text);
GRANT all ON ROWACL_TBL_Z TO public;

INSERT INTO ROWACL_TBL_A VALUES (1, 'aaa'), (2, 'bbb'), (3, 'ccc');
INSERT INTO ROWACL_TBL_A (tuple_acl, a, b) VALUES ('{ragroup=w/rausr_o}', 4, 'ddd');
COPY ROWACL_TBL_A (tuple_acl, a, b) FROM stdin;
{ragroup=wd/rausr_o}	5	eee
{ragroup=d/rausr_o}	6	fff
{}	7	ggg
\.

INSERT INTO ROWACL_TBL_X VALUES (1, 'red'), (2, 'blue'), (3, 'yellow'), (4, 'orange'),
				(5, 'white'), (6, 'black'), (7, 'green');

INSERT INTO ROWACL_TBL_Y VALUES (1, 'milk'), (2, 'tea'), (3, 'coke'), (4, 'soda'),
				(5, 'water'), (6, 'beer'), (7, 'wine');

INSERT INTO ROWACL_TBL_Z VALUES (1, 'dog'), (2, 'cat');

UPDATE ROWACL_TBL_A SET tuple_acl = rowacl_revoke(tableoid, tuple_acl, 'public', 'all');
UPDATE ROWACL_TBL_A SET tuple_acl = rowacl_grant(tableoid, tuple_acl, 'rausr_x', 'select') WHERE a IN (1,3,5,7);
UPDATE ROWACL_TBL_A SET tuple_acl = rowacl_grant(tableoid, tuple_acl, 'rausr_y', 'select') WHERE a IN (2,4,6);

UPDATE ROWACL_TBL_X SET tuple_acl = '{rausr_x=r/rausr_o}' WHERE x IN (1,2,3,4);
UPDATE ROWACL_TBL_X SET tuple_acl = '{rausr_y=r/rausr_o}' WHERE x IN (4,5,6,7);
UPDATE ROWACL_TBL_X SET tuple_acl = rowacl_grant(tableoid, tuple_acl, 'rausr_x', 'update') WHERE x IN (1,2);
UPDATE ROWACL_TBL_X SET tuple_acl = rowacl_grant(tableoid, tuple_acl, 'rausr_x', 'delete') WHERE x IN (5,6);
UPDATE ROWACL_TBL_X SET tuple_acl = rowacl_grant(tableoid, tuple_acl, 'rausr_y', 'update') WHERE x IN (3,4,5);
UPDATE ROWACL_TBL_X SET tuple_acl = rowacl_grant(tableoid, tuple_acl, 'rausr_y', 'delete') WHERE x IN (1,2,3);

UPDATE ROWACL_TBL_Y SET tuple_acl = '{rausr_x=r/rausr_o}' WHERE y IN (1,3,5,7);
UPDATE ROWACL_TBL_Y SET tuple_acl = '{rausr_y=r/rausr_o}' WHERE y IN (2,4,6);
UPDATE ROWACL_TBL_Y SET tuple_acl = rowacl_grant(tableoid, tuple_acl, 'rausr_x', 'references');
UPDATE ROWACL_TBL_Y SET tuple_acl = rowacl_grant(tableoid, tuple_acl, 'ragroup', 'update') WHERE y IN (3,4,5);
UPDATE ROWACL_TBL_Y SET tuple_acl = rowacl_grant(tableoid, tuple_acl, 'ragroup', 'delete') WHERE y IN (1,2,6,7);

SELECT tuple_acl, * FROM ROWACL_TBL_A;
SELECT tuple_acl, * FROM ROWACL_TBL_X;
SELECT tuple_acl, * FROM ROWACL_TBL_Y;
SELECT tuple_acl, * FROM ROWACL_TBL_Z;

\c -
-- test rausr_x privileges
SET SESSION AUTHORIZATION rausr_x;

SELECT tuple_acl, * FROM ROWACL_TBL_A;
SELECT tuple_acl, * FROM ROWACL_TBL_X;
SELECT tuple_acl, * FROM ROWACL_TBL_Y;
SELECT tuple_acl, * FROM ROWACL_TBL_Z;

BEGIN;
DELETE FROM ROWACL_TBL_X;
ROLLBACK;

BEGIN;
UPDATE ROWACL_TBL_X SET xx = xx || '_updt';
ROLLBACK;

\c -
-- test rausr_y privileges
SET SESSION AUTHORIZATION rausr_y;

SELECT tuple_acl, * FROM ROWACL_TBL_A;
SELECT tuple_acl, * FROM ROWACL_TBL_X;
SELECT tuple_acl, * FROM ROWACL_TBL_Y;
SELECT tuple_acl, * FROM ROWACL_TBL_Z;
