--
-- Testcases for Row-level Database ACLs
--

SET client_min_messages TO 'error';

DROP TABLE IF EXISTS ratbl_f CASCADE;
DROP TABLE IF EXISTS ratbl_p CASCADE;

DROP ROLE IF EXISTS rausr_o;
DROP ROLE IF EXISTS rausr_x;
DROP ROLE IF EXISTS rausr_y;

RESET client_min_messages;

-- initial setup
CREATE USER rausr_o;	-- owner
CREATE USER rausr_x;
CREATE USER rausr_y;

SET SESSION AUTHORIZATION rausr_o;

CREATE TABLE ratbl_p
(
	a	int primary key,
	b	text
) WITH (row_level_acl=on);
GRANT all ON ratbl_p TO public;

CREATE TABLE ratbl_f
(
	x	int references ratbl_p(a)
		    ON DELETE SET NULL,
	y	text
) WITH (row_level_acl=on);
GRANT all ON ratbl_f TO public;

INSERT INTO ratbl_p VALUES (1, 'aaa');

INSERT INTO ratbl_p (security_acl, a, b)
       VALUES ('{rausr_x=r/rausr_o}',   2, 'bbb');
INSERT INTO ratbl_p (security_acl, a, b)
       VALUES ('{rausr_x=rw/rausr_o}',  3, 'ccc');
INSERT INTO ratbl_p (security_acl, a, b)
       VALUES ('{rausr_x=rd/rausr_o}',  4, 'ddd');
INSERT INTO ratbl_p (security_acl, a, b)
       VALUES ('{rausr_x=rx/rausr_o}',  5, 'eee');
INSERT INTO ratbl_p (security_acl, a, b)
       VALUES ('{rausr_x=x/rausr_o}',   6, 'fff');
INSERT INTO ratbl_p (security_acl, a, b)
       VALUES ('{rausr_x=wx/rausr_o}',  7, 'ggg');
INSERT INTO ratbl_p (security_acl, a, b)
       VALUES ('{rausr_x=dx/rausr_o}',  8, 'hhh');

INSERT INTO ratbl_p (security_acl, a, b)
       VALUES ('{rausr_y=r/rausr_o}',   9, 'BBB');
INSERT INTO ratbl_p (security_acl, a, b)
       VALUES ('{rausr_y=rw/rausr_o}', 10, 'CCC');
INSERT INTO ratbl_p (security_acl, a, b)
       VALUES ('{rausr_y=rd/rausr_o}', 11, 'DDD');
INSERT INTO ratbl_p (security_acl, a, b)
       VALUES ('{rausr_y=rx/rausr_o}', 12, 'EEE');
INSERT INTO ratbl_p (security_acl, a, b)
       VALUES ('{rausr_y=x/rausr_o}',  13, 'FFF');
INSERT INTO ratbl_p (security_acl, a, b)
       VALUES ('{rausr_y=wx/rausr_o}', 14, 'GGG');
INSERT INTO ratbl_p (security_acl, a, b)
       VALUES ('{rausr_y=dx/rausr_o}', 15, 'HHH');

INSERT INTO ratbl_p (security_acl, a, b)
       VALUES ('{rausr_x=rw/rausr_o,rausr_y=rd/rausr_o}', 20, 'xxx');
INSERT INTO ratbl_p (security_acl, a, b)
       VALUES ('{rausr_x=rd/rausr_o,rausr_y=rw/rausr_o}', 21, 'yyy');
INSERT INTO ratbl_p (security_acl, a, b)
       VALUES ('{rausr_x=r/rausr_o,rausr_y=r/rausr_o}',   22, 'zzz');

INSERT INTO ratbl_p (security_acl, a, b)
       VALUES (NULL, 30, 'xxx');	-- to be failed
INSERT INTO ratbl_p (security_acl, a, b)
       VALUES ('{invalid acl}', 30, 'xxx');	-- to be failed

-- it allows owner to see all tuples
SELECT security_acl, * FROM ratbl_p;

BEGIN;
UPDATE ratbl_p SET b = b || '_updt' RETURNING security_acl, *;
SELECT security_acl, * FROM ratbl_p;
ABORT;

BEGIN;
DELETE FROM ratbl_p RETURNING security_acl, *;
SELECT security_acl, * FROM ratbl_p;
ABORT;

-- switch to superuser
\c -

SELECT security_acl, * FROM ratbl_p;

BEGIN;
UPDATE ratbl_p SET b = b || '_updt' RETURNING security_acl, *;
ABORT;

BEGIN;
DELETE FROM ratbl_p RETURNING security_acl, *;
ABORT;

-- switch to rausr_x
SET SESSION AUTHORIZATION rausr_x;

SELECT security_acl, * FROM ratbl_p;

BEGIN;
UPDATE ratbl_p SET b = b || '_updt' RETURNING security_acl, *;
UPDATE ratbl_p SET b = b || '_updt';
SELECT security_acl, * FROM ratbl_p;
ABORT;

BEGIN;
DELETE FROM ratbl_p RETURNING security_acl, *;
DELETE FROM ratbl_p;
SELECT security_acl, * FROM ratbl_p;
ABORT;

\c -
-- switch to rausr_y
SET SESSION AUTHORIZATION rausr_y;

SELECT security_acl, * FROM ratbl_p;

BEGIN;
UPDATE ratbl_p SET b = b || '_updt' RETURNING security_acl, *;
UPDATE ratbl_p SET b = b || '_updt';
SELECT security_acl, * FROM ratbl_p;
ABORT;

BEGIN;
DELETE FROM ratbl_p RETURNING *;
DELETE FROM ratbl_p;
SELECT security_acl, * FROM ratbl_p;
ABORT;

\c -
-- switch to rausr_x again (For FK/PK testing)
SET SESSION AUTHORIZATION rausr_x;

INSERT INTO ratbl_p VALUES(6, 'fff');	-- to be failed

INSERT INTO ratbl_p (security_acl, a, b)
       VALUES ('{=r/rausr_x}', 30, 'xxx');	-- to be failed

INSERT INTO ratbl_f VALUES ( 1, 'red');
INSERT INTO ratbl_f VALUES ( 2, 'blue');		-- to be failed
INSERT INTO ratbl_f VALUES ( 5, 'green');
INSERT INTO ratbl_f VALUES ( 6, 'yellow');
INSERT INTO ratbl_f VALUES ( 7, 'orange');
INSERT INTO ratbl_f VALUES ( 8, 'pink');
INSERT INTO ratbl_f VALUES (10, 'white');	-- to be failed
INSERT INTO ratbl_f VALUES (12, 'black');	-- to be failed

SELECT security_acl, * FROM ratbl_f;

\c -
-- switch to rausr_o again
SET SESSION AUTHORIZATION rausr_o;

UPDATE ratbl_f SET security_acl = '{rausr_x=r/rausr_o}' WHERE x = 5;
UPDATE ratbl_f SET security_acl = '{rausr_x=x/rausr_o}' WHERE x = 6;
UPDATE ratbl_f SET security_acl = '{rausr_x=w/rausr_o}' WHERE x = 7;
UPDATE ratbl_f SET security_acl = '{rausr_x=d/rausr_o}' WHERE x = 8;

\c -
-- switch to rausr_x again
SET SESSION AUTHORIZATION rausr_x;

SELECT security_acl, * FROM ratbl_p;
SELECT security_acl, * FROM ratbl_f;

UPDATE ratbl_p SET a = 300 WHERE a = 3;
UPDATE ratbl_p SET a = 700 WHERE a = 7;		-- to be failed

DELETE FROM ratbl_p WHERE a = 4;
DELETE FROM ratbl_p WHERE a = 8;		-- to be failed

SELECT security_acl, * FROM ratbl_p;

\c -
-- switch to rausr_o again (TABLE Option related)
SET SESSION AUTHORIZATION rausr_o;

DELETE FROM ratbl_p WHERE a > 8;

ALTER TABLE ratbl_p SET (row_level_acl=off);

INSERT INTO ratbl_p VALUES (40, 'foo');
INSERT INTO ratbl_p VALUES (41, 'var');
INSERT INTO ratbl_p (security_acl, a, b)
       VALUES ('{rausr_y=rx/rausr_o}', 42, 'baz');	-- to be failed

SELECT security_acl, * FROM ratbl_p;

ALTER TABLE ratbl_p SET (row_level_acl=on);

INSERT INTO ratbl_p (security_acl, a, b)
       VALUES ('{rausr_y=rx/rausr_o}', 42, 'baz');

SELECT security_acl, * FROM ratbl_p;

ALTER TABLE ratbl_p SET (default_row_acl='{rausr_x=rd/rausr_o,rausr_y=rw}');

INSERT INTO ratbl_p VALUES (50, 'coffee');
INSERT INTO ratbl_p (security_acl, a, b)
       VALUES ('{rausr_x=r/rausr_o}', 51, 'juice');
SELECT security_acl, * FROM ratbl_p;

ALTER TABLE ratbl_p RESET (default_row_acl);

INSERT INTO ratbl_p VALUES (52, 'coke');
INSERT INTO ratbl_p (security_acl, a, b)
       VALUES ('{rausr_x=rwd/rausr_o}', 53, 'red tea');	-- to be failed
SELECT security_acl, * FROM ratbl_p;

\c -
-- cleanups
SET client_min_messages TO 'error';

DROP TABLE IF EXISTS ratbl_f CASCADE;
DROP TABLE IF EXISTS ratbl_p CASCADE;

DROP ROLE IF EXISTS rausr_o;
DROP ROLE IF EXISTS rausr_x;
DROP ROLE IF EXISTS rausr_y;

RESET client_min_messages;
