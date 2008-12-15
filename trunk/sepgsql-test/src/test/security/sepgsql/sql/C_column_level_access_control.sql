--
-- testcases of column level access control
--
-- selinux_user: unconfined_u
-- selinux_role: unconfined_r
-- selinux_type: sepgsql_test_t
-- selinux_range: s0

SELECT * FROM c1;	-- to be failed

SELECT b, c FROM c1;

SELECT b, c FROM c1 WHERE a > 10;	-- to be failed

UPDATE c1 SET b = 'mokeke';		-- to be failed

SELECT * FROM c2;	-- to be failed

SELECT b, d FROM c2;

INSERT INTO c2 (a, b, d) VALUES ('aaa', 'bbb', 'ddd');	-- to be failed

INSERT INTO c2 (a, d) VALUES ('aaa', 'ddd');

UPDATE c2 SET a = a || '_update', d = d || '_update';	-- to be failed

DELETE FROM c2;
