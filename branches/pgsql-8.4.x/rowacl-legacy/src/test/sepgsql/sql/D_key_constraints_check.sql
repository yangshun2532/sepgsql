--
-- testcases of cleanup of tuple level access control
--
-- selinux_user: unconfined_u
-- selinux_role: unconfined_r
-- selinux_type: unconfined_t
-- selinux_range: s0

SELECT security_context, * FROM d1;
SELECT security_context, * FROM d2;

-- invisible PK
INSERT INTO d1 VALUES (5, 'EEE_ins');
INSERT INTO d1 VALUES (2, 'BBB_ins');	-- to be failed

-- visible PK, and invisible FK
DELETE FROM d1 WHERE id IN (1);
DELETE FROM d1 WHERE id IN (4);		-- to be failed

-- invisible PK with new FK
INSERT INTO d2 VALUES (4, 'ZZZ_ins');
INSERT INTO d2 VALUES (3, 'YYY_ins');	-- to be failed
