--
-- SE-PostgreSQL testcases : Set Operations/WITH RECURSIVE
--
-- selinux_user: unconfined_u
-- selinux_role: unconfined_r
-- selinux_type: sepgsql_test_t
-- selinux_range: s0:c0

WITH RECURSIVE h9 AS
(
	SELECT security_context, * FROM h1 WHERE pid is NULL

	UNION ALL

	SELECT h1.security_context, h1.* FROM h1,h9 WHERE h1.pid = h9.id
)
SELECT * FROM h9;

WITH h9 AS (SELECT * FROM h2)
SELECT * FROM h9;		-- to be failed

WITH h9 AS (SELECT t FROM h2)
SELECT t FROM h9;

SELECT * FROM h3
UNION
SELECT * FROM h4;

SELECT * FROM h3
INTERSECT
SELECT * FROM h4;

SELECT * FROM h3
EXCEPT
SELECT * FROM h4;


