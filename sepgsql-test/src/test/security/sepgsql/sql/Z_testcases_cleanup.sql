--
-- Initial setup of SE-PostgreSQL testcases
--
-- selinux_user: unconfined_u
-- selinux_role: unconfined_r
-- selinux_type: unconfined_t
-- selinux_range: s0-s0:c0.c15

-- -------------------------------------------------------
-- Test B : Row-Level Access Control
-- -------------------------------------------------------

-- memo: to confirm default security context on INSERT
SELECT security_context, * FROM b1;
SELECT security_context, * FROM b2;

DROP TABLE b1;
DROP TABLE b2;

-- -------------------------------------------------------
-- Test C : Column-Level Access Control
-- -------------------------------------------------------

DROP TABLE c1;
DROP TABLE c2;

-- -------------------------------------------------------
-- Test D : PK/FK constraint
-- -------------------------------------------------------

DROP TABLE d2;
DROP TABLE d1;

-- -------------------------------------------------------
-- Test E : Trusted Procedure
-- -------------------------------------------------------

DROP TABLE e1;
DROP FUNCTION e2(integer);
DROP FUNCTION e3();

-- -------------------------------------------------------
-- Test F : Large Object
-- -------------------------------------------------------

SELECT lo_unlink(6001);
SELECT lo_unlink(6002);
SELECT lo_unlink(6003);
SELECT lo_unlink(6004);


-- -------------------------------------------------------
-- Test G : Copy To/From
-- -------------------------------------------------------

COPY g1 (security_context, a, b) TO stdout;
COPY g2 (security_context, x, y, z) TO stdout;
DROP TABLE g1;
DROP TABLE g2;

-- -------------------------------------------------------
-- Test H : Set Operations/With Recursive
-- -------------------------------------------------------

WITH RECURSIVE h9 AS
(
	SELECT security_context, * FROM h1 WHERE pid is NULL

	UNION ALL

	SELECT h1.security_context, h1.* FROM h1,h9 WHERE h1.pid = h9.id
)
SELECT * FROM h9;

SELECT * FROM h3;

SELECT * FROM h4;

DROP TABLE h1;
DROP TABLE h2;
DROP TABLE h3;
DROP TABLE h4;
