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
-- Test F : Extended SQL Grammer
-- -------------------------------------------------------


-- -------------------------------------------------------
-- Test G : Large Object
-- -------------------------------------------------------

