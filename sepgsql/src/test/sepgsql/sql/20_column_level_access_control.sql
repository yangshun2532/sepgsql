--
-- initial setup of column level access control
--
-- selinux_user: unconfined_u
-- selinux_role: unconfined_r
-- selinux_type: unconfined_t
-- selinux_range: s0-s0:c0.c15

-- CREATE TABLE with explicit context

CREATE TABLE t1
(
	a  INTEGER
	   SECURITY_CONTEXT = 'system_u:object_r:sepgsql_secret_table_t:s0',
	b  TEXT,
	c  TEXT
) SECURITY_CONTEXT = 'system_u:object_r:sepgsql_ro_table_t:s0';

SELECT security_context, relname FROM pg_class
       WHERE relname ='t1' and relnamespace = 2200;

SELECT security_context, attname FROM pg_attribute
       WHERE attrelid in (SELECT oid FROM pg_class WHERE relname ='t1' and relnamespace = 2200);

-- ALTER TABLE with SECURITY_CONTEXT
CREATE TABLE t2
(
	a	TEXT,
	b	TEXT,
	c	TEXT,
	d	TEXT
);

ALTER TABLE t2 ALTER b SECURITY_CONTEXT = 'system_u:object_r:sepgsql_ro_table_t:s0';
ALTER TABLE t2 ALTER c SECURITY_CONTEXT = 'system_u:object_r:sepgsql_secret_table_t:s0';
ALTER TABLE t2 ALTER d SECURITY_CONTEXT = 'system_u:object_r:sepgsql_fixed_table_t:s0';

SELECT security_context, relname FROM pg_class
       WHERE relname ='t2' and relnamespace = 2200;

SELECT security_context, attname FROM pg_attribute
       WHERE attrelid in (SELECT oid FROM pg_class WHERE relname ='t2' and relnamespace = 2200);
