/*
 * ace_attribute.c
 *
 * security hooks related to attribute object class.
 *
 * Portions Copyright (c) 1996-2010, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "miscadmin.h"
#include "security/ace.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"

/*
 * check_attribute_create
 *
 * It checks privileges to create a new column using ALTER TABLE statement.
 * If violated, it shall raise an error.
 *
 * Note that this check is not invoked on creation of new columns due to
 * CREATE TABLE, so use check_relation_create() instead.
 *
 * relOid : OID of the relation that shall own the new column
 * colDef : definition of the new column
 */
void
check_attribute_create(Oid relOid, ColumnDef *cdef)
{
	/*
	 * The default PG privilege checks ownership of the relation which
	 * will own the new column, because it doesn't have individual owner
	 * property of the column.
	 */
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * check_attribute_alter
 *
 * It checks privileges to alter properties of the specified column
 * using ALTER TABLE statement.
 * If violated, it shall raise an error.
 *
 * relOid : OID of the relation that owns the target column
 * colName : Name of the column to be altered
 */
void
check_attribute_alter(Oid relOid, const char *colName)
{
	/*
	 * The default PG privilege checks ownership of the relation which
	 * owns the target column, instead of the column itself, because
	 * it does not have individual owner property.
	 */
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * check_attribute_drop
 *
 * It checks privileges to drop the specified column using ALTER TABLE
 * statement.
 * If violated, it shall raise an error.
 *
 * Note that this check is not invoked on deletion of columns due
 * to DROP TABLE, so also use the check_relation_drop().
 *
 * relOid : OID of the relation that owns the target column
 * attName : Name of the column to be dropped
 * cascade : True, if it was called due to the cascaded deletion
 */
void
check_attribute_drop(Oid relOid, const char *colName, bool cascade)
{
	/*
	 * The default PG privilege checks ownership of the relation owning
	 * the target column, because it doesn't have individual owner property
	 * of the column.
	 */
	if (!cascade &&
		!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * check_attribute_grant
 *
 * It checks privileges to grant/revoke the default PG permissions on
 * the specified column.
 * The caller (aclchk.c) handles the default PG privileges well,
 * so rest of enhanced security providers can apply its checks here.
 * If violated, it shall raise an error.
 *
 * relOid : OID of the relation that owns the target column
 * colName : Name of the column to be granted/revoked
 */
void
check_attribute_grant(Oid relOid, AttrNumber attnum)
{
	/* right now, no enhanced security providers */
}

/*
 * check_attribute_comment
 *
 * It checks privileges to comment on the specified column.
 * If violated, it shall raise an error.
 *
 * relOid : OID of the relation that owns the target column
 * colName : Name of the column to be commented on
 */
void
check_attribute_comment(Oid relOid, const char *colName)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}
