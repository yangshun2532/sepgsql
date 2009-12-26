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
 * Note that this operation is a combination of modification of the table's
 * property and creation of the new column. So, if security provider can
 * apply all the checks in the check_relation_alter(), it is not necessary
 * to apply any permission checks here.
 * Also note that this check is not called on the creation of the column
 * due to CREATE TABLE, so use check_relation_create() instead.
 *
 * relOid : OID of the relation that shall own the new column
 * colDef : definition of the new column
 */
void
check_attribute_create(Oid relOid, ColumnDef *cdef)
{
	/*
	 * For that purpose, the default PG privilege checks ownership of
	 * the relation that shall own the new column. It is already checked
	 * in the check_relation_alter(), so we don't check anything here.
	 */
}

/*
 * check_attribute_alter
 *
 * It checks privileges to alter properties of a certain column
 * using ALTER TABLE statement.
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
 * It checks privileges to drop a certain column using ALTER TABLE statement.
 * Note that this operation is a combination of modification of the table's
 * property and deletion of the column. So, if security provider can apply
 * all the checks in the check_relation_alter(), it is not necessary to apply
 * any other permission checks here.
 * Also note that this check is not called on the creation of the column
 * due to DROP TABLE, so also use the check_relation_drop().
 *
 * relOid : OID of the relation that owns the target column
 * attName : Name of the column to be dropped
 * cascade : True, if it was called due to the cascaded deletion
 */
void
check_attribute_drop(Oid relOid, const char *colName, bool cascade)
{
	/*
	 * For that purpose, the default PG privilege checks ownership of
	 * the relation that shall own the new column. It is already checked
	 * in the check_relation_alter(), so we don't check anything here.
	 */
}

/*
 * check_attribute_grant
 *
 * It checks privileges to grant/revoke the default PG permissions on
 * a certain column.
 * The caller (aclchk.c) handles the default PG privileges well,
 * so rest of enhanced security providers can apply its checks here.
 *
 * relOid : OID of the relation that owns the target column
 * colName : Name of the column to be granted/revoked
 */
void
check_attribute_grant(Oid relOid, AttrNumber attnum)
{
	/*
	 * Now we don't check anything here
	 */
}

/*
 * check_attribute_comment
 *
 * It checks privileges to comment on a certain column
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
