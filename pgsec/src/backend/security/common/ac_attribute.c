/*
 * src/backend/security/common/ac_attribute.c
 *   common access control abstration corresponding to attributes objects
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "miscadmin.h"
#include "security/common.h"
#include "utils/lsyscache.h"

/*
 * ac_attribute_create
 *
 * It checks privilege to create a new column using ALTER TABLE
 * statement.
 * Note that this check is not called on CREARE TABLE, so use
 * the ac_class_create() instead, if necessary.
 *
 * [Params]
 *   relOid : OID of the relation to be altered
 *   cdef   : Definition of the new column
 */
void
ac_attribute_create(Oid relOid, ColumnDef *cdef)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * ac_attribute_alter
 *
 * It checks privilege to alter definition of a certain column
 * using ALTER TABLE statement.
 *
 * [Params]
 *   relOid : OID of the relation to be altered
 *   cdef   : Name of the target column
 */
void
ac_attribute_alter(Oid relOid, const char *colName)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * ac_attribute_drop
 *
 * It checks privilege to drop a certain column using ALTER TABLE
 * statement. Note that this check is not called on DROP TABLE, so
 * use the ac_class_drop() instead, if necessary.
 *
 * [Params]
 *   relOid  : OID of the relation to be altered
 *   colName : Name of the target column
 */
void
ac_attribute_drop(Oid relOid, const char *colName)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * ac_attribute_grant
 *
 * It checks privileges to grant/revoke permissions on a certain attribute
 *
 * [Params]
 *   relOid   : OID of the target relation for GRANT/REVOKE
 *   attnum   : Attribute number of the target column for GRANT/REVOKE
 *   isGrant  : True, if the statement is GRANT
 *   privs    : AclMask being tries to be granted/revoked
 *   grantor  : OID of the gractor role
 *   goptions : Available AclMask available to grant others
 */
void
ac_attribute_grant(Oid relOid, AttrNumber attnum,
				   bool isGrant, AclMode privs,
				   Oid grantor, AclMode goptions)
{
	if (goptions == ACL_NO_RIGHTS)
	{
		AclMode		whole_mask = ACL_ALL_RIGHTS_COLUMN;

		if (pg_class_aclmask(relOid, grantor,
							 whole_mask | ACL_GRANT_OPTION_FOR(whole_mask),
							 ACLMASK_ANY) == ACL_NO_RIGHTS ||
			pg_attribute_aclmask(relOid, attnum, grantor,
								 whole_mask | ACL_GRANT_OPTION_FOR(whole_mask),
								 ACLMASK_ANY) == ACL_NO_RIGHTS)
			aclcheck_error_col(ACLCHECK_NO_PRIV, ACL_KIND_COLUMN,
							   get_rel_name(relOid),
							   get_attname(relOid, attnum));
	}
}

/*
 * ac_attribute_comment
 *
 * It checks privilege to comment on a certain attribute
 *
 * [Params]
 *   relOid  : OID of the relation which contains the target
 *   colName : Name of the target attribute
 */
void
ac_attribute_comment(Oid relOid, const char *colName)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}
