/*
 * ace_schema.c
 *
 * security hooks related to schema object class.
 *
 * Portions Copyright (c) 1996-2010, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "commands/dbcommands.h"
#include "miscadmin.h"
#include "security/ace.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"

/*
 * check_schema_create
 *
 * It enables security providers to check permission to create
 * a new schema object.
 *
 * nspName : Name of the new schema object
 * nspOwner : OID of the new schema owner
 * isTemp : True, if it is a temporary schema.
 */
void
check_schema_create(const char *nspName, Oid nspOwner, bool isTemp)
{
	AclResult	aclresult;

	/*
	 * To create a schema, must have (temporary) schema-create privilege
	 * on the current database and must be able to become the target role
	 * (this does not imply that the target role itself must have create-schema
	 * privilege), if not temporary schema.
	 * The latter provision guards against "giveaway" attacks.  Note that a
	 * superuser will always have both of these privileges a fortiori.
	 */
	aclresult = pg_database_aclcheck(MyDatabaseId, GetUserId(),
									 isTemp ? ACL_CREATE_TEMP : ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_DATABASE,
					   get_database_name(MyDatabaseId));

	if (!isTemp)
		check_is_member_of_role(GetUserId(), nspOwner);
}

/*
 * check_schema_alter_rename
 *
 * It enables security providers to check permission to alter
 * name of a certain schema object.
 *
 * nspOid : OID of the schema to be renamed
 * newName : New name of the schema
 */
void
check_schema_alter_rename(Oid nspOid, const char *newName)
{
	AclResult	aclresult;

	/* Must be owner for all the ALTER SCHEMA options */
	if (!pg_namespace_ownercheck(nspOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_NAMESPACE,
					   get_namespace_name(nspOid));

	/* must have CREATE privilege on database to rename */
	aclresult = pg_database_aclcheck(MyDatabaseId, GetUserId(),
									 ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_DATABASE,
					   get_database_name(MyDatabaseId));

}

/*
 * check_schema_alter_owner
 *
 * It enables security providers to check permission to alter
 * ownership of a certain schema object.
 *
 * nspOid : OID of the schema to be altered
 * newOwner : New owner of the schema
 */
void
check_schema_alter_owner(Oid nspOid, Oid newOwner)
{
	AclResult	aclresult;

	/* Must be owner for all the ALTER SCHEMA options */
	if (!pg_namespace_ownercheck(nspOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_NAMESPACE,
					   get_namespace_name(nspOid));

	/* Must be able to become new owner */
	check_is_member_of_role(GetUserId(), newOwner);

	/*
	 * must have create-schema rights
	 *
	 * NOTE: This is different from other alter-owner checks in that the
	 * current user is checked for create privileges instead of the
	 * destination owner.  This is consistent with the CREATE case for
	 * schemas.  Because superusers will always have this right, we need
	 * no special case for them.
	 */
	aclresult = pg_database_aclcheck(MyDatabaseId, GetUserId(),
									 ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_DATABASE,
					   get_database_name(MyDatabaseId));
}

/*
 * check_schema_drop
 *
 * It enables security providers to check permission to drop a certain
 * schema obejct.
 *
 * nspOid : OID of the schema to be dropped
 * cascade : True, if cascaded deletion.
 */
void
check_schema_drop(Oid nspOid, bool cascade)
{
	if (!cascade &&
		!pg_namespace_ownercheck(nspOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_NAMESPACE,
					   get_namespace_name(nspOid));
}

/*
 * check_schema_grant
 *
 * It enables security providers to check permission to grant/revoke
 * the default PG permissions on a certain schema.
 * The caller (aclchk.c) handles the default PG privileges well,
 * so rest of enhanced security providers can apply its checks here.
 *
 * nspOid : OID of the schema to be granted/revoked
 */
void
check_schema_grant(Oid nspOid)
{
	/* do nothing here */
}

/*
 * check_schema_search
 *
 * It enables security provides to check permission to search database
 * objects under a certain schema.
 *
 * Note that we handles "pg_temp" schema as an exception.
 * It is indeed a schema in fact, and in implementation. but it is an
 * internal details from the perspective of users.
 * Any security providers launched from this hook shall always return
 * 'true' on the temporary schema. Even if it tries to apply access
 * controls on temporary schema, this hook is not called when the schema
 * is obviously temporary.
 *
 * nspOid : OID of the schema to be searched 
 * abort : True, if the caller want to raise an error on violation.
 */
bool
check_schema_search(Oid nspOid, bool abort)
{
	AclResult	aclresult;

	aclresult = pg_namespace_aclcheck(nspOid, GetUserId(),
									  ACL_USAGE);
	if (aclresult != ACLCHECK_OK)
	{
		if (abort)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(nspOid));
		return false;
	}

	return true;
}

/*
 * check_schema_comment
 *
 * It enables security provides to check permission to comment on
 * a certain schema object.
 *
 * nspOid : OID of the schema to be commented
 */
void
check_schema_comment(Oid nspOid)
{
	if (!pg_namespace_ownercheck(nspOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_NAMESPACE,
					   get_namespace_name(nspOid));
}
