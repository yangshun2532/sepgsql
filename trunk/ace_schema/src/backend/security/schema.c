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
 * It checks privileges to create a new schema with the given parameters.
 * If violated, it shall raise an error.
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
 * It checks privileges to alter name of the specified schema.
 * If violated, it shall raise an error.
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
 * It checks privileges to alter ownership of the specified schema.
 * If violated, it shall raise an error.
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
 * It checks privileges to drop the specified schema.
 * If violated, it shall raise an error.
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
 * It checks privileges to grant/revoke the default PG permissions on
 * the specified schema.
 * The caller (aclchk.c) handles the default PG privileges well,
 * so, this hook is just an entrypoint for additional checks.
 * If violated, it shall raise an error.
 */
void
check_schema_grant(Oid nspOid)
{
	/* right now, no enhanced security providers */
}

/*
 * check_schema_search
 *
 * It checks privileges to search database objects owned by the specified 
 * schema.
 * If violated, it shall raise an error, or return false when the `abort'
 * is not true.
 *
 * Note that we handles "pg_temp" schema as an exception.
 * It is indeed a schema in fact, and in implementation. but it is an
 * internal details from the perspective of users. So, this hook always
 * return `true' for temporary schemas.
 * Also note that this hook is not called on the code path, when the
 * schema is obviously temporary, because it shall be always allowed.
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
 * It checks privileges to comment on the specified schema.
 * If violated, it raised an error.
 */
void
check_schema_comment(Oid nspOid)
{
	if (!pg_namespace_ownercheck(nspOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_NAMESPACE,
					   get_namespace_name(nspOid));
}
