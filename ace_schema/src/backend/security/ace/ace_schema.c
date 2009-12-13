/*
 * ace_schema.c
 *
 * security hooks related to schema object class.
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
 * ace_schema_create
 *
 * It enables security providers to apply permission checks to create
 * a new schema object.
 *
 * nspName : Name of the new schema object
 * nspOwner : OID of the new schema owner
 * isTemp : True, if it is a temporary schema.
 */
void
ace_schema_create(const char *nspName, Oid nspOwner, bool isTemp)
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
 * ace_schema_alter
 *
 * It enables security providers to apply permission checks to alter
 * properties of a certain schema object.
 *
 * nspOid : OID of the schema to be altered
 * newName : New name of the schema, if given. Or, NULL.
 * newOwner : OID of the new owner, if given, Or, InvalidOid.
 */
void
ace_schema_alter(Oid nspOid, const char *newName, Oid newOwner)
{
	AclResult	aclresult;

	/* Must be owner for all the ALTER SCHEMA options */
	if (!pg_namespace_ownercheck(nspOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_NAMESPACE,
					   get_namespace_name(nspOid));

	/* ALTER SCHEMA ... RENAME TO */
	if (newName)
	{
		/* must have CREATE privilege on database to rename */
		aclresult = pg_database_aclcheck(MyDatabaseId, GetUserId(),
										 ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_DATABASE,
						   get_database_name(MyDatabaseId));
	}

	/* ALTER SCHEMA ... OWNER TO */
	if (OidIsValid(newOwner))
	{
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
}

/*
 * ace_schema_drop
 *
 * It enables security providers to apply permission checks to drop
 * a certain schema obejct.
 *
 * nspOid : OID of the schema to be dropped
 * cascade : True, if cascaded deletion.
 */
void
ace_schema_drop(Oid nspOid, bool cascade)
{
	if (!cascade &&
		!pg_namespace_ownercheck(nspOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_NAMESPACE,
					   get_namespace_name(nspOid));
}

/*
 * ace_schema_grant
 *
 * It enables security provides to check permission to grant/revoke
 * privileges in the default PG model.
 *
 * nspOid : OID of the schema to be granted/revoked
 * grantor : OID of the grantor role
 * goptions : Available AclMask available to grant others
 */
void
ace_schema_grant(Oid nspOid, Oid grantor, AclMode goptions)
{
	if (goptions == ACL_NO_RIGHTS)
	{
		/*
		 * If we found no grant options, consider whether to issue a hard
		 * error. Per spec, having any privilege at all on the object will
		 * get you by here.
		 */
		AclMode		whole_mask = ACL_ALL_RIGHTS_NAMESPACE;

		if (pg_namespace_aclmask(nspOid, grantor,
								 whole_mask | ACL_GRANT_OPTION_FOR(whole_mask),
								 ACLMASK_ANY) == ACL_NO_RIGHTS)
			aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_DATABASE,
						   get_namespace_name(nspOid));
	}
}

/*
 * ace_schema_search
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
 * is obviously temporary one.
 *
 * nspOid : OID of the schema to be searched 
 * abort : True, if the caller want to raise an error on violation.
 */
bool
ace_schema_search(Oid nspOid, bool abort)
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
 * ace_schema_comment
 *
 * It enables security provides to check permission to comment on
 * a certain schema object.
 *
 * nspOid : OID of the schema to be commented
 */
void
ace_schema_comment(Oid nspOid)
{
	if (!pg_namespace_ownercheck(nspOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_NAMESPACE,
					   get_namespace_name(nspOid));
}
