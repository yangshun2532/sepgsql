/*
 * src/backend/security/common/ac_database.c
 *   common access control abstration corresponding to database
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_namespace.h"
#include "commands/dbcommands.h"
#include "miscadmin.h"
#include "security/common.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"

/*
 * ac_namespace_create
 *
 * It checks privileges to create a new namespace object
 *
 * [Params]
 *   nspName  : Name of the new namespace object
 *   nspOwner : OID of the namespace owner
 *   isTemp   : True, if the namespace is temporay
 */
void
ac_namespace_create(const char *nspName, Oid nspOwner, bool isTemp)
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
 * ac_namespace_alter
 *
 * It checks privileges to alter a certain namespace object
 *

 * [Params]
 *  nspOid   : OID of the namespace to be altered
 *  newName  : New name of the namespace, if exist
 *  newOwner : OID of the new namespace owner, if exist
 */
void
ac_namespace_alter(Oid nspOid, const char *newName, Oid newOwner)
{
	AclResult	aclresult;

	/* must be owner for all the ALTER SCHEMA options */
	if (!pg_namespace_ownercheck(nspOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_NAMESPACE,
					   get_namespace_name(nspOid));

	/* must have CREATE privilege on database to rename */
	if (newName)
	{
		aclresult = pg_database_aclcheck(MyDatabaseId, GetUserId(),
										 ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_DATABASE,
						   get_database_name(MyDatabaseId));
	}

	if (OidIsValid(newOwner))
	{
		/* Must be able to become new owner */
		check_is_member_of_role(GetUserId(), newOwner);
	}
}

/*
 * ac_namespace_drop
 *
 * It checks privileges to drop a certain namespace object
 *
 * [Params]
 *  nspOid  : OID of the namespace to be dropped
 *  cascade : True, if cascaded deletion
 */
void
ac_namespace_drop(Oid nspOid, bool cascade)
{
	if (!cascade &&
		!pg_namespace_ownercheck(nspOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_NAMESPACE,
					   get_namespace_name(nspOid));
}

/*
 * ac_namespace_grant
 *
 * It checks privileges to grant/revoke permissions on a certain namespace
 *
 * [Params]
 *  nspOid   : OID of the target namespace for GRANT/REVOKE
 *  isGrant  : True, if the statement is GRANT
 *  privs    : AclMask being tries to be granted
 *  grantor  : OID of the gractor role
 *  goptions : Available AclMask available to grant others
 */
void
ac_namespace_grant(Oid nspOid, bool isGrant, AclMode privs,
				   Oid grantor, AclMode goptions)
{
	if (goptions == ACL_NO_RIGHTS)
	{
		AclMode		whole_mask = ACL_ALL_RIGHTS_NAMESPACE;

		if (pg_namespace_aclmask(nspOid, grantor, 
								 whole_mask | ACL_GRANT_OPTION_FOR(whole_mask),
								 ACLMASK_ANY) == ACL_NO_RIGHTS)
			aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_DATABASE,
						   get_namespace_name(nspOid));
	}
}

/*
 * ac_namespace_search
 *
 * It checks privileges to search a certain namespace
 *
 * [Params]
 *  nspOid : OID of the target namespace
 *  abort  : True, if caller want to raise an error, if violated
 */
bool
ac_namespace_search(Oid nspOid, bool abort)
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
 * ac_namespace_comment
 *
 * It checks privileges to comment on a certain namespace
 *
 * [Params]
 *  nspOid : OID of the namespace to be commented on
 */
void
ac_namespace_comment(Oid nspOid)
{
	if (!pg_namespace_ownercheck(nspOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_NAMESPACE,
					   get_namespace_name(nspOid));
}
