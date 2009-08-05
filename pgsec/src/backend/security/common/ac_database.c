/*
 * src/backend/security/common/ac_database.c
 *   common access control abstration corresponding to database
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_authid.h"
#include "catalog/pg_database.h"
#include "commands/dbcommands.h"
#include "commands/tablespace.h"
#include "miscadmin.h"
#include "security/common.h"
#include "utils/syscache.h"

/* Helper functions */
static bool
have_createdb_privilege(void)
{
	bool		result = false;
	HeapTuple	utup;

	/* Superusers can always do everything */
	if (superuser())
		return true;

	utup = SearchSysCache(AUTHOID,
						  ObjectIdGetDatum(GetUserId()),
						  0, 0, 0);
	if (HeapTupleIsValid(utup))
	{
		result = ((Form_pg_authid) GETSTRUCT(utup))->rolcreatedb;
		ReleaseSysCache(utup);
	}
	return result;
}

/*
 * ac_database_create
 *
 * It checks privileges to create a new database.
 *
 * [Params]
 *  datName   : Name of the new database 
 *  srcDatOid : OID of the source database
 *  srcIsTemp : True, if the source database is template
 *  datOwner  : OID of the new database owner
 *  datTblspc : OID of the new default tablespace, if given
 */
void
ac_database_create(const char *datName, Oid srcDatOid, bool srcIsTemp,
				   Oid datOwner, Oid datTblspc)
{
	AclResult	aclresult;

	/*
	 * To create a database, must have createdb privilege and must be able to
	 * become the target role (this does not imply that the target role itself
	 * must have createdb privilege).  The latter provision guards against
	 * "giveaway" attacks.	Note that a superuser will always have both of
	 * these privileges a fortiori.
	 */
	if (!have_createdb_privilege())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied to create database")));

	check_is_member_of_role(GetUserId(), datOwner);


	/*
	 * Permission check: to copy a DB that's not marked datistemplate, you
	 * must be superuser or the owner thereof.
	 */
	if (!srcIsTemp)
	{
		if (!pg_database_ownercheck(srcDatOid, GetUserId()))
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("permission denied to copy database \"%s\"",
							get_database_name(srcDatOid))));
	}

	/*
	 * Check permissions to use a certain tablespace as a default one
	 * on the new database
	 */
	if (OidIsValid(datTblspc))
	{
		aclresult = pg_tablespace_aclcheck(datTblspc, GetUserId(),
										   ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_TABLESPACE,
						   get_tablespace_name(datTblspc));
	}
}

/*
 * ac_database_alter
 *
 * It checks privileges to alter a certain database.
 *
 * [Params]
 *  datOid    : OID of the database to be altered
 *  newName   : New name of the database, if exist
 *  newTblspc : OID of the new default tablespace, if exist
 *  newOwner  : OID of the new owner, if exist
 *  newAcl    : Pointer to set a new acl datum, when newOwner is valid.
 */
void
ac_database_alter(Oid datOid, const char *newName,
				  Oid newTblspc, Oid newOwner, Datum *newAcl)
{
	AclResult	aclresult;

	/* Must be owner for all the ALTER DATABASE options */
	if (!pg_database_ownercheck(datOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_DATABASE,
					   get_database_name(datOid));

	/* Must have createdb right for renaming */
	if (newName)
	{
		if (!have_createdb_privilege())
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("permission denied to rename database")));
	}

	/* Must have ACL_CREATE for the new default tablespace */
	if (OidIsValid(newTblspc))
	{
		aclresult = pg_tablespace_aclcheck(newTblspc, GetUserId(),
										   ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_TABLESPACE,
						   get_tablespace_name(newTblspc));
	}

	if (OidIsValid(newOwner))
	{
		Form_pg_database	datForm;
		HeapTuple	dattup;
		Datum		acldat;
		bool		isnull;
		Acl		   *acl = NULL;

		/* Must be able to become new owner */
		check_is_member_of_role(GetUserId(), newOwner);

		/*
		 * must have createdb rights
		 *
		 * NOTE: This is different from other alter-owner checks in that the
		 * current user is checked for createdb privileges instead of the
		 * destination owner.  This is consistent with the CREATE case for
		 * databases.  Because superusers will always have this right, we need
		 * no special case for them.
		 */
		if (!have_createdb_privilege())
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("permission denied to change owner of database")));

		dattup = SearchSysCache(DATABASEOID,
								ObjectIdGetDatum(datOid),
								0, 0, 0);
		if (!HeapTupleIsValid(dattup))
			elog(ERROR, "cache lookup failed for database %u", datOid);
		datForm = (Form_pg_database) GETSTRUCT(dattup);

		/*
		 * Determine the modified ACL for the new owner.
		 */
		acldat = SysCacheGetAttr(DATABASEOID, dattup,
								 Anum_pg_database_datacl, &isnull);
		if (!isnull)
			acl = aclnewowner(DatumGetAclP(acldat),
							  datForm->datdba, newOwner);
		*newAcl = PointerGetDatum(acl);

		ReleaseSysCache(dattup);
	}
}

/*
 * ac_database_drop
 *
 * It checks privileges to drop a certain database
 *
 * [Params]
 *  datOid  : OID of the database to be dropped
 *  cascade : True, if cascaded deletion
 */
void
ac_database_drop(Oid datOid, bool cascade)
{
	if (!cascade &&
		!pg_database_ownercheck(datOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_DATABASE,
					   get_database_name(datOid));
}

/*
 * ac_database_grant
 *
 * It checks privileges to grant/revoke permissions on a certain database.
 *
 * [Params]
 *  datOid     : OID of the target database for GRANT/REVOKE
 *  isGrant    : True, if the statement is GRANT
 *  privileges : AclMask being tries to be granted
 *  grantor    : OID of the gractor role
 *  goptions   : Available AclMask available to grant others
 */
void
ac_database_grant(Oid datOid, bool isGrant, AclMode privileges,
				  Oid grantor, AclMode goptions)
{
	if (goptions == ACL_NO_RIGHTS)
	{
		AclMode		whole_mask = ACL_ALL_RIGHTS_DATABASE;

		if (pg_database_aclmask(datOid, grantor, 
								whole_mask | ACL_GRANT_OPTION_FOR(whole_mask),
								ACLMASK_ANY) == ACL_NO_RIGHTS)
			aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_DATABASE,
						   get_database_name(datOid));
	}
}

/*
 * ac_database_connect
 *
 * It checks privileges to connect on the database
 * If violated, it raises a FATAL error to disconnect soon.
 *
 * [Params]
 *  datOid : OID of the database to be connected
 *
 */
void
ac_database_connect(Oid datOid)
{
	if (pg_database_aclcheck(MyDatabaseId, GetUserId(),
							 ACL_CONNECT) != ACLCHECK_OK)
		ereport(FATAL,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied for database \"%s\"",
						get_database_name(datOid)),
				 errdetail("User does not have CONNECT privilege.")));
}

/*
 * ac_database_calculate_size
 *
 * It checks privileges to calculate size of a certain database
 *
 * [Params]
 *  datOid : OID of the target database
 */
void
ac_database_calculate_size(Oid datOid)
{
	AclResult	aclresult;

	/* User must have connect privilege for target database */
	aclresult = pg_database_aclcheck(datOid, GetUserId(),
									 ACL_CONNECT);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_DATABASE,
					   get_database_name(datOid));
}

/*
 * ac_database_reindex
 *
 * It checks privileges to reindex tables within the database
 *
 * [Params]
 *  datOid : OID of the database to be commented on
 */
void
ac_database_reindex(Oid datOid)
{
	if (!pg_database_ownercheck(datOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_DATABASE,
					   get_database_name(datOid));
}

/*
 * ac_database_comment
 *
 * It checks privilges to comment on the database
 *
 * [Params]
 *  datOid : OID of the database to be commented
 */
void
ac_database_comment(Oid datOid)
{
	if (!pg_database_ownercheck(datOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_DATABASE,
					   get_database_name(datOid));
}
