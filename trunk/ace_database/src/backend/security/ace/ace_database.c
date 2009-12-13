/*
 * ace_database.c
 *
 * security hooks related to database object class.
 *
 * Portions Copyright (c) 1996-2010, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_authid.h"
#include "catalog/pg_database.h"
#include "commands/dbcommands.h"
#include "commands/tablespace.h"
#include "miscadmin.h"
#include "security/ace.h"
#include "utils/syscache.h"

/* Check if current user has createdb privileges */
static bool
have_createdb_privilege(void)
{
	bool        result = false;
	HeapTuple   utup;

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
 * ace_database_create
 *
 * It enables security providers to apply permission checks to create
 * a new database.
 *
 * datName : Name of the new database
 * srcDatOid : OID of the source database
 * srcIsTemplate : True, if the source database is marked as template
 * datOwner : OID of the new database owner
 * datTblspc : OID of the default tablespace of the new database,
 *             if explicitly given. Otherwise, InvalidOid.
 */
void
ace_database_create(const char *datName, Oid srcDatOid, bool srcIsTemplate,
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
	if (!srcIsTemplate)
	{
		if (!pg_database_ownercheck(srcDatOid, GetUserId()))
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("permission denied to copy database \"%s\"",
							get_database_name(srcDatOid))));
	}

	/*
	 * Check permissions to use a certain tablespace as the default
	 * tablespace in the new database
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
 * ace_database_alter
 *
 * It enables security provides to check permission to alter properties
 * of a certain database.
 *
 * datOid : OID of the database to be altered.
 * newName : New name of the database, if given. Or, NULL.
 * newTblspc : OID of the new defatult tablespace, if given. Or, InvalidOid.
 * newOwner : OID of the new database owner, if given. Or, InvalidOid.
 */
void
ace_database_alter(Oid datOid, const char *newName,
				   Oid newTblspc, Oid newOwner)
{
	AclResult	aclresult;

	/* Must be owner for all the ALTER DATABASE options */
	if (!pg_database_ownercheck(datOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_DATABASE,
					   get_database_name(datOid));

	/* ALTER DATABASE ... RENAME TO */
	if (newName)
	{
		/* Must have createdb right for renaming */
		if (!have_createdb_privilege())
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("permission denied to rename database")));
	}

	/* ALTER DATABASE ... SET TABLESPACE */
	if (OidIsValid(newTblspc))
	{
		/* Must have ACL_CREATE for the new default tablespace */
		aclresult = pg_tablespace_aclcheck(newTblspc, GetUserId(),
										   ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_TABLESPACE,
						   get_tablespace_name(newTblspc));
	}

	/* ALTER DATABASE ... OWNER TO */
	if (OidIsValid(newOwner))
	{
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
	}
}

/*
 * ace_database_drop
 *
 * It enables security providers to check permission to drop a certain
 * database.
 *
 * datOid : OID of the database to be dropped
 * cascade : True, if cascaded deletion. Currently, it should never happen.
 */
void
ace_database_drop(Oid datOid, bool cascade)
{
	if (!cascade &&
		!pg_database_ownercheck(datOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_DATABASE,
					   get_database_name(datOid));
}

/*
 * ace_database_grant
 *
 * It enables security provides to check permission to grant/revoke
 * privileges in the default PG model.
 *
 * datOid : OID of the database to be granted/revoked
 * grantor : OID of the grantor role
 * goptions : Available AclMask available to grant others
 */
void
ace_database_grant(Oid datOid, Oid grantor, AclMode goptions)
{
	/*
	 * If we found no grant options, consider whether to issue a hard
	 * error. Per spec, having any privilege at all on the object will
	 * get you by here.
	 */
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
 * ace_database_comment
 *
 * It enables security provides to check permission to comment on
 * the given database.
 *
 * datOid : OID of the database to be commented
 */
void
ace_database_comment(Oid datOid)
{
	if (!pg_database_ownercheck(datOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_DATABASE,
					   get_database_name(datOid));
}

/*
 * ace_database_connect
 *
 * It enables security providers to check permission to connect to
 * the given database on CheckMyDatabase()
 *
 * datOid : OID of the database to be connected
 */
void
ace_database_connect(Oid datOid)
{
	if (pg_database_aclcheck(datOid, GetUserId(),
							 ACL_CONNECT) != ACLCHECK_OK)
		ereport(FATAL,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied for database \"%s\"",
						get_database_name(datOid)),
				 errdetail("User does not have CONNECT privilege.")));
}

/*
 * ace_database_reindex
 *
 * It enables security providers to check permissions to reindex
 * all the tables withing the database
 *
 * datOid : OID of the database to be reindexed
 */
void
ace_database_reindex(Oid datOid)
{
	/* Must have ownership of the database */
	if (!pg_database_ownercheck(datOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_DATABASE,
					   get_database_name(datOid));
}

/*
 * ace_database_calculate_size
 *
 * It enables security providers to check permission to calculate
 * a certain database size.
 *
 * datOid : OID of the database to be referenced
 */
void
ace_database_calculate_size(Oid datOid)
{
	AclResult	aclresult;

	/* User must have connect privilege for target database */
	aclresult = pg_database_aclcheck(datOid, GetUserId(), ACL_CONNECT);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_DATABASE,
					   get_database_name(datOid));
}
