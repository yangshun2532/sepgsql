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

/*
 * Check pg_authid.rolcreatedb bit for the current database user
 */
static bool
role_has_createdb(void)
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
 * check_database_create
 *
 * It checks privileges to create a new database with the given parameters.
 * If violated, it shall raise an error.
 *
 * datName : Name of the new database
 * srcDatOid : OID of the source database (may be template database)
 * datOwner : OID of the new database owner
 * datTblspc : OID of the default tablespace, if explicitly given.
 *             Otherwise, InvalidOid
 */
void
check_database_create(const char *datName,
					  Oid srcDatOid, Oid datOwner, Oid datTblspc)
{
	AclResult	aclresult;
	HeapTuple	tuple;
	bool		datistemplate;

	/*
	 * To create a database, must have createdb privilege and must be able to
	 * become the target role (this does not imply that the target role itself
	 * must have createdb privilege).  The latter provision guards against
	 * "giveaway" attacks.	Note that a superuser will always have both of
	 * these privileges a fortiori.
	 */
	if (!role_has_createdb())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied to create database")));

	check_is_member_of_role(GetUserId(), datOwner);

	/*
	 * Permission check: to copy a DB that's not marked datistemplate, you
	 * must be superuser or the owner thereof.
	 */
	tuple = SearchSysCache(DATABASEOID,
						   ObjectIdGetDatum(srcDatOid),
						   0, 0, 0);
	if (!HeapTupleIsValid(tuple))
		elog(ERROR, "cache lookup failed for database %u", srcDatOid);

	datistemplate = ((Form_pg_database) GETSTRUCT(tuple))->datistemplate;

	ReleaseSysCache(tuple);

	if (!datistemplate)
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
 * check_database_alter
 *
 * It checks privileges to alter properties of a certain database, except
 * for its name, ownership and default tablespace.
 * If violated, it shall raise an error.
 *
 * datOid : OID of the database to be altered
 */
void
check_database_alter(Oid datOid)
{
	/* Must be owner for all the ALTER DATABASE options */
	if (!pg_database_ownercheck(datOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_DATABASE,
					   get_database_name(datOid));

}

/*
 * check_database_alter_rename
 *
 * It checks privileges to alter name of a certain database.
 * If violated, it shall raise an error.
 *
 * datOid : OID of the database to be altered
 * newName : The new database name 
 */
void
check_database_alter_rename(Oid datOid, const char *newName)
{
	/* Must be owner for all the ALTER DATABASE options */
	if (!pg_database_ownercheck(datOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_DATABASE,
					   get_database_name(datOid));

	/* Must have createdb right for renaming */
	if (!role_has_createdb())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied to rename database")));
}

/*
 * check_database_alter_owner
 *
 * It checks privileges to alter ownership of a certain database.
 * If violated, it shall raise an error.
 *
 * datOid : OID of the database to be altered
 * newOwner : OID of the new database owner
 */
void
check_database_alter_owner(Oid datOid, Oid newOwner)
{
	/* Must be owner for all the ALTER DATABASE options */
	if (!pg_database_ownercheck(datOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_DATABASE,
					   get_database_name(datOid));

	/* Must be able to become new owner */
	check_is_member_of_role(GetUserId(), newOwner);

	/*
	 * role must have createdb rights
	 *
	 * NOTE: This is different from other alter-owner checks in that the
	 * current user is checked for createdb privileges instead of the
	 * destination owner.  This is consistent with the CREATE case for
	 * databases.  Because superusers will always have this right, we need
	 * no special case for them.
	 */
	if (!role_has_createdb())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied to change owner of database")));
}

/*
 * check_database_alter_tablespace
 *
 * It checks privileges to alter tablespace of a certain database.
 * If violated, it shall raise an error.
 *
 * datOid : OID of the database to be altered
 * newTblspc : OID of the new default tablespace
 */
void
check_database_alter_tablespace(Oid datOid, Oid newTblspc)
{
	AclResult	aclresult;

	/* Must be owner for all the ALTER DATABASE options */
	if (!pg_database_ownercheck(datOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_DATABASE,
					   get_database_name(datOid));

	/* Must have ACL_CREATE for the new default tablespace */
	aclresult = pg_tablespace_aclcheck(newTblspc, GetUserId(),
									   ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_TABLESPACE,
					   get_tablespace_name(newTblspc));
}

/*
 * check_database_drop 
 *
 * It checks privileges to drop a certain database.
 * If violated, it shall raise an error.
 *
 * datOid : OID of the database to be dropped
 * cascade : True, if cascaded deletion. Currently, it should never happen.
 */
void
check_database_drop(Oid datOid, bool cascade)
{
	if (!cascade &&
		!pg_database_ownercheck(datOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_DATABASE,
					   get_database_name(datOid));
}

/*
 * check_database_getattr
 *
 * It checks privileges to get attribute of a certain database.
 * If violated, it shall raise an error.
 *
 * datOid : OID of the database to be referenced
 */
void
check_database_getattr(Oid datOid)
{
	AclResult	aclresult;

	/* Must have connect privilege for target database */
	aclresult = pg_database_aclcheck(datOid, GetUserId(), ACL_CONNECT);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_DATABASE,
					   get_database_name(datOid));
}

/*
 * check_database_grant
 *
 * It checks privileges to grant/revoke the default PG permissions
 * on a certain database.
 * The caller (aclchk.c) handles the default PG privileges well,
 * so rest of enhanced security providers can apply its checks here.
 * If violated, it shall raise an error.
 *
 * datOid : OID of the database to be granted/revoked
 */
void
check_database_grant(Oid datOid)
{
	/* right now, no enhanced security providers */
}

/*
 * check_database_comment
 *
 * It checks privileges to comment on a certain database.
 * If violated, it shall raise an error.
 *
 * datOid : OID of the database to be commented
 */
void
check_database_comment(Oid datOid)
{
	if (!pg_database_ownercheck(datOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_DATABASE,
					   get_database_name(datOid));
}

/*
 * check_database_connect
 *
 * It checks privileges to connect to a certain database under the
 * initialization of a server instance.
 * In this hook, security providers shall raise a FATAL error, not
 * an ERROR, if violated.
 *
 * datOid : OID of the database to be connected
 */
void
check_database_connect(Oid datOid)
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
 * check_database_reindex
 *
 * It checks privileges to reindex all the tables within a certain
 * database.
 * If violated, it shall raise an error.
 *
 * datOid : OID of the database to be reindexed
 */
void
check_database_reindex(Oid datOid)
{
	/* Must have ownership of the database */
	if (!pg_database_ownercheck(datOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_DATABASE,
					   get_database_name(datOid));
}
