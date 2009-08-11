/*
 * src/backend/security/common/ac_foreign.c
 *   common access control abstration corresponding to foreign data wrappers,
 *   foreign servers and user mapping.
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "security/common.h"

/*
 * Hepler functions
 */
static char *
get_fdw_name(Oid fdwOid)
{
	Form_pg_foreign_data_wrapper	fdwForm;
	HeapTuple	fdwTup;
	char	   *fdwName = NULL;

	fdwTup = SearchSysCache(FOREIGNDATAWRAPPEROID,
							ObjectIdGetDatum(fdwOid),
							0, 0, 0);
	if (HeapTupleIsValid(fdwTup))
	{
		fdwForm = (Form_pg_foreign_data_wrapper) GETSTRUCT(fdwTup);

		fdwName = pstrdup(NameStr(fdwForm->fdwname));

		ReleaseSysCache(fdwTup);
	}
	return fdwName;
}

static char *
get_fsrv_name(Oid fsrvOid)
{
	Form_pg_foreign_server	fsrvForm;
	HeapTuple	fsrvTup;
	char	   *fsrvName = NULL;

	fsrvTup = SearchSysCache(FOREIGNSERVEROID,
							 ObjectIdGetDatum(fsrvOid),
							 0, 0, 0);
	if (HeapTupleIsValid(fsrvTup))
	{
		fsrvForm = (Form_pg_foreign_server) GETSTRUCT(fsrvTup);

		fsrvName = pstrdup(NameStr(fsrvForm->srvname));

		ReleaseSysCache(fsrvTup);
	}
	return fsrvName;
}

/*
 * Common routine to check permission for user-mapping-related DDL
 * commands.  We allow server owners to operate on any mapping, and
 * users to operate on their own mapping.
 */
static void
user_mapping_ddl_aclcheck(Oid umuserid, Oid serverid)
{
	Oid         curuserid = GetUserId();

	if (!pg_foreign_server_ownercheck(serverid, curuserid))
	{
		if (umuserid == curuserid)
		{
			AclResult	aclresult;

			aclresult = pg_foreign_server_aclcheck(serverid, curuserid, ACL_USAGE);
			if (aclresult != ACLCHECK_OK)
				aclcheck_error(aclresult, ACL_KIND_FOREIGN_SERVER,
							   get_fsrv_name(serverid));
		}
		else
			aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_FOREIGN_SERVER,
						   get_fsrv_name(serverid));
    }
}

/*
 * ac_foreign_data_wrapper_create
 *
 * It checks privilege to create a new foreign data wrapper
 *
 * [Params]
 *   fdwName      : Name of the new foreign data wrapper
 *   fdwValidator : OID of the validator function, if exist
 */
void
ac_foreign_data_wrapper_create(const char *fdwName, Oid fdwValidator)
{
	/* Must be super user */
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied to create "
						"foreign-data wrapper \"%s\"", fdwName),
				 errhint("Must be superuser to create a foreign-data wrapper.")));
}

/*
 * ac_foreign_data_wrapper_alter
 *
 * It checks privilege to alter a certain foreign data wrapper
 *
 * [Params]
 *   fdwOid       : OID of the target foreign data wrapper
 *   newValidator : OID of the new validator function, if exist
 *   newOwner     : OID of the new owner, if exist
 */
void
ac_foreign_data_wrapper_alter(Oid fdwOid, Oid newValidator, Oid newOwner)
{
	/* Must be super user */
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied to alter foreign-data wrapper \"%s\"",
						get_fdw_name(fdwOid)),
				 errhint("Must be superuser to alter a foreign-data wrapper.")));

	/* New owner must also be a superuser */
	if (OidIsValid(newOwner) && !superuser_arg(newOwner))
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied to change owner of foreign-data wrapper \"%s\"",
						get_fdw_name(fdwOid)),
				 errhint("The owner of a foreign-data wrapper must be a superuser.")));
}

/*
 * ac_foreign_data_wrapper_drop
 *
 * It checks privilege to drop a certain foreign data wrapper
 *
 * [Params]
 *   fdwOid  : OID of the target foreign data wrapper
 *   cascade : True, if cascaded deletion
 */
void
ac_foreign_data_wrapper_drop(Oid fdwOid, bool cascade)
{
	if (!cascade &&
		!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied to drop foreign-data wrapper \"%s\"",
						get_fdw_name(fdwOid)),
				 errhint("Must be superuser to drop a foreign-data wrapper.")));
}

/*
 * ac_foreign_data_wrapper_grant
 *
 * It checks privilege to grant/revoke permissions on a certain foreign
 * data wrapper
 *
 * [Params]
 *   fdwOid   : OID of the target foreign data wrapper
 *   grantor  : OID of the gractor database role
 *   goptions : Available AclMask to grant others
 */
void
ac_foreign_data_wrapper_grant(Oid fdwOid, Oid grantor, AclMode goptions)
{
	if (goptions == ACL_NO_RIGHTS)
	{
		AclMode		whole_mask = ACL_ALL_RIGHTS_FDW;

		whole_mask |= ACL_GRANT_OPTION_FOR(whole_mask);
		if (pg_foreign_data_wrapper_aclmask(fdwOid, grantor, whole_mask,
											ACLMASK_ANY) == ACL_NO_RIGHTS)
			aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_FDW,
						   get_fdw_name(fdwOid));
	}
}

/*
 * ac_foreign_server_create
 *
 * It checks privilege to create a new foreign server
 *
 * [Params]
 *   fsrvName  : Name of the new foreign server
 *   fsrvOwner : OID of the foreign server owner
 *   fdwOid    : OID of the foreign data wrapper used in the server
 */
void
ac_foreign_server_create(const char *fsrvName, Oid fsrvOwner, Oid fdwOid)
{
	AclResult	aclresult;

	aclresult = pg_foreign_data_wrapper_aclcheck(fdwOid, fsrvOwner, ACL_USAGE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_FDW, get_fdw_name(fdwOid));
}

/*
 * ac_foreign_server_alter
 *
 * It checks privilege to alter a certain foreign server
 *
 * [Params]
 *   fsrvOid  : OID of the target foreign server
 *   newOwner : OID of the new foreign server owner, if exist
 */
void
ac_foreign_server_alter(Oid fsrvOid, Oid newOwner)
{
	if (!pg_foreign_server_ownercheck(fsrvOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_FOREIGN_SERVER,
					   get_fsrv_name(fsrvOid));

	/* Additional checks for change owner */
	if (OidIsValid(newOwner))
	{
		Form_pg_foreign_server	fsrvForm;
		HeapTuple		fsrvTup;
		AclResult		aclresult;

		/* Must be able to become new owner */
		check_is_member_of_role(GetUserId(), newOwnerId);

		/* New owner must have USAGE privilege on foreign-data wrapper */
		fsrvTup = SearchSysCacheCopy(FOREIGNSERVEROID,
									 ObjectIdGetDatum(fsrvOid),
									 0, 0, 0);
		if (!HeapTupleIsValid(fsrvTup))
			elog(ERROR, "cache lookup failed for foreign server: %u", fsrvOid);

		fsrvForm = (Form_pg_foreign_server) GETSTRUCT(fsrvTup);

		aclresult = pg_foreign_data_wrapper_aclcheck(fsrvForm->srvfdw,
													 newOwner, ACL_USAGE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_FDW,
						   get_fdw_name(fsrvForm->srvfdw));
	}
}

/*
 * ac_foreign_server_drop
 *
 * It checks privilege to drop a certain foreign server.
 *
 * [Params]
 *   fsrvOid : OID of the target foreign server
 *   cascade : True, if cascaded deletion
 */
void
ac_foreign_server_drop(Oid fsrvOid, bool cascade)
{
	/* Only allow DROP if the server is owned by the user. */
	if (!cascade &&
		!pg_foreign_server_ownercheck(fsrvOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_FOREIGN_SERVER,
					   get_fsrv_name(fsrvOid));
}

/*
 * ac_foreign_server_grant
 *
 * It checks privilege to grant/revoke permissions on a certain
 * foreign server
 *
 * [Params]
 *   fsrvOid  : OID of the target foreign server
 *   grantor  : OID of the gractor database role
 *   goptions : Available AclMask to grant others
 */
void
ac_foreign_server_grant(Oid fsrvOid, Oid grantor, AclMode goptions)
{
	if (goptions == ACL_NO_RIGHTS)
	{
		AclMode		whole_mask = ACL_KIND_FOREIGN_SERVER;

		whole_mask |= ACL_GRANT_OPTION_FOR(whole_mask);
		if (pg_foreign_server_aclmask(fdwOid, grantor, whole_mask,
									  ACLMASK_ANY) == ACL_NO_RIGHTS)
			aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_FOREIGN_SERVER,
						   get_fsrv_name(fsrvOid));
	}
}

/*
 * ac_user_mapping_create
 *
 * It checks permission to create a new user mapping
 *
 * [Params]
 *   umuserId : OID of the mapped user id
 *   fsrvOid  : OID of the foreign server
 */
void
ac_user_mapping_create(Oid umuserId, Oid fsrvOid)
{
	user_mapping_ddl_aclcheck(umuserId, fsrvOid);
}

/*
 * ac_user_mapping_alter
 *
 * It checks permission to alter a certain user mapping
 *
 * [Params]
 *   umuserId : OID of the mapped user id
 *   fsrvOid  : OID of the foreign server
 */
void
ac_user_mapping_alter(Oid umuserId, Oid fsrvOid)
{
	user_mapping_ddl_aclcheck(umuserId, fsrvOid);
}

/*
 * ac_user_mapping_drop
 *
 * It checks permission to drop a certain user mapping
 *
 * [Params]
 *   umuserId : OID of the mapped user id
 *   fsrvOid  : OID of the foreign server
 *   cascade : True, if cascaded deletion
 */
void
ac_user_mapping_drop(Oid umuserId, Oid fsrvOid, bool cascade)
{
	if (!cascade)
		user_mapping_ddl_aclcheck(umuserId, fsrvOid);
}
