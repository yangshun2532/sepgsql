/*
 * src/backend/security/common/ac_proc.c
 *   common access control abstration corresponding to procedures
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_language.h"
#include "catalog/pg_proc.h"
#include "miscadmin.h"
#include "security/common.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"

/*
 * Helper functions
 */
static bool
check_language_usage(Oid langOid)
{
	Form_pg_language	langForm;
	HeapTuple		langTup;
	bool			langTrusted;

	/* Check permissions to use language */
	langTup = SearchSysCache(LANGOID,
							 ObjectIdGetDatum(langOid),
							 0, 0, 0);
	if (!HeapTupleIsValid(langTup))
		elog(ERROR, "cache lookup failed for language %u", langOid);

	langForm = (Form_pg_language) GETSTRUCT(langTup);
	langTrusted = langForm->lanpltrusted;

	if (langTrusted)
	{
		/* if trusted language, need USAGE privilege */
		AclResult	aclresult;

		aclresult = pg_language_aclcheck(langOid, GetUserId(), ACL_USAGE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_LANGUAGE,
						   NameStr(langForm->lanname));
	}
	else
	{
		/* if untrusted language, must be superuser */
		if (!superuser())
			aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_LANGUAGE,
						   NameStr(langForm->lanname));
	}
	ReleaseSysCache(langTup);

	return langTrusted;
}

/*
 * ac_proc_create
 *
 * It checks privilege to create a new function
 *
 * [Params]
 *   proName : Name of the new function
 *   nspOid  : OID of the namespace for the new function
 *   langOid : OID of the procedural language for the new function
 */
void
ac_proc_create(const char *proName, Oid nspOid, Oid langOid)
{
	AclResult		aclresult;
	bool			langTrusted;

	/* Check we have creation rights in target namespace */
	aclresult = pg_namespace_aclcheck(nspOid, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
					   get_namespace_name(nspOid));

	/* Check permission to use language */
	langTrusted = check_language_usage(langOid);
}

/*
 * ac_proc_replace
 *
 * It checks privilege to replace an existing function, instead of
 * the ac_proc_create()
 *
 * [Params]
 *   proOid  : OID of the function to be replaced 
 *   nspOid  : OID of the namespace for the function
 *   langOid : OID of the language for the function
 */
void
ac_proc_replace(Oid proOid, Oid nspOid, Oid langOid)
{
	AclResult		aclresult;
	bool			langTrusted;

	/* Check we have creation rights in target namespace */
	aclresult = pg_namespace_aclcheck(nspOid, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
					   get_namespace_name(nspOid));

	/* Need ownership to replace an existing function */
	if (!pg_proc_ownercheck(proOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
					   get_func_name(proOid));

	/* Check permissions to use language */
	langTrusted = check_language_usage(langOid);
}

/*
 * ac_aggregate_create
 *
 * It checks privilege to create a new aggregate function
 *
 * [Params]
 *   aggName : Name of the new aggregate function
 *   nspOid  : OID of the namespace for the new aggregate function
 *   transfn : OID of the trans function for the aggregate
 *   finalfn : OID of the final function for the aggregate, if exist
 */
void
ac_aggregate_create(const char *aggName, Oid nspOid,
					Oid transfn, Oid finalfn)
{
	AclResult	aclresult;

	/* Check we have creation rights in target namespace */
	aclresult = pg_namespace_aclcheck(nspOid, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
					   get_namespace_name(nspOid));

	/* Check aggregate creator has permission to call the trans function */
	Assert(OidIsValid(transfn));
	aclresult = pg_proc_aclcheck(transfn, GetUserId(), ACL_EXECUTE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_PROC, get_func_name(transfn));

	/* Check aggregate creator has permission to call the final function */
	if (OidIsValid(finalfn))
	{
		aclresult = pg_proc_aclcheck(finalfn, GetUserId(), ACL_EXECUTE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_PROC, get_func_name(finalfn));
	}
}

/*
 * ac_proc_alter
 *
 * It checks privilege to alter a certain function
 *
 * [Params]
 *   proOid    : OID of the function to be altered
 *   newName   : New name of the function, if given
 *   newNspOid : OID of the new namespace, if given
 *   newOwner  : OID of the new function owner, if given
 */
void
ac_proc_alter(Oid proOid, const char *newName, Oid newNspOid, Oid newOwner)
{
	AclResult	aclresult;
	Oid			curNspOid;

	/* Must be owner for all the ALTER FUNCTION options */
	if (!pg_proc_ownercheck(proOid, GetUserId()))
        aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
					   get_func_name(proOid));

	/* must have CREATE privilege on namespace, to rename it */
	if (newName)
	{
		curNspOid = get_func_namespace(proOid);

		aclresult = pg_namespace_aclcheck(curNspOid, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(curNspOid));
	}

	/* must have CREATE privilege on the new namespace, to change it */
	if (OidIsValid(newNspOid))
	{
		aclresult = pg_namespace_aclcheck(newNspOid, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(newNspOid));
	}

	/*
	 * Must be able to become new owner, and he must have CREATE privilege
	 * on the namespace
	 */
	if (OidIsValid(newOwner))
	{
		/* Must be owner of the existing object */
		check_is_member_of_role(GetUserId(), newOwner);

		/* New owner must have CREATE privilege on namespace */
		curNspOid = get_func_namespace(proOid);

		aclresult = pg_namespace_aclcheck(curNspOid, newOwner, ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(curNspOid));
	}
}

/*
 * ac_proc_drop
 *
 * It checks privilege to drop a certain function.
 *
 * [Params]
 *   proOID  : OID of the function to be dropped
 *   cascade : True, if cascaded deletion
 */
void
ac_proc_drop(Oid proOid, bool cascade)
{
	HeapTuple		proTup;
	Form_pg_proc	proForm;

	/* Must be owner of function or its namespace */
	proTup =  SearchSysCache(PROCOID,
							 ObjectIdGetDatum(proOid),
							 0, 0, 0);
	if (!HeapTupleIsValid(proTup))
		elog(ERROR, "cache lookup failed for function %u", proOid);
	proForm = (Form_pg_proc) GETSTRUCT(proTup);

	if (!cascade &&
		!pg_proc_ownercheck(proOid, GetUserId()) &&
		!pg_namespace_ownercheck(proForm->pronamespace, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
					   get_func_name(proOid));

	ReleaseSysCache(proTup);
}

/*
 * ac_proc_grant
 *
 * It checks privileges to grant/revoke permissions on a certain function
 *
 * [Params]
 *   proOid   : OID of the target function for GRANT/REVOKE
 *   grantor  : OID of the gractor role
 *   goptions : Available AclMask available to grant others
 */
void
ac_proc_grant(Oid proOid, Oid grantor, AclMode goptions)
{
	if (goptions == ACL_NO_RIGHTS)
	{
		AclMode		whole_mask = ACL_ALL_RIGHTS_FUNCTION;

		if (pg_proc_aclmask(proOid, grantor,
							whole_mask | ACL_GRANT_OPTION_FOR(whole_mask),
							ACLMASK_ANY) == ACL_NO_RIGHTS)
			aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_DATABASE,
						   get_func_name(proOid));
	}
}

/*
 * ac_proc_comment
 *
 * It checks privilege to comment on the function
 *
 * [Params]
 *   proOid : OID of the function to be commented
 */
void
ac_proc_comment(Oid proOid)
{
	if (!pg_proc_ownercheck(proOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
					   get_func_name(proOid));
}

/*
 * ac_proc_execute
 *
 * It checks privilege to execute a certain function.
 *
 * Note that it should be checked on the function runtime.
 * Some of DDL statements requires ACL_EXECUTE on creation time, such as
 * CreateConversionCommand(), however, these are individually checked on
 * the ac_xxx_create() hook.
 *
 * [Params]
 *   proOID  : OID of the function to be executed
 *   roleOid : OID of the database role to be evaluated
 */
void
ac_proc_execute(Oid proOid, Oid roleOid)
{
	AclResult	aclresult;

	aclresult = pg_proc_aclcheck(proOid, roleOid, ACL_EXECUTE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_PROC, get_func_name(proOid));
}

/*
 * ac_proc_hint_inlined
 *
 * It provides a hint for the optimizer whether the given SQL function
 * can be inlined from the viewpoint of access controls.
 * Because we have no chance to apply execution permission checks on
 * the inlined functions, the function must be executable.
 *
 * [Params]
 *   proOid : OID of the function tried to be inlined
 */
bool
ac_proc_hint_inline(Oid proOid)
{
	if (pg_proc_aclcheck(proOid, GetUserId(), ACL_EXECUTE) != ACLCHECK_OK)
		return false;

	return true;
}
