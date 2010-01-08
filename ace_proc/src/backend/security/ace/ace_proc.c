/*
 * ace_proc.c
 *
 * security hooks related to (aggregate) procedure object class
 *
 * Portions Copyright (c) 1996-2010, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_aggregate.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_language.h"
#include "miscadmin.h"
#include "security/ace.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"

/*
 * check_proc_create
 *
 * It checks privileges to create a new regular procedure using CREATE
 * FUNCTION statement.
 * If violated, it shall raise an error.
 *
 * proName : Name of the new function
 * replaced : OID of the function to be replaced, if exist.
 *            Elsewhere, InvalidOid shall be given.
 * nspOid : OID of the namespace for the new function
 * langOid : OID of the procedural language for the new function
 */
void
check_proc_create(const char *proName, Oid replaced, Oid nspOid, Oid langOid)
{
	Form_pg_language	languageStruct;
	HeapTuple			langTup;
	AclResult			aclresult;

	/* Check we have creation rights in target namespace */
	aclresult = pg_namespace_aclcheck(nspOid, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
					   get_namespace_name(nspOid));

	/* Look up the language and validate permissions */
	langTup = SearchSysCache(LANGOID,
							 ObjectIdGetDatum(langOid),
							 0, 0, 0);
	if (!HeapTupleIsValid(langTup))
		elog(ERROR, "cache lookup failed for language %u", langOid);

	languageStruct = (Form_pg_language) GETSTRUCT(langTup);
	if (languageStruct->lanpltrusted)
	{
		/* if trusted language, need USAGE privilege */
		aclresult = pg_language_aclcheck(langOid, GetUserId(), ACL_USAGE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_LANGUAGE,
						   NameStr(languageStruct->lanname));
	}
	else
	{
		/* if untrusted language, must be superuser */
		if (!superuser())
			aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_LANGUAGE,
						   NameStr(languageStruct->lanname));
	}

	ReleaseSysCache(langTup);

	/*
	 * If user want to replace a certain procedure, he must have
	 * ownership of the procedure to be replaced.
	 */
	if (OidIsValid(replaced))
	{
		if (!pg_proc_ownercheck(replaced, GetUserId()))
			aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC, proName);
	}
}

/*
 * check_proc_alter
 *
 * It checks privileges to alter properties of a certain procedure
 * except for its name, ownership and schema.
 * If violated, it shall raise an error.
 *
 * proOid : OID of the procedure to be altered
 */
void
check_proc_alter(Oid proOid)
{
	/* must be owner */
	if (!pg_proc_ownercheck(proOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
					   get_func_name(proOid));
}

/*
 * check_proc_alter_rename
 *
 * It checks privileges to rename a certain procedure.
 * If violated, it shall raise an error.
 *
 * proOid : OID of the procedure to be renamed
 * newName : New name of the procedure
 */
void
check_proc_alter_rename(Oid proOid, const char *newName)
{
	Oid			namespaceOid;
	AclResult	aclresult;

	/* must be owner */
	if (!pg_proc_ownercheck(proOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
					   get_func_name(proOid));

	/* must have CREATE privilege on namespace */
	namespaceOid = get_func_namespace(proOid);
	aclresult = pg_namespace_aclcheck(namespaceOid, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
					   get_namespace_name(namespaceOid));
}

/*
 * check_proc_alter_schema
 *
 * It checks privileges to move a certain procedure into the new schema.
 * If violated, it shall raise an error.
 *
 * proOid : OID of the procedure to be moved
 * newNsp : OID of the new namespace which shall own the procedure
 */
void
check_proc_alter_schema(Oid proOid, Oid newNsp)
{
	AclResult	aclresult;

	/* must be owner */
	if (!pg_proc_ownercheck(proOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
					   get_func_name(proOid));

	/* must have CREATE privilege on the new namespace */
	aclresult = pg_namespace_aclcheck(newNsp, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
					   get_namespace_name(newNsp));
}

/*
 * check_proc_alter_owner
 *
 * It checks privileges to change ownership of a certain procedure.
 * If violated, it shall raise an error.
 *
 * proOid : OID of the procedure to be moved
 * newOwner : OID of the new owner of the procedure
 */
void
check_proc_alter_owner(Oid proOid, Oid newOwner)
{
	Oid			namespaceOid;
	AclResult	aclresult;

	/* Superusers can always do it */
	if (!superuser())
	{
		/* Otherwise, must be owner of the existing object */
		if (!pg_proc_ownercheck(proOid, GetUserId()))
			aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
						   get_func_name(proOid));

		/* Must be able to become new owner */
		check_is_member_of_role(GetUserId(), newOwner);

		/* New owner must have CREATE privilege on namespace */
		namespaceOid = get_func_namespace(proOid);
		aclresult = pg_namespace_aclcheck(namespaceOid, newOwner,
										  ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(namespaceOid));
	}
}

/*
 * check_proc_drop
 *
 * It checks privileges to drop a certain procedure
 * If violated, it shall raise an error.
 *
 * proOid : OID of the procedure to be dropped
 * cascade : True, if it was called due to the cascaded deletion
 */
void
check_proc_drop(Oid proOid, bool cascade)
{
	Oid		namespaceOid = get_func_namespace(proOid);

	/*
	 * Must be owner of the procedure to be dropped or its namespace.
	 */
	if (!cascade &&
		!pg_proc_ownercheck(proOid, GetUserId()) &&
		!pg_namespace_ownercheck(namespaceOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
					   get_func_name(proOid));
}

/*
 * check_proc_grant
 *
 * It checks privileges to grant/revoke the default PG permissions
 * on a certain relation.
 * The caller (aclchk.c) handles the default PG privileges well,
 * so rest of enhanced security providers can apply its checks here.
 * If violated, it shall raise an error.
 *
 * proOid : OID of the procedure to be granted/revoked
 */
void
check_proc_grant(Oid proOid)
{
	/* right now, no enhanced security providers */
}

/*
 * check_proc_comment
 *
 * It checks privileges to comment on a procedure
 * If violated, it shall raise an error.
 *
 * proOid : OID of the procedure to be commented on
 */
void
check_proc_comment(Oid proOid)
{
	/* Must be owner */
	if (!pg_proc_ownercheck(proOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
					   get_func_name(proOid));
}

/*
 * check_proc_execute
 *
 * It checks privileges to execute a certain procedure
 * If violated, it shall raise an error.
 *
 * proOid : OID of the procedure to be executed
 */
void
check_proc_execute(Oid proOid)
{
	AclResult	aclresult;

	aclresult = pg_proc_aclcheck(proOid, GetUserId(), ACL_EXECUTE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_PROC, get_func_name(proOid));
}

/*
 * check_proc_canbe_inlined
 *
 * It gives the caller a hint whether the given SQL function can be inlined
 * for query optimization purpose, or not, due to the security reason.
 * If not optimizable, it returns false.
 *
 * proTup : HeapTuple of the procedure to be inlined
 */
bool
check_proc_canbe_inlined(HeapTuple proTup)
{
	Form_pg_proc	proForm = (Form_pg_proc) GETSTRUCT(proTup);
	Oid		proOid = HeapTupleGetOid(proTup);

	/*
	 * If the procedure is declared as a security-definer function
	 * or user does not have EXECUTE privilege on the procedire,
	 * we cannot inline the function call due to the security reason.
	 */
	if (proForm->prosecdef ||
		pg_proc_aclcheck(proOid, GetUserId(), ACL_EXECUTE) != ACLCHECK_OK)
		return false;

	return true;
}

/*
 * check_proc_canbe_setcred
 *
 * It gives the caller a hint whether the given SQL function need to be
 * invoked via fmgr_security_definer(), or not. If we need to change the
 * credential (such as user identifier) during execution of the function
 * call, this hook returns true. Elsewhere, it returns false.
 *
 * proTup : HeapTuple of the procedure to be invoked
 */
bool
check_proc_canbe_setcred(HeapTuple proTup)
{
	Form_pg_proc	proForm = (Form_pg_proc) GETSTRUCT(proTup);

	/*
	 * If the procedure is declared as security definer function,
	 * it needs to be called via fmgr_security_definer().
	 */
	if (proForm->prosecdef)
		return true;

	return false;
}

/*
 * check_aggregate_create
 *
 * It checks privileges to create a new aggregate function.
 * If violated, it shall raise an error.
 *
 * aggName : Name of the new aggregate function
 * nspOid : OID of the namespace for the new aggregate function
 * transfn : OID of the trans function for the aggregate
 * finalfn : OID of the final function for the aggregate, if exist
 */
void
check_aggregate_create(const char *aggName, Oid nspOid,
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
 * check_aggregate_execute
 *
 * It checks privileges to execute a certain function
 * If violated, it shall raise an error.
 *
 * aggOid : OID of the aggregate function to be executed
 */
void
check_aggregate_execute(Oid aggOid)
{
	Form_pg_aggregate	aggForm;
	HeapTuple	aggTup;
	HeapTuple	proTup;
	Oid			aggOwner;
	AclResult	aclresult;

	aggTup = SearchSysCache(AGGFNOID,
							ObjectIdGetDatum(aggOid),
							0, 0, 0);
	if (!HeapTupleIsValid(aggTup))
		elog(ERROR, "cache lookup failed for aggregate %u", aggOid);
	aggForm = (Form_pg_aggregate) GETSTRUCT(aggTup);

	/* Check permission to call aggregate function */
	aclresult = pg_proc_aclcheck(aggForm->aggfnoid,
								 GetUserId(), ACL_EXECUTE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_PROC,
					   get_func_name(aggForm->aggfnoid));

	/* Check permission aggregate owner to call component function */
	proTup = SearchSysCache(PROCOID,
							ObjectIdGetDatum(aggForm->aggfnoid),
							0, 0, 0);
	aggOwner = ((Form_pg_proc) GETSTRUCT(proTup))->proowner;
	ReleaseSysCache(proTup);

	aclresult = pg_proc_aclcheck(aggForm->aggtransfn,
								 aggOwner, ACL_EXECUTE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_PROC,
					   get_func_name(aggForm->aggtransfn));

	if (OidIsValid(aggForm->aggfinalfn))
	{
		aclresult = pg_proc_aclcheck(aggForm->aggfinalfn,
									 aggOwner, ACL_EXECUTE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_PROC,
						   get_func_name(aggForm->aggfinalfn));
	}

	ReleaseSysCache(aggTup);
}
