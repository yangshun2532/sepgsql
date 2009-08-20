/*
 * src/backend/security/common/ac_operator.c
 *   common access control abstration corresponding to types
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_cast.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_type.h"
#include "miscadmin.h"
#include "security/common.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"

static char *
get_operator_name(Oid operOid)
{
	Form_pg_operator	operForm;
	HeapTuple	operTup;
	char	   *operName;

	operTup = SearchSysCache(OPEROID,
							 ObjectIdGetDatum(operOid),
							 0, 0, 0);
	if (!HeapTupleIsValid(operTup))
		elog(ERROR, "cache lookup failed for operator %u", operOid);

	operForm = (Form_pg_operator) GETSTRUCT(operTup);
	operName = pstrdup(NameStr(operForm->oprname));

	ReleaseSysCache(operTup);

	return operName;
}

static Oid
get_operator_namespace(Oid operOid)
{
	Form_pg_operator	operForm;
	HeapTuple	operTup;
	Oid			operNsp;

	operTup = SearchSysCache(OPEROID,
							 ObjectIdGetDatum(operOid),
							 0, 0, 0);
	if (!HeapTupleIsValid(operTup))
		elog(ERROR, "cache lookup failed for operator %u", operOid);

	operForm = (Form_pg_operator) GETSTRUCT(operTup);
	operNsp = operForm->oprnamespace;

	ReleaseSysCache(operTup);

	return operNsp;
}

/*
 * ac_operator_create
 *
 * It checks privilege to create a new operator
 *
 * [Params]
 * oprName : Name of the new operator
 * nspOid  : OID of the namespace to be used for the operator
 * commutatorOp : OID of the commutator operator, if exist 
 * negatorOp    : OID of the nagator operator, if exist
 * codeFn  : OID of the function to implement the operator, if exist
 * restFn  : OID of the restriction estimator function, if exist
 * joinFn  : OID of the join estimator function, if exist
 */
void
ac_operator_create(const char *oprName, Oid nspOid,
				   Oid commutatorOp, Oid negatorOp,
				   Oid codeFn, Oid restFn, Oid joinFn)
{
	AclResult	aclresult;

	aclresult = pg_namespace_aclcheck(nspOid, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE, get_namespace_name(nspOid));

	if (OidIsValid(commutatorOp))
	{
		if (!pg_oper_ownercheck(commutatorOp, GetUserId()))
			aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPER,
						   get_operator_name(commutatorOp));
	}

	if (OidIsValid(negatorOp))
	{
		if (!pg_oper_ownercheck(negatorOp, GetUserId()))
			aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPER,
						   get_operator_name(negatorOp));
	}

	if (OidIsValid(codeFn))
	{
		/*
		 * We require EXECUTE rights for the function.	This isn't strictly
		 * necessary, since EXECUTE will be checked at any attempted use of the
		 * operator, but it seems like a good idea anyway.
		 */
		aclresult = pg_proc_aclcheck(codeFn, GetUserId(), ACL_EXECUTE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_PROC, get_func_name(codeFn));
	}

	if (OidIsValid(restFn))
	{
		/* Require EXECUTE rights for the estimator */
		aclresult = pg_proc_aclcheck(restFn, GetUserId(), ACL_EXECUTE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_PROC, get_func_name(restFn));
	}

	if (OidIsValid(joinFn))
	{
		/* Require EXECUTE rights for the estimator */
		aclresult = pg_proc_aclcheck(joinFn, GetUserId(), ACL_EXECUTE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_PROC, get_func_name(joinFn));
	}
}

/*
 * ac_operator_replace
 *
 * It checks privilege to replace definition of a certain operator
 *
 * [Params]
 * oprName : Name of the new operator
 * nspOid  : OID of the namespace to be used for the operator
 * commutatorOp : OID of the commutator operator, if exist 
 * negatorOp    : OID of the nagator operator, if exist
 * codeFn  : OID of the function to implement the operator, if exist
 * restFn  : OID of the restriction estimator function, if exist
 * joinFn  : OID of the join estimator function, if exist
 */
void
ac_operator_replace(Oid operOid, Oid nspOid,
					Oid commutatorOp, Oid negatorOp,
					Oid codeFn, Oid restFn, Oid joinFn)
{
	char   *operName = get_operator_name(operOid);

	ac_operator_create(operName, nspOid,
					   commutatorOp, negatorOp,
					   codeFn, restFn, joinFn);

	if (!pg_oper_ownercheck(operOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPER, operName);

	pfree(operName);
}

/*
 * ac_operator_alter
 *
 * It checks privilege to alter a certain operator.
 *
 * [Params]
 * operOid  : OID of the operator to be altered
 * newOwner : OID of the new operator owner, if exist
 */
void
ac_operator_alter(Oid operOid, Oid newOwner)
{
	AclResult	aclresult;

	/* Must be owner of the operator */
	if (!pg_oper_ownercheck(operOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPER,
					   get_operator_name(operOid));

	if (OidIsValid(newOwner))
	{
		Oid		operNsp = get_operator_namespace(operOid);

		if (!superuser())
		{
			/* Must be able to become new owner */
			check_is_member_of_role(GetUserId(), newOwner);

			/* New owner must have CREATE privilege on the namespace */
			aclresult = pg_namespace_aclcheck(operNsp, newOwner, ACL_CREATE);
			if (aclresult != ACLCHECK_OK)
				aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
							   get_namespace_name(operNsp));
		}
	}
}

/*
 * ac_operator_drop
 *
 * It checks privilege to drop a certain operator
 *
 * [Params]
 * operOid : OID of the operator to be dropped
 * cascade : True, if cascaded deletion
 */
void
ac_operator_drop(Oid operOid, bool cascade)
{
	Oid			operNsp = get_operator_namespace(operOid);

	/* Must be owner of the operator or its namespace */
	if (!cascade &&
		!pg_oper_ownercheck(operOid, GetUserId()) &&
		!pg_namespace_ownercheck(operNsp, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPER,
					   get_operator_name(operOid));
}

/*
 * ac_operator_comment
 *
 * It checks privilege to comment on 
 *
 * [Params]
 * operOid: OID of the operator to be commented on
 */
void
ac_operator_comment(Oid operOid)
{
	if (!pg_oper_ownercheck(operOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPER,
					   get_operator_name(operOid));
}
