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
#include "catalog/pg_opclass.h"
#include "catalog/pg_opfamily.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_type.h"
#include "miscadmin.h"
#include "security/common.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"

/* ************************************************************
 *
 * Pg_opepator system catalog related access control stuffs
 *
 * ************************************************************/
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
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
					   get_namespace_name(nspOid));

	if (OidIsValid(commutatorOp))
	{
		if (!pg_oper_ownercheck(commutatorOp, GetUserId()))
			aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPER,
						   get_opname(commutatorOp));
	}

	if (OidIsValid(negatorOp))
	{
		if (!pg_oper_ownercheck(negatorOp, GetUserId()))
			aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPER,
						   get_opname(negatorOp));
	}

	if (OidIsValid(codeFn))
	{
		/*
		 * We require EXECUTE rights for the function.	This isn't strictly
		 * necessary, since EXECUTE will be checked at any attempted use of
		 * the operator, but it seems like a good idea anyway.
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
	char   *operName = get_opname(operOid);

	ac_operator_create(operName, nspOid,
					   commutatorOp, negatorOp,
					   codeFn, restFn, joinFn);

	if (!pg_oper_ownercheck(operOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPER,
					   operName);

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
					   get_opname(operOid));

	if (OidIsValid(newOwner) && !superuser())
	{
		Oid		operNsp = get_operator_namespace(operOid);

		/* Must be able to become new owner */
		check_is_member_of_role(GetUserId(), newOwner);

		/* New owner must have CREATE privilege on the namespace */
		aclresult = pg_namespace_aclcheck(operNsp, newOwner, ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(operNsp));
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
					   get_opname(operOid));
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
					   get_opname(operOid));
}

/* ************************************************************
 *
 * Pg_opclass system catalog related access control stuffs
 *
 * ************************************************************/
static char *
get_opclass_name(Oid opcOid)
{
	Form_pg_opclass		opcForm;
	HeapTuple	opcTup;
	char	   *opcName;

	opcTup = SearchSysCache(CLAOID,
							ObjectIdGetDatum(opcOid),
							0, 0, 0);
	if (!HeapTupleIsValid(opcTup))
		elog(ERROR, "cache lookup failed for opclass %u", opcOid);

	opcForm = (Form_pg_opclass) GETSTRUCT(opcTup);
	opcName = pstrdup(NameStr(opcForm->opcname));

	ReleaseSysCache(opcTup);

	return opcName;
}

static Oid
get_opclass_namespace(Oid opcOid)
{
	HeapTuple	opcTup;
	Oid			opcNsp;

	opcTup = SearchSysCache(CLAOID,
							ObjectIdGetDatum(opcOid),
							0, 0, 0);
	if (!HeapTupleIsValid(opcTup))
		elog(ERROR, "cache lookup failed for opclass %u", opcOid);

	opcNsp = ((Form_pg_opclass) GETSTRUCT(opcTup))->opcnamespace;

	ReleaseSysCache(opcTup);

	return opcNsp;
}

/*
 * ac_opclass_create
 *
 * It checks privilege to create a new operator class
 *
 * [Params]
 * opcName  : Name of the new operator class
 * opcNsp   : OID of the namespace to be used
 * typOid   : OID of the type to be set up
 * opfOid   : OID of the corresponding operator family, 
 * operList : List of operator OID
 * procList : List of procedure OID
 * stgOid   : OID of the type stored used as a storage
 */
void
ac_opclass_create(const char *opcName, Oid opcNsp, Oid typOid, Oid opfOid,
				  List *operList, List *procList, Oid stgOid)
{
	AclResult	aclresult;
#ifdef NOT_USED
	ListCell   *l;
#endif

	/* Check we have creation rights in target namespace */
	aclresult = pg_namespace_aclcheck(opcNsp, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
					   get_namespace_name(opcNsp));

	/* XXX Should we make any privilege check against the AM? */

	/*
	 * The question of appropriate permissions for CREATE OPERATOR CLASS is
	 * interesting.  Creating an opclass is tantamount to granting public
	 * execute access on the functions involved, since the index machinery
	 * generally does not check access permission before using the functions.
	 * A minimum expectation therefore is that the caller have execute
	 * privilege with grant option.  Since we don't have a way to make the
	 * opclass go away if the grant option is revoked, we choose instead to
	 * require ownership of the functions.  It's also not entirely clear what
	 * permissions should be required on the datatype, but ownership seems
	 * like a safe choice.
	 *
	 * Currently, we require superuser privileges to create an opclass. This
	 * seems necessary because we have no way to validate that the offered set
	 * of operators and functions are consistent with the AM's expectations.
	 * It would be nice to provide such a check someday, if it can be done
	 * without solving the halting problem :-(
	 *
	 * XXX re-enable NOT_USED code sections below if you remove this test.
	 */
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to create an operator class")));

#ifdef NOT_USED
	/*
	 * XXX this is unnecessary given the superuser check above
	 * Check we have ownership of the datatype
	 */
	if (!pg_type_ownercheck(typOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_TYPE,
					   format_type_be(typeoid));

	/*
	 * XXX given the superuser check above, there's no need
	 * for an ownership check to operator family here
	 */
	if (!pg_opfamily_ownercheck(opfOid, GetUserId())
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPFAMILY,
					   get_opfamily_name(opfOid));
#endif

#ifdef NOT_USED
	/* XXX this is unnecessary given the superuser check above */
	foreach(l, operList)
	{
		Oid		operOid = lfirst_oid(l);
		Oid		funcOid

		/* Caller must own operator and its underlying function */
		if (!pg_oper_ownercheck(operOid, GetUserId()))
			aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPER,
						   get_opname(operOid));
		funcOid = get_opcode(operOid);
		if (!pg_proc_ownercheck(funcOid, GetUserId()))
			aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
						   get_func_name(funcOid));
	}
#endif

#ifdef NOT_USED
	/* XXX this is unnecessary given the superuser check above */
	foreach(l, procList)
	{
		Oid		funcOid = lfirst_oid(l);

		/* Caller must own function */
		if (!pg_proc_ownercheck(funcOid, GetUserId()))
			aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
						   get_func_name(funcOid));
	}
#endif

#ifdef NOT_USED
	/* XXX this is unnecessary given the superuser check above */
	if (OidIsValid(stgOid))
	{
		/* Check we have ownership of the datatype */
		if (!pg_type_ownercheck(stgOid, GetUserId()))
			aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_TYPE,
						   format_type_be(stgOid));
	}
#endif
}

/*
 * ac_opclass_alter
 *
 * It checks privilege to alter a certain operator class
 *
 * [Params]
 * opcOid   : OID of the operator class to be altered
 * newName  : New name of the operator class, if exist
 * newOwner : OID of new owner of the operator class, if exist
 */
void
ac_opclass_alter(Oid opcOid, const char *newName, Oid newOwner)
{
	Oid			opcNsp = get_opclass_namespace(opcOid);
	AclResult	aclresult;

	/* Must be owner for all the ALTER OPERATOR CLASS option */
	if (!pg_opclass_ownercheck(opcOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPCLASS,
					   get_opclass_name(opcOid));

	if (newName)
	{
		/* must have CREATE privilege on namespace */
		aclresult = pg_namespace_aclcheck(opcNsp, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(opcNsp));
	}

	if (OidIsValid(newOwner) && !superuser())
	{
		/* Must be able to become new owner */
		check_is_member_of_role(GetUserId(), newOwner);

		/* New owner must have CREATE privilege on namespace */
		aclresult = pg_namespace_aclcheck(opcNsp, newOwner, ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(opcNsp));
	}
}

/*
 * ac_opclass_drop
 *
 * It checks privilege to drop a certain operator class
 *
 * [Params]
 * opcOid  : OID of the operator class to be dropped
 * cascade : True, if cascaded deletion
 */
void
ac_opclass_drop(Oid opcOid, bool cascade)
{
	Oid		opcNsp = get_opclass_namespace(opcOid);

	if (!cascade &&
		!pg_opclass_ownercheck(opcOid, GetUserId()) &&
		!pg_namespace_ownercheck(opcNsp, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPCLASS,
					   get_opclass_name(opcOid));
}

/*
 * ac_opclass_comment
 *
 * It checks privilege to comment on a certain operator class
 *
 * [Params]
 * opcOid  : OID of the operator class to be commented on
 */
void
ac_opclass_comment(Oid opcOid)
{
	if (!pg_opclass_ownercheck(opcOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPCLASS,
					   get_opclass_name(opcOid));
}

/* ************************************************************
 *
 * Pg_opfamily system catalog related access control stuffs
 *
 * ************************************************************/
static char *
get_opfamily_name(Oid opfOid)
{
	Form_pg_opfamily	opfForm;
	HeapTuple	opfTup;
	char	   *opfName;

	opfTup = SearchSysCache(OPFAMILYOID,
							ObjectIdGetDatum(opfOid),
							0, 0, 0);
	if (!HeapTupleIsValid(opfTup))
		elog(ERROR, "cache lookup failed for opfamily %u", opfOid);

	opfForm = (Form_pg_opfamily) GETSTRUCT(opfTup);
	opfName = pstrdup(NameStr(opfForm->opfname));

	ReleaseSysCache(opfTup);

	return opfName;
}

static Oid
get_opfamily_namespace(Oid opfOid)
{
	HeapTuple	opfTup;
	Oid			opfNsp;

	opfTup = SearchSysCache(OPFAMILYOID,
							ObjectIdGetDatum(opfOid),
							0, 0, 0);
	if (!HeapTupleIsValid(opfTup))
		elog(ERROR, "cache lookup failed for opfamily %u", opfOid);

	opfNsp = ((Form_pg_opfamily) GETSTRUCT(opfTup))->opfnamespace;

	ReleaseSysCache(opfTup);

	return opfNsp;
}

/*
 * ac_opfamily_create
 *
 * It checks privilege to create a new operator family
 *
 * [Params]
 * opfName : New name of the operator family
 * opfNsp  : OID of the namespace to be used
 */
void
ac_opfamily_create(const char *opfName, Oid opfNsp, Oid amOid)
{
	AclResult	aclresult;

	/* Check we have creation rights in target namespace */
	aclresult = pg_namespace_aclcheck(opfNsp, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
					   get_namespace_name(opfNsp));

	/* XXX Should we make any privilege check against the AM? */

	/*
	 * Currently, we require superuser privileges to create an opfamily. See
	 * comments in DefineOpClass.
	 *
	 * XXX re-enable NOT_USED code sections below if you remove this test.
	 */
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to create an operator family")));
}

/*
 * ac_opfamily_alter
 *
 * It checks privilege to alter a certain operator family
 *
 * [Params]
 * opfOid   : OID of the operator family 
 * newName  : New name of the operator family, if exist
 * newOwner : New owner of the operator family, if exist
 */
void
ac_opfamily_alter(Oid opfOid, const char *newName, Oid newOwner)
{
	if (!newName && !OidIsValid(newOwner))
	{
		/*
		 * Currently, we require superuser privileges to alter an opfamily.
		 *
		 * XXX re-enable NOT_USED code sections below if you remove this test.
		 */
		if (!superuser())
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("must be superuser to alter an operator family")));
	}
	else
	{
		Oid			opfNsp = get_opfamily_namespace(opfOid);
		AclResult	aclresult;

		/* Must be owner for RENAME and OWNER TO */
		if (!pg_opfamily_ownercheck(opfOid, GetUserId()))
			aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPFAMILY,
						   get_opfamily_name(opfOid));

		if (newName)
		{
			/* must have CREATE privilege on namespace */
			aclresult = pg_namespace_aclcheck(opfNsp, GetUserId(), ACL_CREATE);
			if (aclresult != ACLCHECK_OK)
				aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
							   get_namespace_name(opfNsp));
		}

		if (OidIsValid(newOwner) && !superuser())
		{
			/* Must be able to become new owner */
			check_is_member_of_role(GetUserId(), newOwner);

			/* New owner must have CREATE privilege on namespace */
			aclresult = pg_namespace_aclcheck(opfNsp, newOwner, ACL_CREATE);
			if (aclresult != ACLCHECK_OK)
				aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
							   get_namespace_name(opfNsp));
		}
	}
}

/*
 * ac_opfamily_drop
 *
 * It checks privilege to drop a certain operator family
 *
 * [Params]
 * opfOid  : OID of the operator family to be dropped
 * cascade : True, if cascaded deletion
 */
void
ac_opfamily_drop(Oid opfOid, bool cascade)
{
	Oid		opfNsp = get_opfamily_namespace(opfOid);

	/* Must be owner of opfamily or its namespace */
	if (!pg_opfamily_ownercheck(opfOid, GetUserId()) &&
		!pg_namespace_ownercheck(opfNsp, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPFAMILY,
					   get_opfamily_name(opfOid));
}

/*
 * ac_opfamily_comment
 *
 * It checks privilege to comment on a certain operator family
 *
 * [Params]
 * opfOid : OID of the operator family to be commented
 */
void
ac_opfamily_comment(Oid opfOid)
{
	if (!pg_opfamily_ownercheck(opfOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPFAMILY,
					   get_opfamily_name(opfOid));
}

/*
 * ac_opfamily_add_oper
 *
 * It checks privilege to add a certain operator to the given
 * operator family.
 *
 * [Params]
 * opfOid  : OID of the target operator family
 * operOid : OID of the given operator
 */
void
ac_opfamily_add_oper(Oid opfOid, Oid operOid)
{
#ifdef NOT_USED
	Oid		funcOid;

	/* XXX this is unnecessary given the superuser check above */
	/* Caller must own operator and its underlying function */
	if (!pg_oper_ownercheck(itemOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_OPER,
					   get_opname(itemOid));

	funcOid = get_opcode(itemOid);
	if (!pg_proc_ownercheck(funcOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
					   get_func_name(funcOid));
#endif
}

/*
 * ac_opfamily_add_proc
 *
 * It checks privilege to add a certain procedure to the given
 * operator family.
 *
 * [Params]
 * opfOid  : OID of the target operator family
 * procOid : OID of the given procedure
 */
void
ac_opfamily_add_proc(Oid opfOid, Oid procOid)
{
#ifdef NOT_USED
	/* XXX this is unnecessary given the superuser check above */
	/* Caller must own function */
	if (!pg_proc_ownercheck(itemOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
					   get_func_name(itemOid));
#endif
}
