/*
 * src/backend/security/common/ac_type.c
 *   common access control abstration corresponding to types
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_cast.h"
#include "catalog/pg_conversion.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_type.h"
#include "miscadmin.h"
#include "security/common.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"

/*
 * Helper functions
 */
static Oid
get_type_namespace(Oid typOid)
{
	HeapTuple	typTup;
	Oid			typNsp;

	typTup = SearchSysCache(TYPEOID,
							ObjectIdGetDatum(typOid),
							0, 0, 0);
	if (!HeapTupleIsValid(typTup))
		elog(ERROR, "cache lookup failed for type: %u", typOid);

	typNsp = ((Form_pg_type) GETSTRUCT(typTup))->typnamespace;

	ReleaseSysCache(typTup);

	return typNsp;
}

/*
 * ac_type_create
 *
 * It checks privilege to create a new regular type
 *
 * [Params]
 *   typName      : Name of the new regular type
 *   nspOid       : OID of the namespace to be used for the type
 *   inputOid     : OID of the input function, if exist
 *   outputOid    : OID of the output function, if exist
 *   receiveOid   : OID of the receive function, if exist
 *   sendOid      : OID of the send function, if exist
 *   typmodinOid  : OID of the typemodin function, if exist
 *   typmodoutOid : OID of the typemodout function, if exist
 *   analyzeOid   : OID of the analyze function, if exist
 */
void
ac_type_create(const char *typName, Oid nspOid,
			   Oid inputOid, Oid outputOid, Oid receiveOid, Oid sendOid,
			   Oid typmodinOid, Oid typmodoutOid, Oid analyzeOid)
{
	/*
	 * As of Postgres 8.4, we require superuser privilege to create a base
	 * type.  This is simple paranoia: there are too many ways to mess up the
	 * system with an incorrect type definition (for instance, representation
	 * parameters that don't match what the C code expects).  In practice it
	 * takes superuser privilege to create the I/O functions, and so the
	 * former requirement that you own the I/O functions pretty much forced
	 * superuserness anyway.  We're just making doubly sure here.
	 *
	 * XXX re-enable NOT_USED code sections below if you remove this test.
	 */
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to create a base type")));

#ifdef NOT_USED
	/* XXX this is unnecessary given the superuser check above */
	/* Check we have creation rights in target namespace */
	aclresult = pg_namespace_aclcheck(nspOid, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
					   get_namespace_name(nspOid));
#endif

	/*
	 * Check permissions on functions.	We choose to require the creator/owner
	 * of a type to also own the underlying functions.	Since creating a type
	 * is tantamount to granting public execute access on the functions, the
	 * minimum sane check would be for execute-with-grant-option.  But we
	 * don't have a way to make the type go away if the grant option is
	 * revoked, so ownership seems better.
	 */
#ifdef NOT_USED
	/* XXX this is unnecessary given the superuser check above */
	if (inputOid && !pg_proc_ownercheck(inputOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
					   NameListToString(inputName));
	if (outputOid && !pg_proc_ownercheck(outputOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
					   NameListToString(outputName));
	if (receiveOid && !pg_proc_ownercheck(receiveOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
					   NameListToString(receiveName));
	if (sendOid && !pg_proc_ownercheck(sendOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
					   NameListToString(sendName));
	if (typmodinOid && !pg_proc_ownercheck(typmodinOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
					   NameListToString(typmodinName));
	if (typmodoutOid && !pg_proc_ownercheck(typmodoutOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
					   NameListToString(typmodoutName));
	if (analyzeOid && !pg_proc_ownercheck(analyzeOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_PROC,
					   NameListToString(analyzeName));
#endif
}

/*
 * ac_domain_create
 *
 * It checks privilege to create a new domain type
 *
 * [Params]
 *   domName : Name of the new domain type
 *   nspOid  : OID of the namespace to be used
 */
void
ac_domain_create(const char *domName, Oid nspOid)
{
	AclResult	aclresult;

	/* Check we have creation rights in target namespace */
	aclresult = pg_namespace_aclcheck(nspOid, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
					   get_namespace_name(nspOid));
}

/*
 * ac_enum_create
 *
 * It checks privilege to create a new enumelate type
 *
 * [Params]
 *   enumName : Name of the new enumelate type
 *   nspOid   : OID of the namespace to be used
 */
void
ac_enum_create(const char *enumName, Oid nspOid)
{
	AclResult	aclresult;

	/* Check we have creation rights in target namespace */
	aclresult = pg_namespace_aclcheck(nspOid, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
					   get_namespace_name(nspOid));
}

/*
 * ac_type_alter
 *
 * It checks privilege to alter a certain type
 *
 * [Params]
 *   typOid    : OID of the type to be altered
 *   newName   : New name of the type, if exist
 *   newNspOid : OID of the new type namespace, if exist
 *   newOwner  : OID of the new type owner, if exist
 */
void
ac_type_alter(Oid typOid, const char *newName,
			  Oid newNspOid, Oid newOwner)
{
	AclResult	aclresult;

	if (!pg_type_ownercheck(typOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_TYPE,
					   format_type_be(typOid));

	if (newName)
	{
		/*
		 * MEMO: Why ACL_CREATE on the namespace is not checked
		 * on renaming the type? Other database objects also checks
		 * it on renaming.
		 */
	}

	if (OidIsValid(newNspOid))
	{
		aclresult = pg_namespace_aclcheck(newNspOid, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(newNspOid));
	}

	if (OidIsValid(newOwner))
	{
		if (!superuser())
		{
			Oid		typNsp = get_type_namespace(typOid);

			/* Must be able to become new owner */
			check_is_member_of_role(GetUserId(), newOwner);

			/* New owner must have CREATE privilege on namespace */
			aclresult = pg_namespace_aclcheck(typNsp, newOwner, ACL_CREATE);
			if (aclresult != ACLCHECK_OK)
				aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
							   get_namespace_name(typNsp));
		}
	}
}

/*
 * ac_type_drop
 *
 * It checks privileges to drop a certain type
 *
 * [Params]
 *   typOid  : OID of the type to be dropped
 *   cascade : True, if cascaded deletion
 */
void
ac_type_drop(Oid typOid, bool cascade)
{
	Oid		typNsp = get_type_namespace(typOid);

	/* Permission check: must own type or its namespace */
	if (!cascade &&
		!pg_type_ownercheck(typOid, GetUserId()) &&
		!pg_namespace_ownercheck(typNsp, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_TYPE,
					   format_type_be(typOid));
}

/*
 * ac_type_comment
 *
 * It checks privilege to comment on a certain type
 *
 * [Params]
 *   typOid : OID of the type to be commented on
 */
void
ac_type_comment(Oid typOid)
{
	if (!pg_type_ownercheck(typOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_TYPE,
					   format_type_be(typOid));
}

/*
 * ac_cast_create
 *
 * It checks privilege to create a new cast
 *
 * [Params]
 *   sourceTypOid : OID of the source type
 *   targetTypOid : OID of the target type
 *   castmethod   : One of the COERCION_METHOD_*
 *   funcOid      : OID of the cast function
 */
void
ac_cast_create(Oid sourceTypOid, Oid targetTypOid,
			   char castmethod, Oid funcOid)
{
	/* Must be owner of either source or target type */
	if (!pg_type_ownercheck(sourceTypOid, GetUserId()) &&
		!pg_type_ownercheck(targetTypOid, GetUserId()))
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be owner of type %s or type %s",
						format_type_be(sourceTypOid),
						format_type_be(targetTypOid))));
	/*
	 * Must be superuser to create binary-compatible casts,
	 * since erroneous casts can easily crash the backend.
	 */
	if (castmethod == COERCION_METHOD_BINARY)
	{
		if (!superuser())
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("must be superuser to create a cast WITHOUT FUNCTION")));
	}
}

/*
 * ac_cast_drop
 *
 * It checks privilege to drop a certain cast
 *
 * [Params]
 *   sourceTypOid : OID of the source type
 *   targetTypOid : OID of the target type
 *   cascade      : True, if cascaded deletion
 */
void
ac_cast_drop(Oid sourceTypOid, Oid targetTypOid, bool cascade)
{
	if (!cascade &&
		!pg_type_ownercheck(sourceTypOid, GetUserId()) &&
		!pg_type_ownercheck(targetTypOid, GetUserId()))
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be owner of type %s or type %s",
						format_type_be(sourceTypOid),
						format_type_be(targetTypOid))));
}

/*
 * ac_cast_comment
 *
 * It checks privilege to comment on a certain cast
 *
 * [Params]
 *   sourceTypOid : OID of the source type
 *   targetTypOid : OID of the target type
 */
void
ac_cast_comment(Oid sourceTypOid, Oid targetTypOid)
{
	if (!pg_type_ownercheck(sourceTypOid, GetUserId()) &&
		!pg_type_ownercheck(targetTypOid, GetUserId()))
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be owner of type %s or type %s",
						format_type_be(sourceTypOid),
						format_type_be(targetTypOid))));
}

/*
 * pg_conversion
 */
static char *
get_conversion_name(Oid convOid)
{
	Form_pg_conversion	convForm;
	HeapTuple	convTup;
	char	   *result;

	convTup = SearchSysCache(CONVOID,
							 ObjectIdGetDatum(convOid),
							 0, 0, 0);
	if (!HeapTupleIsValid(convTup))
		elog(ERROR, "cache lookup failed for conversion: %u", convOid);

	convForm = (Form_pg_conversion) GETSTRUCT(convTup);
	result = pstrdup(NameStr(convForm->conname));

	ReleaseSysCache(convTup);

	return result;
}

static Oid
get_conversion_namespace(Oid convOid)
{
	Form_pg_conversion	convForm;
	HeapTuple	convTup;
	Oid			result;

	convTup = SearchSysCache(CONVOID,
							 ObjectIdGetDatum(convOid),
							 0, 0, 0);
	if (!HeapTupleIsValid(convTup))
		elog(ERROR, "cache lookup failed for conversion: %u", convOid);

	convForm = (Form_pg_conversion) GETSTRUCT(convTup);
	result = convForm->connamespace;

	ReleaseSysCache(convTup);

	return result;
}

/*
 * ac_conversion_create
 *
 * It checks privilege to create a new conversion
 *
 * [Params]
 *   convName : Name of the new conversion
 *   nspOid   : OID of the namespace to be created on
 *   funcOid  : OID of the conversion function
 */
void
ac_conversion_create(const char *convName, Oid nspOid, Oid funcOid)
{
	AclResult	aclresult;

	aclresult = pg_namespace_aclcheck(nspOid, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
					   get_namespace_name(nspOid));

	aclresult = pg_proc_aclcheck(funcOid, GetUserId(), ACL_EXECUTE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_PROC,
					   get_func_name(funcOid));
}

/*
 * ac_conversion_alter
 *
 * It checks privilege to alter a certain conversion
 *
 * [Params]
 *   convOid  : OID of the conversion to be altered
 *   newName  : New name of the conversion, if exist
 *   newOwner : OID of the new conversion owner, if exist
 */
void
ac_conversion_alter(Oid convOid, const char *newName, Oid newOwner)
{
	Oid			nspOid = get_conversion_namespace(convOid);
	AclResult	aclresult;

	/* Must be owner for all the ALTER CONVERSION options */
	if (!pg_conversion_ownercheck(convOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CONVERSION,
					   get_conversion_name(convOid));

	/* Must have CREATE privilege on namespace on renaming */
	if (newName)
	{
		aclresult = pg_namespace_aclcheck(nspOid, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(nspOid));
	}

	if (OidIsValid(newOwner))
	{
		if (!superuser())
		{
			/* Must be able to become new owner */
			check_is_member_of_role(GetUserId(), newOwner);

			/* New owner must have CREATE privilege on namespace */
			aclresult = pg_namespace_aclcheck(nspOid, newOwner, ACL_CREATE);
			if (aclresult != ACLCHECK_OK)
                aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
							   get_namespace_name(nspOid));
		}
	}
}

/*
 * ac_conversion_drop
 *
 * It checks privilege to drop a certain conversion
 *
 * [Params]
 *   convOid : OID of the target conversion
 *   cascade : Trus, if cascaded deletion
 */
void
ac_conversion_drop(Oid convOid, bool cascade)
{
	Oid		nspOid = get_conversion_namespace(convOid);

	if (!cascade &&
		!pg_conversion_ownercheck(convOid, GetUserId()) &&
		!pg_namespace_ownercheck(nspOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CONVERSION,
					   get_conversion_name(convOid));
}

/*
 * ac_conversion_comment
 *
 * It checks privilege to comment on a certain conversion
 *
 * [Params]
 *   convOid : OID of the conversion to be commented on
 */
void
ac_conversion_comment(Oid convOid)
{
	if (!pg_conversion_ownercheck(convOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CONVERSION,
					   get_conversion_name(convOid));
}
