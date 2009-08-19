/*
 * src/backend/security/common/ac_language.c
 *   common access control abstration corresponding to procedural languages
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_language.h"
#include "commands/dbcommands.h"
#include "miscadmin.h"
#include "security/common.h"
#include "utils/syscache.h"

/*
 * Helper functions
 */
static char *
get_lang_name(Oid langOid)
{
	HeapTuple	langTup;
	char	   *result = NULL;

	langTup = SearchSysCache(LANGOID,
							 ObjectIdGetDatum(langOid),
							 0, 0, 0);
	if (HeapTupleIsValid(langTup))
	{
		Form_pg_language	langForm
			= (Form_pg_language) GETSTRUCT(langTup);

		result = pstrdup(NameStr(langForm->lanname));

		ReleaseSysCache(langTup);
	}
	return result;
}

/*
 * ac_language_create
 *
 * It checks privilege to create a new procedural language.
 *
 * [Params]
 *   langName     : Name of the new procedural language
 *   IsTemplate   : True, if the procedural language is based on a template
 *   plTrusted    : A copy from PLTemplate->tmpltrusted, if exist
 *   plDbaCreate  : A copy from PLTemplate->tmpldbacreate, if exist
 *   handlerOid   : OID of the handler function
 *   validatorOid : OID of the validator function
 */
void
ac_language_create(const char *langName, bool IsTemplate,
				   bool plTrusted, bool plDbaCreate,
				   Oid handlerOid, Oid validatorOid)
{
	if (!superuser())
	{
		if (!IsTemplate)
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("must be superuser to create "
							"custom procedural language")));

		if (!plDbaCreate)
			ereport(ERROR,
                    (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                     errmsg("must be superuser to create "
							"procedural language \"%s\"", langName)));

		if (!pg_database_ownercheck(MyDatabaseId, GetUserId()))
			aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_DATABASE,
						   get_database_name(MyDatabaseId));
	}
}

/*
 * ac_language_alter
 *
 * It checks privilege to alter a certain procedural language
 *
 * [Params]
 *   langOid  : OID of the procedural language
 *   newName  : New name of the procedural language, if exist
 *   newOwner : New owner of the procedural language, if exist
 */
void
ac_language_alter(Oid langOid, const char *newName, Oid newOwner)
{
	/* must be owner of PL */
	if (!pg_language_ownercheck(langOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_LANGUAGE,
					   get_lang_name(langOid));

	/* Must be able to become new owner, when owner changes  */
	if (OidIsValid(newOwner))
		check_is_member_of_role(GetUserId(), newOwner);
}

/*
 * ac_langugae_drop
 *
 * It checks privilege to drop a certain procedural language
 *
 * [Params]
 *   langOid : 
 *   cascade : True, if cascaded deletion
 */
void
ac_language_drop(Oid langOid, bool cascade)
{
	if (!cascade &&
		!pg_language_ownercheck(langOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_LANGUAGE,
					   get_lang_name(langOid));
}

/*
 * ac_language_grant
 *
 * It checks privilege to grant/revoke permissions on procedural language
 *
 * [Params]
 *   langOid  : OID of the target procedural language
 *   grantor  : OID of the gractor database role
 *   goptions : Available AclMask to grant others
 */
void
ac_language_grant(Oid langOid, Oid grantor, AclMode goptions)
{
	if (goptions == ACL_NO_RIGHTS)
	{
		AclMode		whole_mask = ACL_ALL_RIGHTS_LANGUAGE;

		if (pg_language_aclmask(langOid, grantor,
								whole_mask | ACL_GRANT_OPTION_FOR(whole_mask),
								ACLMASK_ANY) == ACL_NO_RIGHTS)
			aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_LANGUAGE,
						   get_lang_name(langOid));
	}
}

/*
 * ac_language_comment
 *
 * It checks privilege to comment on a certain procedural language
 *
 * [Params]
 *   langOid : OID of the procedural language
 */
void
ac_language_comment(Oid langOid)
{
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to comment on procedural language")));
}
