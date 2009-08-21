/*
 * src/backend/security/access_control.c
 *
 * Routines for common access control facilities. 
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_rewrite.h"
#include "catalog/pg_ts_config.h"
#include "catalog/pg_ts_dict.h"
#include "catalog/pg_ts_parser.h"
#include "catalog/pg_ts_template.h"
#include "miscadmin.h"
#include "security/common.h"
#include "utils/acl.h"
#include "utils/lsyscache.h"
#include "utils/security.h"
#include "utils/syscache.h"









/* ************************************************************
 *
 * Pg_rewrite system catalog related access control stuffs
 *
 * ************************************************************/

/*
 * ac_rule_create
 *
 * It checks privilege to create a new query rewrite rule.
 *
 * [Params]
 * relOid   : OID of the relation to be applied on
 * ruleName : Name of the query rewrite rule
 */
void
ac_rule_create(Oid relOid, const char *ruleName)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * ac_rule_drop
 *
 * It checks privilege to drop a certain query rewrite rule
 *
 * [Params]
 * relOid   : OID of the relation to be applied on
 * ruleName : Name of the query rewrite rule
 * cascade  : True, if cascaded deletion
 */
void
ac_rule_drop(Oid relOid, const char *ruleName, bool cascade)
{
	if (!cascade &&
		!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * ac_rule_comment
 *
 * It checks privilege to comment on a certain query rewrite rule
 *
 * [Params]
 * relOid   : OID of the relation to be applied on
 * ruleName : Name of the query rewrite rule
 */
void
ac_rule_comment(Oid relOid, const char *ruleName)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * ac_rule_toggle
 *
 * It checks privilege to enable/disable a certain query rewrite rule
 *
 * [Params]
 * relOid    : OID of the relation to be applied on
 * ruleName  : Name of the query rewrite rule
 * fire_when : One of the RULE_FIRES_* or RULE_DISABLED
 */
void
ac_rule_toggle(Oid relOid, const char *ruleName, char fire_when)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/* ************************************************************
 *
 * Pg_ts_config system catalog related access control stuffs
 *
 * ************************************************************/

static char *
get_ts_config_name(Oid cfgOid)
{
	Form_pg_ts_config	cfgForm;
	HeapTuple	cfgTup;
	char	   *cfgName;

	cfgTup =  SearchSysCache(TSCONFIGOID,
							 ObjectIdGetDatum(cfgOid),
							 0, 0, 0);
	if (!HeapTupleIsValid(cfgTup))
		elog(ERROR, "cache lookup failed for text search configuration %u", cfgOid);

	cfgForm = ((Form_pg_ts_config) GETSTRUCT(cfgTup));
	cfgName = pstrdup(NameStr(cfgForm->cfgname));

	ReleaseSysCache(cfgTup);

	return cfgName;
}

static Oid
get_ts_config_namespace(Oid cfgOid)
{
	HeapTuple	cfgTup;
	Oid			cfgNsp;

	cfgTup =  SearchSysCache(TSCONFIGOID,
							 ObjectIdGetDatum(cfgOid),
							 0, 0, 0);
	if (!HeapTupleIsValid(cfgTup))
		elog(ERROR, "cache lookup failed for text search configuration %u", cfgOid);

	cfgNsp = ((Form_pg_ts_config) GETSTRUCT(cfgTup))->cfgnamespace;

	ReleaseSysCache(cfgTup);

	return cfgNsp;
}

/*
 * ac_ts_config_create
 *
 * It checks privilege to create a new text search config
 *
 * [Params]
 * cfgName : Name of the new text search config
 * cfgNsp  : OID of the namespace to be used
 */
void
ac_ts_config_create(const char *cfgName, Oid cfgNsp)
{
	AclResult	aclresult;

	/* Check we have creation rights in target namespace */
	aclresult = pg_namespace_aclcheck(cfgNsp, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
					   get_namespace_name(cfgNsp));
}

/*
 * ac_ts_config_alter
 *
 * It checks privilege to alter a certain text search config
 *
 * [Params]
 * cfgOid   : OID of the text search config to be dropped
 * newName  : New name of the text search config, if exist
 * newOwner : New owner of the text search config, if exist
 */
void
ac_ts_config_alter(Oid cfgOid, const char *newName, Oid newOwner)
{
	Oid			cfgNsp = get_ts_config_namespace(cfgOid);
	AclResult	aclresult;

	/* Must be owner for all the ALTER TEXT SEARCH CONFIG options */
	if (!pg_ts_config_ownercheck(cfgOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_TSCONFIGURATION,
					   get_ts_config_name(cfgOid));

	/* Must have CREATE privilege on namespace when renaming */
	if (newName)
	{
		aclresult = pg_namespace_aclcheck(cfgNsp, GetUserId(), ACL_CREATE);
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
					   get_namespace_name(cfgNsp));
	}

	/* Superusers can always do it */
	if (OidIsValid(newOwner) && !superuser())
	{
		/* Must be able to become new owner */
		check_is_member_of_role(GetUserId(), newOwner);

		/* New owner must have CREATE privilege on namespace */
		aclresult = pg_namespace_aclcheck(cfgNsp, newOwner, ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(cfgNsp));
	}
}

/*
 * ac_ts_config_drop
 *
 * It checks privilege to drop a certain text search config
 *
 * [Params]
 * cfgOid  : OID of the text search config to be dropped
 * cascade : True, if cascaded deletion
 */
void
ac_ts_config_drop(Oid cfgOid, bool cascade)
{
	Oid		cfgNsp = get_ts_config_namespace(cfgOid);

	if (!cascade &&
		!pg_ts_config_ownercheck(cfgOid, GetUserId()) &&
		!pg_namespace_ownercheck(cfgNsp, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_TSCONFIGURATION,
					   get_ts_config_name(cfgOid));
}

/*
 * ac_ts_config_comment
 *
 * It checks privilege to comment on a certain text search config
 *
 * [Params]
 * cfgOid : OID of the text search config to be dropped
 */
void
ac_ts_config_comment(Oid cfgOid)
{
	if (!pg_ts_config_ownercheck(cfgOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_TSCONFIGURATION,
					   get_ts_config_name(cfgOid));
}

/* ************************************************************
 *
 * Pg_ts_dict system catalog related access control stuffs
 *
 * ************************************************************/

static char *
get_ts_dict_name(Oid dictOid)
{
	Form_pg_ts_dict	dictForm;
	HeapTuple	dictTup;
	char	   *dictName;

	dictTup = SearchSysCache(TSDICTOID,
							 ObjectIdGetDatum(dictOid),
							 0, 0, 0);
	if (!HeapTupleIsValid(dictTup))
		elog(ERROR, "cache lookup failed for text search dictionary %u", dictOid);

	dictForm = (Form_pg_ts_dict) GETSTRUCT(dictTup);
	dictName = pstrdup(NameStr(dictForm->dictname));

	ReleaseSysCache(dictTup);

	return dictName;
}

static Oid
get_ts_dict_namespace(Oid dictOid)
{
	HeapTuple	dictTup;
	Oid			dictNsp;

	dictTup = SearchSysCache(TSDICTOID,
							 ObjectIdGetDatum(dictOid),
							 0, 0, 0);
	if (!HeapTupleIsValid(dictTup))
		elog(ERROR, "cache lookup failed for text search dictionary %u", dictOid);

	dictNsp = ((Form_pg_ts_dict) GETSTRUCT(dictTup))->dictnamespace;

	ReleaseSysCache(dictTup);

	return dictNsp;
}

/*
 * ac_ts_dict_create
 *
 * It checks privilege to create a new text search dictionary
 *
 * [Params]
 * dictName : Name of the new text search dictionary
 * dictNsp  : OID of the namespace to be used
 */
void
ac_ts_dict_create(const char *dictName, Oid dictNsp)
{
	AclResult	aclresult;

	/* Check we have creation rights in target namespace */
	aclresult = pg_namespace_aclcheck(dictNsp, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
					   get_namespace_name(dictNsp));
}

/*
 * ac_ts_dict_alter
 *
 * It checks privilege to alter a certain text search dictionary
 *
 * [Params]
 * dictOid  : OID of the text search dictionary to be altered
 * newName  : New name of the text search dictionary, if exist
 * newOwner : New OID of the text search dictionary owner, if exist
 */
void
ac_ts_dict_alter(Oid dictOid, const char *newName, Oid newOwner)
{
	Oid			dictNsp = get_ts_dict_namespace(dictOid);
	AclResult	aclresult;

	/* Must be owner for all the ALTER TEXT SEARCH DICTIONARY options */
	if (!pg_ts_dict_ownercheck(dictOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_TSDICTIONARY,
					   get_ts_dict_name(dictOid));

	/* must have CREATE privilege on namespace, if renaming */
	if (newName)
	{
		aclresult = pg_namespace_aclcheck(dictNsp, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(dictNsp));
	}

	/* Superusers can always do it */
	if (OidIsValid(newOwner) && !superuser())
	{
		/* Must be able to become new owner */
		check_is_member_of_role(GetUserId(), newOwner);

		/* New owner must have CREATE privilege on namespace */
		aclresult = pg_namespace_aclcheck(dictNsp, newOwner, ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(dictNsp));
	}
}

/*
 * ac_ts_dict_drop
 *
 * It checks privilege to drop a certain text search dictionary
 *
 * [Params]
 * dictOid : OID of the text search dictionary to be dropped
 * cascade : True, if cascaded deletion
 */
void
ac_ts_dict_drop(Oid dictOid, bool cascade)
{
	Oid		dictNsp = get_ts_dict_namespace(dictOid);

	/* Must be owner of the dictionary or its namespace */
	if (!cascade &&
		!pg_ts_dict_ownercheck(dictOid, GetUserId()) &&
		!pg_namespace_ownercheck(dictNsp, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_TSDICTIONARY,
					   get_ts_dict_name(dictOid));
}

/*
 * ac_ts_dict_comment
 *
 * It checks privilege to comment on a certain text search dictionary
 *
 * [Params]
 * dictOid : OID of the text search dictionary to be commented
 */
void
ac_ts_dict_comment(Oid dictOid)
{
   	if (!pg_ts_dict_ownercheck(dictOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_TSDICTIONARY,
					   get_ts_dict_name(dictOid));
}

/* ************************************************************
 *
 * Pg_ts_parser system catalog related access control stuffs
 *
 * ************************************************************/

/*
 * ac_ts_parser_create
 *
 * It checks privilege to create a new text search parser
 *
 * [Params]
 * prsName    : Name of the new text search parser
 * prsNsp     : OID of the namespace to be used
 * startFn    : OID of the start function
 * tokenFn    : OID of the token function
 * sendFn     : OID of the send function
 * headlineFn : OID of the headline function, if exist
 * lextypeFn  : OID of the lextype function
 */
void
ac_ts_parser_create(const char *prsName, Oid prsNsp,
					Oid startFn, Oid tokenFn, Oid sendFn,
					Oid headlineFn, Oid lextypeFn)
{
	/*
	 * Note that it checks superuser privilege here, so it implicitly 
	 * allows the caller to create a new object within the namespace
	 * and grant public to execute the given functions.
	 * These permissions should be checked, if we don't omit obvious
	 * checks.
	 */
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to create text search parsers")));
}

/*
 * ac_ts_parser_alter
 *
 * It checks privilege to alter a certain text search parser
 *
 * [Params]
 * prsOid  : OID of the text search parser
 * newName : New name of the text search parser, if exist
 */
void
ac_ts_parser_alter(Oid prsOid, const char *newName)
{
	/*
	 * Note that it checks superuser privilege here, so it implicitly
	 * allows caller CREATE privilege on the current namespace.
	 */
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to rename text search parsers")));
}

/*
 * ac_ts_parser_drop
 *
 * It checks privilege to drop a certain text search parser
 *
 * [Params]
 * prsOid  : OID of the text search parser
 * cascade : True, if cascaded deletion
 */
void
ac_ts_parser_drop(Oid prsOid, bool cascade)
{
	if (!cascade && !superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to drop text search parsers")));
}

/*
 * ac_ts_parser_comment
 *
 * It checks privilege to comment on a certain text search parser
 *
 * [Params]
 * prsOid  : OID of the text search parser
 */
void
ac_ts_parser_comment(Oid prsOid)
{
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to comment on text search parser")));
}

/* ************************************************************
 *
 * Pg_ts_template system catalog related access control stuffs
 *
 * ************************************************************/

/*
 * ac_ts_template_create
 *
 * It checks privilege to create a new text search templace
 *
 * [Params]
 * tmplName : Name of the new text search template
 * tmplNsp  : OID of the namespace to be used
 * initFn   : OID of the initialization function, if exist
 * lexizeFn : OID of the base function of dictionary
 */
void
ac_ts_template_create(const char *tmplName, Oid tmplNsp,
					  Oid initFn, Oid lexizeFn)
{
	/*
	 * Note that it checks superuser privilege here, so it implicitly 
	 * allows the caller to create a new object within the namespace
	 * and grant public to execute the given functions.
	 * These permissions should be checked, if we don't omit obvious
	 * checks.
	 */
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to create text search templates")));
}

/*
 * ac_ts_template_alter
 *
 * It checks privilege to alter a certain text search templates
 *
 * [Params]
 * tmplOid : OID of the text search template to be altered
 * newName : New name of the text search template, if exist
 */
void
ac_ts_template_alter(Oid tmplOid, const char *newName)
{
	/*
	 * Note that it checks superuser privilege here, so it implicitly
	 * allows caller CREATE privilege on the current namespace.
	 */
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to rename text search templates")));
}

/*
 * ac_ts_template_drop
 *
 * It checks privilege to drop a certain text search template
 *
 * [Params]
 * tmplOid : OID of the text search template to be dropped
 * cascade : True, if cascaded deletion
 */
void
ac_ts_template_drop(Oid tmplOid, bool cascade)
{
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to drop text search templates")));
}

/*
 * ac_ts_template_comment
 *
 * It checks privilege to comment on a certain tect search template
 *
 * [Params]
 * tmplOid : OID of the text search template to be commented on
 */
void
ac_ts_template_comment(Oid tmplOid)
{
	if (!superuser())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("must be superuser to comment on text search template")));
}
