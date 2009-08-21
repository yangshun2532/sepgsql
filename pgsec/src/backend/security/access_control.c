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
#include "miscadmin.h"
#include "security/common.h"
#include "utils/acl.h"
#include "utils/lsyscache.h"
#include "utils/security.h"









/* ************************************************************
 *
 * Pg_rewrite system catalog related access control stuffs
 *
 * ************************************************************/
void
ac_rule_create(Oid relOid, const char *ruleName)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

void
ac_rule_drop(Oid relOid, const char *ruleName, bool cascade)
{
	if (!cascade &&
		!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

void
ac_rule_comment(Oid relOid, const char *ruleName)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

void
ac_rule_toggle(Oid relOid, const char *ruleName, char fire_when)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}
