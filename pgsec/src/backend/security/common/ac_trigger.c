/*
 * src/backend/security/common/ac_trigger.c
 *   common access control abstration corresponding to trigger objects
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_trigger.h"
#include "security/common.h"

#include "utils/lsyscache.h"

/*
 * ac_trigger_create
 *
 * It checks privilege to create a new trigger on a certain table.
 *
 * [Params]
 *   relOid    : OID of the relation on which the trigger is set up
 *   conRelOid : OID of the constrained relation, if exist
 *   funcOid   : OID of the trigger function
 */
void
ac_trigger_create(Oid relOid, Oid conRelOid, Oid funcOid)
{
	AclResult	aclresult;

	aclresult = pg_class_aclcheck(relOid, GetUserId(), ACL_TRIGGER);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_CLASS, get_rel_name(relOid));

	if (OidIsValid(conRelOid))
	{
		aclresult = pg_class_aclcheck(conRelOid, GetUserId(), ACL_TRIGGER);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_CLASS, get_rel_name(conRelOid));
	}
}

/*
 * ac_trigger_alter
 *
 * It checks privilege to alter definition of a certain trigger.
 * Currently, only an operation to rename is defined on triggers.
 *
 * [Params]
 *   relOid  : OID of the ralation on which the trigger is set up
 *   trigTup : HeapTuple of the target trigger
 *   newName : New name of the trigger
 */
void
ac_trigger_alter(Oid relOid, HeapTuple trigTup, const char *newName)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * ac_trigger_drop
 *
 * It checks privilege to drop a certain trigger
 *
 * [Params]
 *   relOid  : OID of the ralation on which the trigger is set up
 *   trigTup : HeapTuple of the target trigger
 *   cascade : True, if cascaded deletion
 */
void
ac_trigger_drop(Oid relOid, HeapTuple trigTup, bool cascade)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * ac_trigger_comment
 *
 * It checks privilege to comment on a certain trigger
 *
 * [Params]
 *   relOid  : OID of the ralation on which the trigger is set up
 *   trigTup : HeapTuple of the target trigger
 */
void
ac_trigger_comment(Oid relOid, HeapTuple trigTup)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}
