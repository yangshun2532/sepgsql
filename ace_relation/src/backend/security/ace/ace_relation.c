/*
 * ace_relation.c
 *
 * security hooks related to relation object class.
 *
 * Portions Copyright (c) 1996-2010, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "miscadmin.h"
#include "security/ace.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"

/*
 * check_relation_perms
 *
 * It enables security providers to check permission to access a certain
 * relation and columns using regular dml statements and etc.
 *
 * relOid : OID of the relation to be accessed
 * userId : OID of the database role to be accessed
 * requiredPerms : ACL_* flags to be checked
 * selCols : bitmapset of the columns to be referenced
 * modCols : bitmapset of the columns to be modified
 * abort : True, if the caller want to raise an error on violation.
 */
bool
check_relation_perms(Oid relOid, Oid userId, AclMode requiredPerms,
					 Bitmapset *selCols, Bitmapset *modCols, bool abort)
{
	AclMode		relPerms;
	AclMode		remainingPerms;
	Bitmapset  *tmpset;
	int			col;

	/*
	 * We must have *all* the requiredPerms bits, but some of the bits can be
	 * satisfied from column-level rather than relation-level permissions.
	 * First, remove any bits that are satisfied by relation permissions.
	 */
	relPerms = pg_class_aclmask(relOid, userId, requiredPerms, ACLMASK_ALL);
	remainingPerms = requiredPerms & ~relPerms;
	if (remainingPerms != 0)
	{
		/*
		 * If we lack any permissions that exist only as relation permissions,
		 * we can fail straight away.
		 */
		if (remainingPerms & ~(ACL_SELECT | ACL_INSERT | ACL_UPDATE))
		{
			if (abort)
				aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_CLASS,
							   get_rel_name(relOid));
			return false;
		}

		/*
		 * Check to see if we have the needed privileges at column level.
		 *
		 * Note: failures just report a table-level error; it would be nicer
		 * to report a column-level error if we have some but not all of the
		 * column privileges.
		 */
		if (remainingPerms & ACL_SELECT)
		{
			/*
			 * When the query doesn't explicitly reference any columns (for
			 * example, SELECT COUNT(*) FROM table), allow the query if we
			 * have SELECT on any column of the rel, as per SQL spec.
			 */
			if (bms_is_empty(rte->selectedCols))
			{
				if (pg_attribute_aclcheck_all(relOid, userid, ACL_SELECT,
											  ACLMASK_ANY) != ACLCHECK_OK)
				{
					if (abort)
						aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_CLASS,
									   get_rel_name(relOid));
					return false;
				}
			}

			tmpset = bms_copy(rte->selectedCols);
			while ((col = bms_first_member(tmpset)) >= 0)
			{
				/* remove the column number offset */
				col += FirstLowInvalidHeapAttributeNumber;
				if (col == InvalidAttrNumber)
				{
					/* Whole-row reference, must have priv on all cols */
					if (pg_attribute_aclcheck_all(relOid, userid, ACL_SELECT,
												  ACLMASK_ALL) != ACLCHECK_OK)
					{
						if (abort)
							aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_CLASS,
										   get_rel_name(relOid));
						return false;
					}
				}
				else
				{
					if (pg_attribute_aclcheck(relOid, col, userid,
											  ACL_SELECT) != ACLCHECK_OK)
					{
						if (abort)
							aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_CLASS,
										   get_rel_name(relOid));
						return false;
					}
				}
			}
			bms_free(tmpset);
		}

		/*
		 * Basically the same for the mod columns, with either INSERT or
		 * UPDATE privilege as specified by remainingPerms.
		 */
		remainingPerms &= ~ACL_SELECT;
		if (remainingPerms != 0)
		{
			/*
			 * When the query doesn't explicitly change any columns, allow the
			 * query if we have permission on any column of the rel.  This is
			 * to handle SELECT FOR UPDATE as well as possible corner cases in
			 * INSERT and UPDATE.
			 */
			if (bms_is_empty(rte->modifiedCols))
			{
				if (pg_attribute_aclcheck_all(relOid, userid, remainingPerms,
											  ACLMASK_ANY) != ACLCHECK_OK)
				{
					if (abort)
						aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_CLASS,
									   get_rel_name(relOid));
					return false;
				}
			}

			tmpset = bms_copy(rte->modifiedCols);
			while ((col = bms_first_member(tmpset)) >= 0)
			{
				/* remove the column number offset */
				col += FirstLowInvalidHeapAttributeNumber;
				if (col == InvalidAttrNumber)
				{
					/* whole-row reference can't happen here */
					elog(ERROR, "whole-row update is not implemented");
				}
				else
				{
					if (pg_attribute_aclcheck(relOid, col, userid,
											  remainingPerms) != ACLCHECK_OK)
					{
						if (abort)
							aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_CLASS,
										   get_rel_name(relOid));
						return false;
					}
				}
			}
			bms_free(tmpset);
		}
	}

	return true;
}

/*
 * check_relation_perms
 *
 * It enables security providers to check permission to create a new
 * relation.
 *
 * Note that it is not checked on the following cases, although it
 * creates a new relation in actually:
 * - Boot_CreateStmt handling in bootparse
 *   No need to check permission in bootstraping mode
 * - create_toast_table()
 *   TOAST relation is pure internal stuff, no need to check permission
 * - make_new_heap()
 *   This relation is pure internal stuff to cluster the contents, and
 *   it shall be dropped soon. 
 *
 * relName : Name of the new relation
 * relkind : Relkind of the new relation
 * tupDesc : tupDesc of the new relation
 * relNsp  : OID of the namespace to create in
 * relTblspc : OID of the tablespace, if exist
 * colList : List of ColumnDef, if exist
 * isTemp  : True, if the new table is temporary
 * createAs : Trus, if CREATE TABLE AS/SELECT INTO
 */
void
check_relation_create(const char *relName, char relkind,
					  TupleDesc tupDesc, Oid relNsp, Oid relTblspc,
					  List *colList, bool isTemp, bool createAs)
{
	AclResult	aclresult;

	/*
	 * Security check: disallow creating temp tables from security-restricted
	 * code.  This is needed because calling code might not expect untrusted
	 * tables to appear in pg_temp at the front of its search path.
	 */
	if (isTemp && InSecurityRestrictedOperation())
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("cannot create temporary table within "
						"security-restricted operation")));

	/*
	 * Check we have permission to create there. Skip check if bootstrapping,
	 * since permissions machinery may not be working yet.
	 */
	if (!IsBootstrapProcessingMode())
	{
		aclresult = pg_namespace_aclcheck(relNsp, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(relNsp));
	}

	/* Check permissions except when using database's default */
	if (OidIsValid(relTblspc) && relTblspc != MyDatabaseTableSpace)
	{
		aclresult = pg_tablespace_aclcheck(relTblspc, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_TABLESPACE,
						   get_tablespace_name(relTblspc));
	}
}

void
check_relation_alter(Oid relOid)
{}
void
check_relation_alter_rename(Oid relOid, const char *newName)
{}
void
check_relation_alter_schema(Oid relOid, Oid newNsp)
{}
void
check_relation_alter_tablespace(Oid relOid, Oid newTblspc)
{}
void
check_relation_alter_owner(Oid relOid, Oid newOwner)
{}
void
check_relation_drop(Oid relOid, bool cascade)
{}
void
chech_relation_getattr(Oid relOid)
{}
void
check_relation_grant(Oid relOid)
{}
void
check_relation_comment(Oid relOid)
{}
void
check_relation_inheritance(Oid parentOid, Oid childOid)
{}
void
check_relation_cluster(Oid relOid, bool abort)
{}
void
check_relation_truncate(Relation rel)
{}
void
check_relation_reference(Relation rel, int16 *attnums, int natts)
{}
void
check_relation_lock(Relation rel, LOCKMODE lockmode)
{}
bool
check_relation_vacuum(Relation rel)
{}
// XXX - index permission shall be here
void
check_relation_reindex(Oid relOid)
{}
void
check_view_replace(Oid relOid)
{}

/*
 * check_sequence_get_value
 *
 * It enables security providers to check permission to reference
 * a certain sequence object, using currval() or lastval().
 *
 * seqOid : OID of the sequence to be referenced
 */
void
check_sequence_get_value(Oid seqOid)
{
	Assert(get_rel_relkind(seqOid) == RELKIND_SEQUENCE);

	if (pg_class_aclcheck(elm->relid, GetUserId(), ACL_SELECT) != ACLCHECK_OK &&
		pg_class_aclcheck(elm->relid, GetUserId(), ACL_USAGE) != ACLCHECK_OK)
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied for sequence %s",
						get_rel_name(seqOid))));
}

/*
 * check_sequence_next_value
 *
 * It enables security providers to check permission to fetch a value
 * from a certain sequence object, using nextval()
 *
 * seqOid : OID of the sequence to be referenced
 */
void
check_sequence_next_value(Oid seqOid)
{
	Assert(get_rel_relkind(seqOid) == RELKIND_SEQUENCE);

	if (pg_class_aclcheck(seqOid, GetUserId(), ACL_USAGE) != ACLCHECK_OK &&
		pg_class_aclcheck(seqOid, GetUserId(), ACL_UPDATE) != ACLCHECK_OK)
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied for sequence %s",
						get_rel_name(seqOid))));
}

/*
 * check_sequence_set_value
 *
 * It enables security providers to check permission to set an arbitary
 * value on a certain sequence object, using setval()
 *
 * seqOid : OID of the sequence to be referenced
 */
void
check_sequence_set_value(Oid seqOid)
{
	Assert(get_rel_relkind(seqOid) == RELKIND_SEQUENCE);

	if (pg_class_aclcheck(seqOid, GetUserId(), ACL_UPDATE) != ACLCHECK_OK)
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied for sequence %s",
						get_rel_name(seqOid))));
}
