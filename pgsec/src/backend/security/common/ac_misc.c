/*
 * src/backend/security/common/ac_misc.c
 *   common access control abstration for misc objects
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/sysattr.h"
#include "security/common.h"
#include "utils/lsyscache.h"

/*
 * ac_relation_perms
 *
 * It checks privileges to access a certain table and columns using regular DML.
 *
 * [Params]
 *   relOid        : OID of the target relation
 *   roleId        : OID of the database role to be evaluated
 *   requiredPerms : mask of permission bits
 *   selectedCols  : bitmapset of referenced columns
 *   modifiedCols  : bitmapset of modified columns
 *   abort         : Trus, if caller want to raise an error, if violated
 */
bool
ac_relation_perms(Oid relOid, Oid roleId, AclMode requiredPerms,
				  Bitmapset *selectedCols, Bitmapset *modifiedCols, bool abort)
{
	AclMode		relationPerms;
	AclMode		remainingPerms;
	Bitmapset  *tmpset;
	int			col;

	/*
	 * We must have *all* the requiredPerms bits, but some of the bits can be
	 * satisfied from column-level rather than relation-level permissions.
	 * First, remove any bits that are satisfied by relation permissions.
	 */
	relationPerms = pg_class_aclmask(relOid, roleId, requiredPerms, ACLMASK_ALL);
	remainingPerms = requiredPerms & ~relationPerms;
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
			if (bms_is_empty(selectedCols))
			{
				if (pg_attribute_aclcheck_all(relOid, roleId, ACL_SELECT,
											  ACLMASK_ANY) != ACLCHECK_OK)
				{
					if (abort)
						aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_CLASS,
									   get_rel_name(relOid));
					return false;
				}
			}

			tmpset = bms_copy(selectedCols);
			while ((col = bms_first_member(tmpset)) >= 0)
			{
				/* remove the column number offset */
				col += FirstLowInvalidHeapAttributeNumber;
				if (col == InvalidAttrNumber)
				{
					/* Whole-row reference, must have priv on all cols */
					if (pg_attribute_aclcheck_all(relOid, roleId, ACL_SELECT,
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
					if (pg_attribute_aclcheck(relOid, col, roleId,
											  ACL_SELECT) != ACLCHECK_OK)
					{
						if (abort)
							aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_CLASS,
										   get_rel_name(relOid));
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
			if (bms_is_empty(modifiedCols))
			{
				if (pg_attribute_aclcheck_all(relOid, roleId, remainingPerms,
											  ACLMASK_ANY) != ACLCHECK_OK)
				{
					if (abort)
						aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_CLASS,
									   get_rel_name(relOid));
					return false;
				}
			}

			tmpset = bms_copy(modifiedCols);
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
					if (pg_attribute_aclcheck(relOid, col, roleId,
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
