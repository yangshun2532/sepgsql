/*
 * ace_relation.c
 *
 * security hooks related to relation object class.
 *
 * Portions Copyright (c) 1996-2010, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "access/sysattr.h"
#include "commands/tablespace.h"
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
			if (bms_is_empty(selCols))
			{
				if (pg_attribute_aclcheck_all(relOid, userId, ACL_SELECT,
											  ACLMASK_ANY) != ACLCHECK_OK)
				{
					if (abort)
						aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_CLASS,
									   get_rel_name(relOid));
					return false;
				}
			}

			tmpset = bms_copy(selCols);
			while ((col = bms_first_member(tmpset)) >= 0)
			{
				/* remove the column number offset */
				col += FirstLowInvalidHeapAttributeNumber;
				if (col == InvalidAttrNumber)
				{
					/* Whole-row reference, must have priv on all cols */
					if (pg_attribute_aclcheck_all(relOid, userId, ACL_SELECT,
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
					if (pg_attribute_aclcheck(relOid, col, userId,
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
			if (bms_is_empty(modCols))
			{
				if (pg_attribute_aclcheck_all(relOid, userId, remainingPerms,
											  ACLMASK_ANY) != ACLCHECK_OK)
				{
					if (abort)
						aclcheck_error(ACLCHECK_NO_PRIV, ACL_KIND_CLASS,
									   get_rel_name(relOid));
					return false;
				}
			}

			tmpset = bms_copy(modCols);
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
					if (pg_attribute_aclcheck(relOid, col, userId,
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

/*
 * check_relation_alter
 *
 * It checks privileges to alter properties of the relation.
 *
 * relOid : OID of the relation to be altered
 */
void
check_relation_alter(Oid relOid)
{
	/* Must be owner of the relation */
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * check_relation_alter
 *
 * It checks privileges to rename the given relation.
 *
 * relOid : OID of the relation to be altered
 * newName : New name of the relation to be set
 */
void
check_relation_alter_rename(Oid relOid, const char *newName)
{
	AclResult	aclresult;
	Oid			relNsp;

	/* Must be owner of the relation */
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));

	relNsp = get_rel_namespace(relOid);
	aclresult = pg_namespace_aclcheck(relNsp, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
					   get_namespace_name(relNsp));
}

/*
 * check_relation_alter_schema
 *
 * It checks privileges to set a new schema of the relation
 *
 * relOid : OID of the relation to be altered
 * newNsp : OID of the new namespace to be set
 */
void
check_relation_alter_schema(Oid relOid, Oid newNsp)
{
	AclResult	aclresult;

	/* Must be owner of the relation */
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));

	aclresult = pg_namespace_aclcheck(newNsp, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
					   get_namespace_name(newNsp));
}

/*
 * check_relation_alter_tablespace
 *
 * It checks privileges to alter properties of the relation.
 *
 * relOid : OID of the relation to be altered
 * newTblspc : OID of the new tablespace to be set
 */
void
check_relation_alter_tablespace(Oid relOid, Oid newTblspc)
{
	AclResult	aclresult;

	/* Must be owner of the relation */
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));

	aclresult = pg_tablespace_aclcheck(newTblspc, GetUserId(), ACL_CREATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_TABLESPACE,
					   get_tablespace_name(newTblspc));
}

/*
 * check_relation_alter
 *
 * It checks privileges to alter properties of the relation.
 *
 * relOid : OID of the relation to be altered
 */
void
check_relation_alter_owner(Oid relOid, Oid newOwner)
{
	AclResult	aclresult;
	Oid			relNsp;

	/* Must be owner of the relation */
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));

	/* Superusers can always do it */
	if (!superuser())
	{
		/* Must be able to become new owner */
		check_is_member_of_role(GetUserId(), newOwner);

		/* New owner must have CREATE privilege on namespace */
		relNsp = get_rel_namespace(relOid);
		aclresult = pg_namespace_aclcheck(relNsp, newOwner, ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(relNsp));
	}
}

/*
 * check_relation_drop
 *
 * It checks privileges to drop a certain relation
 *
 * relOid  : OID of the relation to be dropped
 * cascade : True, if it was called due to the cascaded deletion
 */
void
check_relation_drop(Oid relOid, bool cascade)
{
	Oid		relNsp = get_rel_namespace(relOid);

	/* Allow DROP to either table or schema owner */
	if (!cascade &&
		!pg_class_ownercheck(relOid, GetUserId()) &&
		!pg_namespace_ownercheck(relNsp, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * check_relation_getattr
 *
 * It checks privileges to reference properties of relation
 *
 * relOid : OID of the relation to be referenced
 */
void
chech_relation_getattr(Oid relOid)
{
	AclResult	aclresult;

	aclresult = pg_class_aclcheck(relOid, GetUserId(), ACL_SELECT);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * check_relation_grant
 *
 * It checks privileges to grant/revoke the default PG permissions on
 * a certain relation.
 * The caller (aclchk.c) handles the default PG privileges well,
 * so rest of enhanced security providers can apply its checks here.
 *
 * relOid : OID of the relation to be granted/revoked
 */
void
check_relation_grant(Oid relOid)
{
	/* do nothing */
}

/*
 * check_relation_comment
 *
 * It checks privileges to comment on a certain relation
 *
 * relOid : OID of the relation to be commented on
 */
void
check_relation_comment(Oid relOid)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * check_relation_inheritance
 *
 * It checks privileges to 
 *
 * parentOid : OID of the parent relation
 * childOid  : OID of the child relation
 */
void
check_relation_inheritance(Oid parentOid, Oid childOid)
{}

/*
 * check_relation_cluster
 *
 * It checks privileges to clusterize 
 *
 * relOid : OID of the relation to be clustered
 * abort  : True, if caller want to raise an error on violation
 */
bool
check_relation_cluster(Oid relOid, bool abort)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
	{
		if (abort)
			aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
						   get_rel_name(relOid));
		return false;
	}
	return true;
}

/*
 * check_relation_truncate
 *
 * It checks privileges to truncate contents of a certain relation.
 *
 * rel : The target Relation to be truncated
 */
void
check_relation_truncate(Relation rel)
{
	AclResult	aclresult;

	aclresult = pg_class_aclcheck(RelationGetRelid(rel),
								  GetUserId(), ACL_TRUNCATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_CLASS,
					   RelationGetRelationName(rel));
}

/*
 * check_relation_reference
 *
 * It checks privileges to set up FK constraint between two relations.
 *
 *
 *
 *
 */
void
check_relation_reference(Relation rel, int16 *attnums, int natts)
{}

/*
 * check_relation_lock
 *
 *
 *
 *
 */
void
check_relation_lock(Relation rel, LOCKMODE lockmode)
{
	Oid			relOid = RelationGetRelid(rel);
	AclResult	aclresult;
	AclMode		required;

	if (lockmode == AccessShareLock)
		required = ACL_SELECT;
	else
		required = (ACL_UPDATE | ACL_DELETE | ACL_TRUNCATE);

	aclresult = pg_class_aclcheck(relOid, GetUserId(), required);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_CLASS, get_rel_name(relOid));
}

/*
 * check_relation_vacuum
 *
 * It checks privileges to run vacuum process on a certain relation
 *
 * rel : Relation to 
 *
 *
 */
bool
check_relation_vacuum(Relation rel)
{
	if (pg_class_ownercheck(RelationGetRelid(rel), GetUserId()) ||
		(pg_database_ownercheck(MyDatabaseId, GetUserId()) &&
		 !rel->rd_rel->relisshared))
		return true;

	return false;
}

/*
 * check_relation_reindex
 *
 * It checks privileges to rebuild all the indexes defined on a certain
 * table using REINDEX statement.
 * Note that it is not called on REINDEX DATABASE or INDEX
 *
 * relOid : OID of the index to be rebuilt
 */
void
check_relation_reindex(Oid relOid)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * check_view_replace
 *
 *
 *
 *
 *
 *
 */
void
check_view_replace(Oid viewOid)
{
	Assert(get_rel_relkind(viewOid) == RELKIND_VIEW);

	if (!pg_class_ownercheck(viewOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(viewOid));
}

/*
 * check_index_create
 *
 * It checks privilege to create a new index.
 * Note that check_relation_alter() on the relation to be indexed is already
 * called to check privilege to alter properties of the relation.
 * The security provider can check any other permissions to create a new
 * index, if necessary.
 *
 * indName : Name of the new index
 * indNsp : OID of the namespace of the relation to be indexed, if needed.
 *          Otherwise, InvalidOid shall be delivered. It should not happen
 *          expect for ALTER TABLE is internally deleting/recreating an index.
 * indTblspc : OID of the tablespace of the index, if exist.
 */
void
check_index_create(const char *indName, Oid indNsp, Oid indTblspc)
{
	AclResult	aclresult;

	/*
	 * Verify we (still) have CREATE rights in the rel's namespace.
	 * (Presumably we did when the rel was created, but maybe not anymore.)
	 * Skip check if caller doesn't want it.  Also skip check if
	 * bootstrapping, since permissions machinery may not be working yet.
	 */
	if (OidIsValid(indNsp) && !IsBootstrapProcessingMode())
	{
		aclresult = pg_namespace_aclcheck(indNsp, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(indNsp));
	}

	/* Check permissions except when using database's default */
	if (OidIsValid(indTblspc) && indTblspc != MyDatabaseTableSpace)
	{
		aclresult = pg_tablespace_aclcheck(indTblspc, GetUserId(), ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_TABLESPACE,
						   get_tablespace_name(indTblspc));
	}
}

/*
 * check_index_reindex
 *
 * It checks privileges to rebuild a certain index.
 * Note that it is not called on REINDEX DATABASE or TABLE.
 * 
 * indOid : OID of the index to be rebuilt
 */
void
check_index_reindex(Oid indOid)
{
	Assert(get_rel_relkind(indOid) == RELKIND_INDEX);

	if (!pg_class_ownercheck(indOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(indOid));
}

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

	if (pg_class_aclcheck(seqOid, GetUserId(), ACL_SELECT) != ACLCHECK_OK &&
		pg_class_aclcheck(seqOid, GetUserId(), ACL_USAGE) != ACLCHECK_OK)
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
