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
 * It enables security providers to check permission to access the specified
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
 * check_relation_create
 *
 * It checks privilege to create a new relation.
 * If violated, it shall raise an error.
 *
 * Note that this hook is not invoked in the below cases:
 * - Boot_CreateStmt handling in bootparse.y
 * - create_toast_table()
 * - make_new_heap()
 *
 * relName : Name of the new relation
 * relkind : Relkind of the new relation
 * tupDesc : tupDesc of the new relation
 * relNsp  : OID of the namespace to create in
 * relTblspc : OID of the tablespace, if exist
 * colList : List of ColumnDef, if exist
 * createAs : True, if CREATE TABLE AS/SELECT INTO
 */
void
check_relation_create(const char *relName, char relkind, TupleDesc tupDesc,
					  Oid relNsp, Oid relTblspc, List *colList, bool createAs)
{
	AclResult	aclresult;

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
 * It checks privileges to alter properties of the specified relation,
 * except for its name, schema, ownership and default tablespace.
 * If violated, it shall raise an error.
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
 * It checks privileges to alter name of the specified relation.
 * If viiolated, it shall raise an error.
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
 * It checks privileges to alter schema of the specified relation.
 * If violated, it shall raise an error.
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
 * It checks privileges to alter default tablespace of the specified
 * relation.
 * If violated, it shall raise an error.
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
 * It checks privileges to alter ownership of the specified relation.
 * If violated, it shall raise an error.
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
 * It checks privileges to drop the specified relation.
 * If violated, it shall raise an error.
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
 * It checks privileges to reference properties of the specified relation.
 * If violated, it shall raise an error.
 *
 * relOid : OID of the relation to be referenced
 */
void
check_relation_getattr(Oid relOid)
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
 * It checks privileges to grant/revoke the default PG permissions
 * on the specified relation.
 * The caller (aclchk.c) handles the default PG privileges well,
 * so rest of enhanced security providers can apply its checks here.
 * If violated, it shall raise an error.
 *
 * relOid : OID of the relation to be granted/revoked
 */
void
check_relation_grant(Oid relOid)
{
	/* right now, no enhanced security providers */
}

/*
 * check_relation_comment
 *
 * It checks privileges to comment on the specified relation.
 * If violated, it shall raise an error.
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
 * It checks privileges to set up inheritance tree between two
 * relations.
 * If violated, it shall raise an error.
 *
 * parentOid : OID of the parent relation
 * childOid : OID of the child relation, or InvalidOid when CREATE TABLE
 */
void
check_relation_inherit(Oid parentOid, Oid childOid)
{
	/*
	 * We should have an UNDER permission flag for this, but for now,
	 * demand that creator of a child table own the parent.
	 */
	if (!pg_class_ownercheck(parentOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(parentOid));
}

/*
 * check_relation_cluster
 *
 * It checks privileges to clusterize the specified relation.
 * If violated, it shall raise an error, or return false when `abort'
 * is not true.
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
 * It checks privileges to truncate all the contents of the specified
 * relation.
 * If violated, it raises an error.
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
 * It checks privileges to set up foreign key constraints on the specified
 * relation and columns.
 * If violated, it raises an error.
 *
 * rel : The FK/PK Relation to be referenced
 * attnums : An array of attribute numbers to be constrained
 * natts : Length of the attnums array
 */
void
check_relation_reference(Relation rel, int16 *attnums, int natts)
{
	Oid			roleId = GetUserId();
	Oid			relOid = RelationGetRelid(rel);
	AclResult	aclresult;
	int			i;

	/* Okay if we have relation-level REFERENCES permission */
	aclresult = pg_class_aclcheck(relOid, roleId, ACL_REFERENCES);
	if (aclresult != ACLCHECK_OK)
	{
		/* Else we must have REFERENCES on each column */
		for (i=0; i < natts; i++)
		{
			aclresult = pg_attribute_aclcheck(relOid, attnums[i], roleId,
											  ACL_REFERENCES);
			if (aclresult != ACLCHECK_OK)
				aclcheck_error(aclresult, ACL_KIND_CLASS,
							   RelationGetRelationName(rel));
		}
	}
}

/*
 * check_relation_lock
 *
 * It checks privileges to lock the specified relation explicitly.
 * If violated, it shall raise an error.
 *
 * rel : The target Relation to be locked
 * lockmode : The required lockmode
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
 * It checks privileges to run vacuum process on the specified relation.
 * If violated, it shall return `false'.
 *
 * rel : Relation to be vacuumed
 */
bool
check_relation_vacuum(Relation rel)
{
	bool	shared = rel->rd_rel->relisshared;

	/*
	 * We allow the user to vacuum a table if he is superuser, the table
	 * owner, or the database owner (but in the latter case, only if it's not
	 * a shared relation).	pg_class_ownercheck includes the superuser case.
	 */
	if (!(pg_class_ownercheck(RelationGetRelid(rel), GetUserId()) ||
		  (pg_database_ownercheck(MyDatabaseId, GetUserId()) && !shared)))
		return false;

	return true;
}

/*
 * check_relation_reindex
 *
 * It checks privileges to rebuild all the indexes defined on the specified
 * table using REINDEX statement.
 * Note that this hook is not called on REINDEX DATABASE or INDEX
 * If violated, it shall raise an error.
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
 * It checks privilege to replace definitions of the specified VIEW.
 * If violated, it shall raise an error.
 *
 * viewOid : OID of the view to be replaced
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
 * If violated, it shall raise an error.
 *
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
 * If violated, it shall raise an error.
 *
 * Note that this hook is not called on REINDEX DATABASE or TABLE.
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
 * It checks privileges to reference the specified sequence object,
 * using currval() or lastval().
 * If violated, it shall raise an error.
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
 * It checks privileges to reference the specified sequence object,
 * using nextval().
 * If violated, it shall raise an error.
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
 * It checks privileges to assign a discretionary value on the specified
 * sequence object, using setval().
 * If violated, it shall raise an error.
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
