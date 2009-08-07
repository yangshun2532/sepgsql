/*
 * src/backend/security/common/ac_class.c
 *   common access control abstration corresponding to class objects
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "catalog/pg_class.h"
#include "commands/dbcommands.h"
#include "commands/tablespace.h"
#include "miscadmin.h"
#include "security/common.h"

#include "utils/lsyscache.h"

/*
 * ac_class_create
 *
 * It checks privilege to create a new relation (except for indexes;
 * use ac_index_create() instead).
 *
 * Note that (currently) this checks is not invoked from bootparse.y
 * (Boot_CreateStmt), create_toast_table() and make_new_heap(),
 * because it is unnecessary to check anything here. But SE-PgSQL
 * requires to return its default security context.
 *
 * [Params]
 *   relName   : Name of the new relation
 *   relkind   : relkind of the new relation
 *   tupDesc   : tupDesc of the new relation
 *   relNspOid : OID of the namespace of the relation
 *   relTblspc : OID of the tablespace of the relation, if exist
 *   stmt      : CreateStmt as a hint, if exist
 */
void
ac_class_create(const char *relName, char relkind, TupleDesc tupDesc,
				Oid relNspOid, Oid relTblspc, CreateStmt *stmt)
{
	AclResult	aclresult;

	/* For indexes, use ac_index_create() instead */
	Assert(relkind != RELKIND_INDEX);

	if (!IsBootstrapProcessingMode())
	{
		/* Check permissions to create a relation on the namespace */
		aclresult = pg_namespace_aclcheck(relNspOid, GetUserId(),
										  ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(relNspOid));
	}

	/* Check permissions except when using database's default */
	if (OidIsValid(relTblspc) && relTblspc != MyDatabaseTableSpace)
	{
		aclresult = pg_tablespace_aclcheck(relTblspc, GetUserId(),
										   ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_TABLESPACE,
						   get_tablespace_name(relTblspc));
	}
}

/*
 * ac_class_alter
 *
 * It checks privilege to alter a certain relation
 *
 * [Params]
 *   relOid    : OID of the relation to be altered
 *   newName   : New name of the relation, if given
 *   newNspOid : OID of the new namespace, if given
 *   newTblSpc : OID of the new tablespace, if given
 *   newOwner  : OID of the new relation owner, if given
 */
void
ac_class_alter(Oid relOid, const char *newName,
			   Oid newNspOid, Oid newTblSpc, Oid newOwner)
{
	AclResult	aclresult;
	Oid			namespaceId;

	/* Must be owner for all the ALTER TABLE options */
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));

	if (newName)
	{
		namespaceId = get_rel_namespace(relOid);
		aclresult = pg_namespace_aclcheck(namespaceId, GetUserId(),
										  ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(namespaceId));
	}

	if (OidIsValid(newNspOid))
	{
		aclresult = pg_namespace_aclcheck(newNspOid, GetUserId(),
										  ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(newNspOid));
	}

	if (OidIsValid(newTblSpc))
	{
		aclresult = pg_tablespace_aclcheck(newTblSpc, GetUserId(),
										   ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_TABLESPACE,
						   get_tablespace_name(newTblSpc));
	}

	if (OidIsValid(newOwner))
	{
		/* Must be able to become new owner */
		check_is_member_of_role(GetUserId(), newOwner);

		/* New owner must have CREATE privilege on namespace */
		namespaceId = get_rel_namespace(relOid);
		aclresult = pg_namespace_aclcheck(namespaceId, newOwner,
										  ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(namespaceId));
	}
}

/*
 * ac_class_drop
 *
 * It checks privilege to drop a certain relation.
 * Note that the security feature also needs to check permissions to
 * drop columns within the relation to be removed here, if necessary.
 *
 * [Params]
 *   relOid  : OID of the relation to be dropped
 *   cascade : True, if cascaded deletion
 */
void
ac_class_drop(Oid relOid, bool cascade)
{
	Oid		relNspOid = get_rel_namespace(relOid);

	/* Allow DROP to either table owner or schema owner */
	if (!cascade &&
		!pg_class_ownercheck(relOid, GetUserId()) &&
		!pg_namespace_ownercheck(relNspOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * ac_class_grant
 *
 * It checks privileges to grant/revoke permissions on a certain relation
 *
 * [Params]
 *   relOid   : OID of the target relation for GRANT/REVOKE
 *   isGrant  : True, if the statement is GRANT
 *   privs    : AclMask being tries to be granted/revoked
 *   grantor  : OID of the gractor role
 *   goptions : Available AclMask available to grant others
 */
void
ac_class_grant(Oid relOid, bool isGrant, AclMode privs,
			   Oid grantor, AclMode goptions)
{
	if (goptions == ACL_NO_RIGHTS)
	{
		char		relkind = get_rel_relkind(relOid);
		AclMode		whole_mask;

		whole_mask = (relkind == RELKIND_SEQUENCE
					  ? ACL_ALL_RIGHTS_SEQUENCE : ACL_ALL_RIGHTS_RELATION);
		if (pg_class_aclmask(relOid, grantor,
							 whole_mask | ACL_GRANT_OPTION_FOR(whole_mask),
							 ACLMASK_ANY) == ACL_NO_RIGHTS)
			aclcheck_error(ACLCHECK_NO_PRIV,
						   (relkind == RELKIND_SEQUENCE
							? ACL_KIND_SEQUENCE : ACL_KIND_CLASS),
						   get_rel_name(relOid));
	}
}

/*
 * ac_class_comment
 *
 * It checks privilges to comment on the relation
 *
 * [Params]
 *   relOid : OID of the relation to be commented
 */
void
ac_class_comment(Oid relOid)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * ac_relation_copy_definition
 *
 * It checks privileges to define a new column which is copied from
 * another relation, using LIKE clause in CREATE TABLE
 *
 * [Params]
 *   relOidSrc : OID of the relation to be copied its column's definition
 */
void
ac_relation_copy_definition(Oid relOidSrc)
{
	AclResult	aclresult;

	aclresult = pg_class_aclcheck(relOidSrc, GetUserId(), ACL_SELECT);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_CLASS, get_rel_name(relOidSrc));
}

/*
 * ac_relation_inheritance
 *
 * It checks privilege to set up an inheritance relationship between
 * a couple of two relations. 
 *
 * [Params]
 *   parentOid : OID of the parant relation
 *   childOid  : OID of the child relation
 *               It is available onlt when ALTER TABLE INHERIT case.
 */
void
ac_relation_inheritance(Oid parentOid, Oid childOid)
{
	Assert(get_rel_relkind(parentOid) == RELKIND_RELATION);

	/*
	 * We should have an UNDER permission flag for this, but for now,
	 * demand that creator of a child table own the parent.
	 */
	if (!pg_class_ownercheck(parentOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(parentOid));

	/*
	 * MEMO: CREATE TABLE (...) INHERITS(xxx); does not prevent to
	 * create a child table with system catalog, but ALTER TABLE
	 * INHERIT xxx prents this. Which is correct?
	 */
}

/*
 * ac_relation_cluster
 *
 * It checks privilege to cluster certain tables using CLUSTER
 * statement.
 *
 * [Params]
 *   relOid : OID of the target relation
 *   abort  : True, if caller want to raise an error on violation
 */
bool
ac_relation_cluster(Oid relOid, bool abort)
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
 * ac_relation_truncate
 *
 * It checks privilege to truncate certain tables using TRUNCATE
 * statement.
 *
 * [Params]
 *   rel : The Relation to be truncated.
 */
void
ac_relation_truncate(Relation rel)
{
	AclResult	aclresult;

	Assert(RelationGetForm(rel)->relkind == RELKIND_RELATION);

	aclresult = pg_class_aclcheck(RelationGetRelid(rel), GetUserId(),
								  ACL_TRUNCATE);
	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_CLASS,
					   RelationGetRelationName(rel));
}

/*
 * ac_relation_references
 *
 * It checks privilege to set up a FK constraint.
 * Note that this check is called twice for both of PK and FK tables.
 *
 * [Params]
 *   rel     : The Relation to be constrained
 *   attnums : An array of constrained attributes numbers
 *   natts   : length of the attnums array
 */
void
ac_relation_references(Relation rel, int16 *attnums, int natts)
{
	AclResult	aclresult;
	int			i;

	Assert(RelationGetForm(rel)->relkind == RELKIND_RELATION);

	/* Okay if we have relation-level REFERENCES permission */
	aclresult = pg_class_aclcheck(RelationGetRelid(rel), GetUserId(),
								  ACL_REFERENCES);
	/* Else we must have REFERENCES on each column */
	if (aclresult != ACLCHECK_OK)
	{
		for (i = 0; i < natts; i++)
		{
			aclresult = pg_attribute_aclcheck(RelationGetRelid(rel),
											  attnums[i], GetUserId(),
											  ACL_REFERENCES);
			if (aclresult != ACLCHECK_OK)
				aclcheck_error(aclresult, ACL_KIND_CLASS,
							   RelationGetRelationName(rel));
		}
	}
}

/*
 * ac_relation_lock
 *
 * It checks privilege to lock a certain relation using LOCK statement
 *
 * [Params]
 *   relOid   : OID of the target relation
 *   lockmode : The lock mode to be acquired
 */
void
ac_relation_lock(Oid relOid, LOCKMODE lockmode)
{
	AclResult	aclresult;

	Assert(get_rel_relkind(relOid) == RELKIND_RELATION);

	if (lockmode == AccessShareLock)
		aclresult = pg_class_aclcheck(relOid, GetUserId(),
									  ACL_SELECT);
	else
		aclresult = pg_class_aclcheck(relOid, GetUserId(),
						ACL_UPDATE | ACL_DELETE | ACL_TRUNCATE);

	if (aclresult != ACLCHECK_OK)
		aclcheck_error(aclresult, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * ac_relation_vacuum
 *
 * It checks privilege to vacuum a certain relation
 *
 * [Params]
 *   rel : The Relation to be vacuumed
 */
bool
ac_relation_vacuum(Relation rel)
{
	Assert(RelationGetForm(rel)->relkind == RELKIND_RELATION ||
		   RelationGetForm(rel)->relkind == RELKIND_TOASTVALUE);

	if (pg_class_ownercheck(RelationGetRelid(rel), GetUserId()) ||
		(pg_database_ownercheck(MyDatabaseId, GetUserId()) &&
		 !rel->rd_rel->relisshared))
		return true;

	return false;
}

/*
 * ac_relation_indexon
 *
 * It checks privilege to create a new index on a certain table.
 *
 * [Params]
 *   relOid : OID of the relation to be rebuilt
 */
void
ac_relation_indexon(Oid relOid)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * ac_relation_reindex
 *
 * It checks privilege to rebuild all the indexes defined on a certain
 * table using REINDEX statement.
 * Note that ac_index_reindex() is not called when this check is uses.
 * In other word, this check implicitly contains checks for each indexes.
 *
 * [Params]
 *   relOid : OID of the index to be rebuilt
 */
void
ac_relation_reindex(Oid relOid)
{
	if (!pg_class_ownercheck(relOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(relOid));
}

/*
 * ac_view_replace
 *
 * It checks privilege to replace an existing view using CREATE OR REPLACE VIEW.
 * Note that ac_class_create() is called when we actually define a new view.
 *
 * [Params]
 *   viewOid : OID of the target view.
 */
void
ac_view_replace(Oid viewOid)
{
	if (!pg_class_ownercheck(viewOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(viewOid));
}

/*
 * ac_index_create
 *
 * It checks privilege to create a new index.
 * Note that ac_relation_indexon() is also called on CREATE INDEX statement.
 * Note that create_toast_table() does not call the check.
 *
 * [Params]
 *   indName      : Name of the new index
 *   check_rights : True, if caller wait permission checks on namespace
 *   indNspOid    : OID of the namespace to be assigned
 *   indTblSpc    : OID of the tablespace, if given
 */
void
ac_index_create(const char *indName, bool check_rights,
				Oid indNspOid, Oid indTblSpc)
{
	AclResult	aclresult;

	if (check_rights)
	{
		aclresult = pg_namespace_aclcheck(indNspOid, GetUserId(),
										  ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_NAMESPACE,
						   get_namespace_name(indNspOid));
	}

	if (OidIsValid(indTblSpc) && indTblSpc != MyDatabaseTableSpace)
	{
		aclresult = pg_tablespace_aclcheck(indTblSpc, GetUserId(),
										   ACL_CREATE);
		if (aclresult != ACLCHECK_OK)
			aclcheck_error(aclresult, ACL_KIND_TABLESPACE,
						   get_tablespace_name(indTblSpc));
	}
}

/*
 * ac_index_reindex
 *
 * It checks privilege to rebuild a certain index using REINDEX statement.
 * Note that ac_database_reindex() and ac_relation_reindex() can be checked
 * depending on the statement option.
 *
 * [Params]
 *   indOid : OID of the target index
 */
void
ac_index_reindex(Oid indOid)
{
	Assert(get_rel_relkind(indOid) == RELKIND_INDEX);

	if (!pg_class_ownercheck(indOid, GetUserId()))
		aclcheck_error(ACLCHECK_NOT_OWNER, ACL_KIND_CLASS,
					   get_rel_name(indOid));
}

/*
 * ac_sequence_get_value
 *
 * It checks privilege to refer a certain sequence object without any
 * modifications. In other words, getval() and lastval() invoke this
 * check.
 *
 * [Params]
 *   seqOid : OID of the sequence to be referenced
 */
void
ac_sequence_get_value(Oid seqOid)
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
 * ac_sequence_next_value
 *
 * It checks privilege to increment and fetch a value from a certain sequence
 * object. In other words, nextval() invokes this check.
 *
 * [Params]
 *   seqOid : OID of the sequence to be fetched
 */
void
ac_sequence_next_value(Oid seqOid)
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
 * ac_sequence_set_value
 *
 * It checks privilege to set a discretionary value on a certain sequence
 * object. In other words, setval() invokes this check.
 *
 * [Params]
 *   seqOid : OID of the sequence to be rewritten
 */
void
ac_sequence_set_value(Oid seqOid)
{
	Assert(get_rel_relkind(seqOid) == RELKIND_SEQUENCE);

	if (pg_class_aclcheck(seqOid, GetUserId(), ACL_UPDATE) != ACLCHECK_OK)
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied for sequence %s",
						get_rel_name(seqOid))));
}
