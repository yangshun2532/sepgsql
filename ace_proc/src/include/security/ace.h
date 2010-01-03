/*
 * ace.h
 *
 * Header file for the ACE framework
 *
 * Portions Copyright (c) 1996-2010, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#ifndef SECURITY_ACE_H
#define SECURITY_ACE_H

#include "nodes/parsenodes.h"
#include "storage/lock.h"
#include "utils/acl.h"
#include "utils/rel.h"

/*
 * ace_misc.c - miscellaneous security hook routines
 */
extern void
check_provider_initialize(void);

/*
 * ace_database.c - hooks related to databases
 */
extern void
check_database_create(const char *datName, Oid srcDatOid,
					  Oid datOwner, Oid datTblspc);
extern void
check_database_alter(Oid datOid);
extern void
check_database_alter_rename(Oid datOid, const char *newName);
extern void
check_database_alter_owner(Oid datOid, Oid newOwner);
extern void
check_database_alter_tablespace(Oid datOid, Oid newTblspc);
extern void
check_database_drop(Oid datOid, bool cascade);
extern void
check_database_getattr(Oid datOid);
extern void
check_database_grant(Oid datOid);
extern void
check_database_comment(Oid datOid);
extern void
check_database_connect(Oid datOid);
extern void
check_database_reindex(Oid datOid);

/*
 * ace_schema.c - hooks related to schema
 */
extern void
check_schema_create(const char *nspName, Oid nspOwner, bool isTemp);
extern void
check_schema_alter_rename(Oid nspOid, const char *newName);
extern void
check_schema_alter_owner(Oid nspOid, Oid newOwner);
extern void
check_schema_drop(Oid nspOid, bool cascade);
extern void
check_schema_grant(Oid nspOid);
extern bool
check_schema_search(Oid nspOid, bool abort);
extern void
check_schema_comment(Oid nspOid);

/*
 * ace_relation.c - hooks related to relation
 */
extern bool
check_relation_perms(Oid relOid, Oid roleId, AclMode requiredPerms,
					 Bitmapset *selCols, Bitmapset *modCols, bool abort);
extern void
check_relation_create(const char *relName, char relkind,
					  TupleDesc tupDesc, Oid relNsp, Oid relTblspc,
					  List *colList, bool isTemp, bool createAs);
extern void
check_relation_alter(Oid relOid);
extern void
check_relation_alter_rename(Oid relOid, const char *newName);
extern void
check_relation_alter_schema(Oid relOid, Oid newNsp);
extern void
check_relation_alter_tablespace(Oid relOid, Oid newTblspc);
extern void
check_relation_alter_owner(Oid relOid, Oid newOwner);
extern void
check_relation_drop(Oid relOid, bool cascade);
extern void
check_relation_getattr(Oid relOid);
extern void
check_relation_grant(Oid relOid);
extern void
check_relation_comment(Oid relOid);
extern void
check_relation_inherit(Oid parentOid, Oid childOid);
extern bool
check_relation_cluster(Oid relOid, bool abort);
extern void
check_relation_truncate(Relation rel);
extern void
check_relation_reference(Relation rel, int16 *attnums, int natts);
extern void
check_relation_lock(Relation rel, LOCKMODE lockmode);
extern bool
check_relation_vacuum(Relation rel);
extern void
check_relation_reindex(Oid relOid);
extern void
check_view_replace(Oid relOid);
extern void
check_index_create(const char *indName, Oid indNsp, Oid indTblspc);
extern void
check_index_reindex(Oid indOid);
extern void
check_sequence_get_value(Oid seqOid);
extern void
check_sequence_next_value(Oid seqOid);
extern void
check_sequence_set_value(Oid seqOid);

/*
 * ace_attribute.c - hooks related to attribute
 */
extern void
check_attribute_create(Oid relOid, ColumnDef *cdef);
extern void
check_attribute_alter(Oid relOid, const char *colName);
extern void
check_attribute_drop(Oid relOid, const char *colName, bool cascade);
extern void
check_attribute_grant(Oid relOid, AttrNumber attnum);
extern void
check_attribute_comment(Oid relOid, const char *colName);

#endif	/* SECURITY_ACE_H */
