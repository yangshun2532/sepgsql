/*
 * src/include/security/common.h
 *   Common abstraction layer of access controls
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#ifndef SECURITY_COMMON_H
#define SECURITY_COMMON_H

#include "access/htup.h"
#include "nodes/bitmapset.h"
#include "nodes/parsenodes.h"
#include "storage/lock.h"
#include "utils/acl.h"
#include "utils/rel.h"

/* regular query permissions */
extern bool
ac_relation_perms(Oid relOid, Oid roleId,
				  AclMode requiredPerms,
				  Bitmapset *selectedCols,
				  Bitmapset *modifiedCols,
				  bool abort);
/* pg_dataabse */
extern void
ac_database_create(const char *datName,
				   Oid srcDatOid, bool srcIsTemp,
				   Oid datOwner, Oid datTblspc);
extern void
ac_database_alter(Oid datOid, const char *newName,
				  Oid newTblspc, Oid newOwner);
extern void
ac_database_drop(Oid datOid, bool cascade);

extern void
ac_database_grant(Oid datOid, Oid grantor, AclMode goptions);
extern void
ac_database_connect(Oid datOid);

extern void
ac_database_calculate_size(Oid datOid);

extern void
ac_database_reindex(Oid datOid);

extern void
ac_database_comment(Oid datOid);

/* pg_namespace */
extern void
ac_namespace_create(const char *nspName, Oid nspOwner, bool isTemp);

extern void
ac_namespace_alter(Oid nspOid, const char *newName, Oid newOwner);

extern void
ac_namespace_drop(Oid nspOid, bool cascade);

extern void
ac_namespace_grant(Oid nspOid, Oid grantor, AclMode goptions);

extern bool
ac_namespace_search(Oid nspOid, bool abort);

extern void
ac_namespace_comment(Oid nspOid);

/* pg_tablespace */
extern void
ac_tablespace_create(const char *tblspcName);

extern void
ac_tablespace_alter(Oid tblspcOid, const char *newName, Oid newOwner);

extern void
ac_tablespace_drop(Oid tblspcOid, bool cascade);

extern void
ac_tablespace_grant(Oid tblspcOid, Oid grantor, AclMode goptions);

extern void
ac_tablespace_calculate_size(Oid tblspcOid);

extern bool
ac_tablespace_for_temporary(Oid tblspcOid, bool abort);

extern void
ac_tablespace_comment(Oid tblspcOid);

/* pg_class */
extern void
ac_class_create(const char *relname, char relkind, TupleDesc tupDesc,
				Oid relNspOid, Oid relTblspc, CreateStmt *stmt);
extern void
ac_class_alter(Oid relOid, const char *newName,
			   Oid newNspOid, Oid newTblSpc, Oid newOwner);
extern void
ac_class_drop(Oid relOid, bool cascade);

extern void
ac_class_grant(Oid relOid, Oid grantor, AclMode goptions);

extern void
ac_class_comment(Oid relOid);

extern void
ac_class_get_transaction_id(Oid relOid);

extern void
ac_relation_copy_definition(Oid relOidSrc);

extern void
ac_relation_inheritance(Oid parentOid, Oid childOid);

extern bool
ac_relation_cluster(Oid relOid, bool abort);

extern void
ac_relation_truncate(Relation rel);

extern void
ac_relation_references(Relation rel, int16 *attnums, int natts);

extern void
ac_relation_lock(Oid relOid, LOCKMODE lockmode);

extern bool
ac_relation_vacuum(Relation rel);

extern void
ac_relation_indexon(Oid relOid);

extern void
ac_relation_reindex(Oid relOid);

extern void
ac_view_replace(Oid viewOid);

extern void
ac_index_create(const char *indName, bool check_rights,
				Oid indNspOid, Oid indTblSpc);
extern void
ac_index_reindex(Oid indOid);

extern void
ac_sequence_get_value(Oid seqOid);

extern void
ac_sequence_next_value(Oid seqOid);

extern void
ac_sequence_set_value(Oid seqOid);

/* pg_attribute */
extern void
ac_attribute_create(Oid relOid, ColumnDef *cdef);

extern void
ac_attribute_alter(Oid relOid, const char *attname);

extern void
ac_attribute_drop(Oid relOid, const char *attname);

extern void
ac_attribute_grant(Oid relOid, AttrNumber attnum, Oid grantor, AclMode goptions);

extern void
ac_attribute_comment(Oid relOid, const char *attname);

/* pg_proc and pg_aggregate */
extern void
ac_proc_create(const char *proName, Oid namespc, Oid pllang);

extern void
ac_aggregate_create(const char *aggName, Oid namespc,
					Oid transfn, Oid finalfn);
extern void
ac_proc_replace(Oid proOid, Oid proNspOid, Oid proLangOid);

extern void
ac_proc_alter(Oid proOid, const char *newName, Oid newNspOid, Oid newOwner);

extern void
ac_proc_drop(Oid proOid, bool cascade);

extern void
ac_proc_grant(Oid proOid, Oid grantor, AclMode goptions);

extern void
ac_proc_comment(Oid proOid);

extern void
ac_proc_execute(Oid proOid, Oid roleOid);

extern bool
ac_proc_hint_inline(Oid proOid);

/* pg_language */
extern void
ac_language_create(const char *langName, bool IsTemplate,
                   bool plTrusted, bool plDbaCreate,
                   Oid handlerOid, Oid validatorOid);

extern void
ac_language_alter(Oid langOid, const char *newName, Oid newOwner);

extern void
ac_language_drop(Oid langOid, bool cascade);

extern void
ac_language_grant(Oid langOid, Oid grantor, AclMode goptions);

extern void
ac_language_comment(Oid langOid);

/* pg_trigger */
extern void
ac_trigger_create(Oid relOid, Oid conRelOid, Oid funcOid);

extern void
ac_trigger_alter(Oid relOid, HeapTuple trigTup, const char *newName);

extern void
ac_trigger_drop(Oid relOid, HeapTuple trigTup, bool cascade);

extern void
ac_trigger_comment(Oid relOid, HeapTuple trigTup);

/* pg_foreign_data_wrapper */
extern void
ac_foreign_data_wrapper_create(const char *fdwName, Oid fdwValidator);

extern void
ac_foreign_data_wrapper_alter(Oid fdwOid, Oid newValidator, Oid newOwner);

extern void
ac_foreign_data_wrapper_drop(Oid fdwOid, bool cascade);

extern void
ac_foreign_data_wrapper_grant(Oid fdwOid, Oid grantor, AclMode goptions);

/* pg_foreign_server */
extern void
ac_foreign_server_create(const char *fsrvName, Oid fsrvOwner, Oid fdwOid);

extern void
ac_foreign_server_alter(Oid fsrvOid, Oid newOwner);

extern void
ac_foreign_server_drop(Oid fsrvOid, bool cascade);

extern void
ac_foreign_server_grant(Oid fsrvOid, Oid grantor, AclMode goptions);

/* pg_user_mapping */
extern void
ac_user_mapping_create(Oid umuserId, Oid fsrvOid);

extern void
ac_user_mapping_alter(Oid umuserId, Oid fsrvOid);

extern void
ac_user_mapping_drop(Oid umuserId, Oid fsrvOid, bool cascade);

/* pg_type */
extern void
ac_type_create(const char *typName, Oid typNsp, Oid typOwner,
			   Oid typReplOid, char typType, bool typIsArray,
			   Oid inputOid, Oid outputOid, Oid recvOid, Oid sendOid,
			   Oid modinOid, Oid modoutOid, Oid analyzeOid);

extern void
ac_type_alter(Oid typOid, const char *newName,
			  Oid newNspOid, Oid newOwner);

extern void
ac_type_drop(Oid typOid, bool cascade);

extern void
ac_type_comment(Oid typOid);

/* pg_cast */
extern void
ac_cast_create(Oid sourceTypOid, Oid targetTypOid,
			   char castmethod, Oid funcOid);
extern void
ac_cast_drop(Oid sourceTypOid, Oid targetTypOid, bool cascade);

extern void
ac_cast_comment(Oid sourceTypOid, Oid targetTypOid);

/* pg_conversion */
extern void
ac_conversion_create(const char *convName, Oid nspOid, Oid funcOid);

extern void
ac_conversion_alter(Oid convOid, const char *newName, Oid newOwner);

extern void
ac_conversion_drop(Oid convOid, bool cascade);

extern void
ac_conversion_comment(Oid convOid);

/* pg_operator */
extern void
ac_operator_create(const char *oprName, Oid nspOid,
				   Oid commutatorOp, Oid negatorOp,
				   Oid codeFn, Oid restFn, Oid joinFn);
extern void
ac_operator_replace(Oid operOid, Oid nspOid,
					Oid commutatorOp, Oid negatorOp,
					Oid codeFn, Oid restFn, Oid joinFn);
extern void
ac_operator_alter(Oid operOid, Oid newOwner);

extern void
ac_operator_drop(Oid operOid, bool cascade);

extern void
ac_operator_comment(Oid operOid);

#endif
