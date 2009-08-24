/*
 * src/include/utils/security.h
 *
 *   Headers for common access control facilities
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#ifndef UTILS_SECURITY_H
#define UTILS_SECURITY_H

#include "access/attnum.h"
#include "catalog/dependency.h"
#include "nodes/bitmapset.h"
#include "nodes/parsenodes.h"
#include "storage/lock.h"
#include "utils/acl.h"
#include "utils/relcache.h"

/* pg_attribute */
extern void
ac_attribute_create(Oid relOid, ColumnDef *cdef);
extern void
ac_attribute_alter(Oid relOid, const char *colName);
extern void
ac_attribute_drop(Oid relOid, const char *colName, bool dacSkip);
extern void
ac_attribute_grant(Oid relOid, AttrNumber attnum,
				   Oid grantor, AclMode goptions);
extern void
ac_attribute_comment(Oid relOid, const char *colName);

/* pg_cast */
extern void
ac_cast_create(Oid sourceTypOid, Oid targetTypOid,
               char castmethod, Oid funcOid);
extern void
ac_cast_drop(Oid sourceTypOid, Oid targetTypOid, bool dacSkip);
extern void
ac_cast_comment(Oid sourceTypOid, Oid targetTypOid);

/* pg_class */
extern bool
ac_relation_perms(Oid relOid, Oid roleId, AclMode requiredPerms,
				  Bitmapset *selCols, Bitmapset *modCols, bool abort);
extern void
ac_relation_create(const char *relName, char relkind, TupleDesc tupDesc,
				   Oid relNsp, Oid relTblspc, List *colList);
extern void
ac_relation_alter(Oid relOid, const char *newName,
				  Oid newNspOid, Oid newTblSpc, Oid newOwner);
extern void
ac_relation_drop(Oid relOid, bool dacSkip);
extern void
ac_relation_grant(Oid relOid, Oid grantor, AclMode goptions);
extern void
ac_relation_comment(Oid relOid);
extern void
ac_relation_get_transaction_id(Oid relOid);
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

/* pg_constraint */
extern void
ac_constraint_comment(Oid conOid);

/* pg_conversion */
extern void
ac_conversion_create(const char *convName, Oid nspOid, Oid funcOid);
extern void
ac_conversion_alter(Oid convOid, const char *newName, Oid newOwner);
extern void
ac_conversion_drop(Oid convOid, bool dacSkip);
extern void
ac_conversion_comment(Oid convOid);

/* pg_database */
extern void
ac_database_create(const char *datName,
				   Oid srcDatOid, bool srcIsTemp,
				   Oid datOwner, Oid datTblspc);
extern void
ac_database_alter(Oid datOid, const char *newName,
				  Oid newTblspc, Oid newOwner);
extern void
ac_database_drop(Oid datOid, bool dacSkip);
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

/* pg_foreign_data_wrapper */
extern void
ac_foreign_data_wrapper_create(const char *fdwName, Oid fdwValidator);
extern void
ac_foreign_data_wrapper_alter(Oid fdwOid, Oid newValidator, Oid newOwner);
extern void
ac_foreign_data_wrapper_drop(Oid fdwOid, bool dacSkip);
extern void
ac_foreign_data_wrapper_grant(Oid fdwOid, Oid grantor, AclMode goptions);

/* pg_foreign_server */
extern void
ac_foreign_server_create(const char *fsrvName, Oid fsrvOwner, Oid fdwOid);
extern void
ac_foreign_server_alter(Oid fsrvOid, Oid newOwner);
extern void
ac_foreign_server_drop(Oid fsrvOid, bool dacSkip);
extern void
ac_foreign_server_grant(Oid fsrvOid, Oid grantor, AclMode goptions);

/* pg_language */
extern void
ac_language_create(const char *langName, bool IsTemplate,
				   bool plTrusted, bool plDbaCreate,
				   Oid handlerOid, Oid validatorOid);
extern void
ac_language_alter(Oid langOid, const char *newName, Oid newOwner);
extern void
ac_language_drop(Oid langOid, bool dacSkip);
extern void
ac_language_grant(Oid langOid, Oid grantor, AclMode goptions);
extern void
ac_language_comment(Oid langOid);

/* pg_opclass */
extern void
ac_opclass_create(const char *opcName,
                  Oid opcNsp, Oid typOid, Oid opfOid,
                  List *operList, List *procList, Oid stgOid);
extern void
ac_opclass_alter(Oid opcOid, const char *newName, Oid newOwner);
extern void
ac_opclass_drop(Oid opcOid, bool dacSkip);
extern void
ac_opclass_comment(Oid opcOid);

/* pg_operator */
extern void
ac_operator_create(const char *oprName,
                   Oid nspOid, Oid operOid,
                   Oid commOp, Oid negaOp,
                   Oid codeFn, Oid restFn, Oid joinFn);
extern void
ac_operator_alter(Oid operOid, Oid newOwner);
extern void
ac_operator_drop(Oid operOid, bool dacSkip);
extern void
ac_operator_comment(Oid operOid);

/* pg_opfamily */
extern void
ac_opfamily_create(const char *opfName, Oid opfNsp, Oid amOid);
extern void
ac_opfamily_alter(Oid opfOid, const char *newName, Oid newOwner);
extern void
ac_opfamily_drop(Oid opfOid, bool dacSkip);
extern void
ac_opfamily_comment(Oid opfOid);
extern void
ac_opfamily_add_oper(Oid opfOid, Oid operOid);
extern void
ac_opfamily_add_proc(Oid opfOid, Oid procOid);

/* pg_proc */
extern void
ac_proc_create(const char *proName, Oid proOid, Oid nspOid, Oid langOid);
extern void
ac_aggregate_create(const char *aggName, Oid nspOid, Oid transfn, Oid finalfn);
extern void
ac_proc_alter(Oid proOid, const char *newName, Oid newNspOid, Oid newOwner);
extern void
ac_proc_drop(Oid proOid, bool dacSkip);
extern void
ac_proc_grant(Oid proOid, Oid grantor, AclMode goptions);
extern void
ac_proc_comment(Oid proOid);
extern void
ac_proc_execute(Oid proOid, Oid roleOid);
extern bool
ac_proc_hint_inline(Oid proOid);

/* pg_namespace */
extern void
ac_schema_create(const char *nspName, Oid nspOwner, bool isTemp);
extern void
ac_schema_alter(Oid nspOid, const char *newName, Oid newOwner);
extern void
ac_schema_drop(Oid nspOid, bool dacSkip);
extern void
ac_schema_grant(Oid nspOid, Oid grantor, AclMode goptions);
extern bool
ac_schema_search(Oid nspOid, bool abort);
extern void
ac_schema_comment(Oid nspOid);

/* pg_rewrite */
extern void
ac_rule_create(Oid relOid, const char *ruleName);
extern void
ac_rule_drop(Oid relOid, const char *ruleName, bool dacSkip);
extern void
ac_rule_comment(Oid relOid, const char *ruleName);
extern void
ac_rule_toggle(Oid relOid, const char *ruleName, char fire_when);

/* pg_tablespace */
extern void
ac_tablespace_create(const char *tblspcName);
extern void
ac_tablespace_alter(Oid tblspcOid, const char *newName, Oid newOwner);
extern void
ac_tablespace_drop(Oid tblspcOid, bool dacSkip);
extern void
ac_tablespace_grant(Oid tblspcOid, Oid grantor, AclMode goptions);
extern void
ac_tablespace_calculate_size(Oid tblspcOid);
extern bool
ac_tablespace_for_temporary(Oid tblspcOid, bool abort);
extern void
ac_tablespace_comment(Oid tblspcOid);

/* pg_trigger */
extern void
ac_trigger_create(Oid relOid, const char *trigName, Oid conRelOid, Oid funcOid);
extern void
ac_trigger_alter(Oid relOid, const char *trigName, const char *newName);
extern void
ac_trigger_drop(Oid relOid, const char *trigName, bool dacSkip);
extern void
ac_trigger_comment(Oid relOid, const char *trigName);

/* pg_ts_config */
extern void
ac_ts_config_create(const char *cfgName, Oid cfgNsp);
extern void
ac_ts_config_alter(Oid cfgOid, const char *newName, Oid newOwner);
extern void
ac_ts_config_drop(Oid cfgOid, bool dacSkip);
extern void
ac_ts_config_comment(Oid cfgOid);

/* pg_ts_dict */
extern void
ac_ts_dict_create(const char *dictName, Oid dictNsp);
extern void
ac_ts_dict_alter(Oid dictOid, const char *newName, Oid newOwner);
extern void
ac_ts_dict_drop(Oid dictOid, bool dacSkip);
extern void
ac_ts_dict_comment(Oid dictOid);

/* pg_ts_parser */
extern void
ac_ts_parser_create(const char *prsName, Oid prsNsp,
					Oid startFn, Oid tokenFn, Oid sendFn,
					Oid headlineFn, Oid lextypeFn);
extern void
ac_ts_parser_alter(Oid prsOid, const char *newName);
extern void
ac_ts_parser_drop(Oid prsOid, bool dacSkip);
extern void
ac_ts_parser_comment(Oid prsOid);

/* pg_ts_template */
extern void
ac_ts_template_create(const char *tmplName, Oid tmplNsp,
                      Oid initFn, Oid lexizeFn);
extern void
ac_ts_template_alter(Oid tmplOid, const char *newName);
extern void
ac_ts_template_drop(Oid tmplOid, bool dacSkip);
extern void
ac_ts_template_comment(Oid tmplOid);

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
ac_type_drop(Oid typOid, bool dacSkip);
extern void
ac_type_comment(Oid typOid);

/* pg_user_mapping */
extern void
ac_user_mapping_create(Oid userId, Oid fsrvOid);
extern void
ac_user_mapping_alter(Oid umOid);
extern void
ac_user_mapping_drop(Oid umOid, bool dacSkip);

/* misc database objects */
extern void
ac_object_drop(const ObjectAddress *object, bool dacSkip);

#endif	/* UTILS_SECURITY_H */
