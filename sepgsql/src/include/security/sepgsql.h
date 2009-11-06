/*
 * src/include/security/sepgsql.h
 *
 * Headers for SE-PostgreSQL
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#ifndef SEPGSQL_H
#define SEPGSQL_H

#include "access/tupdesc.h"
#include "catalog/dependency.h"
#include "fmgr.h"
#include "nodes/bitmapset.h"
#include "nodes/parsenodes.h"
#include "utils/relcache.h"

typedef char *sepgsql_label_t;

/* GUC option to control mode in SE-PostgreSQL */
#define SEPGSQL_MODE_DEFAULT		1
#define SEPGSQL_MODE_ENFORCING		2
#define SEPGSQL_MODE_PERMISSIVE		3
#define SEPGSQL_MODE_INTERNAL		4
#define SEPGSQL_MODE_DISABLED		5

extern int	sepostgresql_mode;

/* GUC option to turn on/off mcstrans */
extern bool	sepostgresql_mcstrans;

/* Internal code for object classes */
enum {
	SEPG_CLASS_DB_DATABASE = 0,
	SEPG_CLASS_DB_SCHEMA,
	SEPG_CLASS_DB_TABLE,
	SEPG_CLASS_DB_COLUMN,
	SEPG_CLASS_MAX
};

/* Internal code for permissions */
#define SEPG_DB_DATABASE__CREATE			(1<<0)
#define SEPG_DB_DATABASE__DROP				(1<<1)
#define SEPG_DB_DATABASE__GETATTR			(1<<2)
#define SEPG_DB_DATABASE__SETATTR			(1<<3)
#define SEPG_DB_DATABASE__RELABELFROM		(1<<4)
#define SEPG_DB_DATABASE__RELABELTO			(1<<5)
#define SEPG_DB_DATABASE__ACCESS			(1<<6)
#define SEPG_DB_DATABASE__LOAD_MODULE		(1<<7)
#define SEPG_DB_DATABASE__SUPERUSER			(1<<8)

#define SEPG_DB_SCHEMA__CREATE				(SEPG_DB_DATABASE__CREATE)
#define SEPG_DB_SCHEMA__DROP				(SEPG_DB_DATABASE__DROP)
#define SEPG_DB_SCHEMA__GETATTR				(SEPG_DB_DATABASE__GETATTR)
#define SEPG_DB_SCHEMA__SETATTR				(SEPG_DB_DATABASE__SETATTR)
#define SEPG_DB_SCHEMA__RELABELFROM			(SEPG_DB_DATABASE__RELABELFROM)
#define SEPG_DB_SCHEMA__RELABELTO			(SEPG_DB_DATABASE__RELABELTO)
#define SEPG_DB_SCHEMA__SEARCH				(1<<6)
#define SEPG_DB_SCHEMA__ADD_NAME			(1<<7)
#define SEPG_DB_SCHEMA__REMOVE_NAME			(1<<8)

#define SEPG_DB_TABLE__CREATE				(SEPG_DB_DATABASE__CREATE)
#define SEPG_DB_TABLE__DROP					(SEPG_DB_DATABASE__DROP)
#define SEPG_DB_TABLE__GETATTR				(SEPG_DB_DATABASE__GETATTR)
#define SEPG_DB_TABLE__SETATTR				(SEPG_DB_DATABASE__SETATTR)
#define SEPG_DB_TABLE__RELABELFROM			(SEPG_DB_DATABASE__RELABELFROM)
#define SEPG_DB_TABLE__RELABELTO			(SEPG_DB_DATABASE__RELABELTO)
#define SEPG_DB_TABLE__SELECT				(1<<6)
#define SEPG_DB_TABLE__UPDATE				(1<<7)
#define SEPG_DB_TABLE__INSERT				(1<<8)
#define SEPG_DB_TABLE__DELETE				(1<<9)
#define SEPG_DB_TABLE__LOCK					(1<<10)

#define SEPG_DB_COLUMN__CREATE				(SEPG_DB_DATABASE__CREATE)
#define SEPG_DB_COLUMN__DROP				(SEPG_DB_DATABASE__DROP)
#define SEPG_DB_COLUMN__GETATTR				(SEPG_DB_DATABASE__GETATTR)
#define SEPG_DB_COLUMN__SETATTR				(SEPG_DB_DATABASE__SETATTR)
#define SEPG_DB_COLUMN__RELABELFROM			(SEPG_DB_DATABASE__RELABELFROM)
#define SEPG_DB_COLUMN__RELABELTO			(SEPG_DB_DATABASE__RELABELTO)
#define SEPG_DB_COLUMN__SELECT				(1<<6)
#define SEPG_DB_COLUMN__UPDATE				(1<<7)
#define SEPG_DB_COLUMN__INSERT				(1<<8)

/*
 * selinux.c : communication routines with SELinux
 * -----------------------------------------------
 */
extern void sepgsql_initialize(void);

extern bool sepgsql_is_enabled(void);

extern bool sepgsql_get_enforce(void);

typedef void (*sepgsql_audit_hook_t) (bool denied,
									  const char *scontext,
									  const char *tcontext,
									  const char *tclass,
									  const char *permissions,
									  const char *audit_name);
extern bool
sepgsql_compute_perms(char *scontext, char *tcontext,
					  uint16 tclass, uint32 required,
					  const char *audit_name, bool abort);
extern char *
sepgsql_compute_create(char *scontext, char *tcontext, uint16 tclass);

/*
 * label.c : management of security context
 */
extern char *sepgsql_get_client_context(void);
extern char *sepgsql_set_client_context(char *new_context);
extern char *sepgsql_get_unlabeled_context(void);
extern char *sepgsql_get_file_context(const char *filename);
extern char *sepgsql_default_database_context(void);
extern char *sepgsql_default_schema_context(Oid datOid);
extern char *sepgsql_default_table_context(Oid nspOid);
extern char *sepgsql_default_column_context(Oid relOid);
extern char *sepgsql_mcstrans_out(char *context);
extern char *sepgsql_mcstrans_in(char *context);

/*
 * checker.c : routines to check DML permissions
 * ---------------------------------------------
 */
extern void
sepgsql_check_rte_perms(RangeTblEntry *rte);
extern void
sepgsql_check_copy_perms(Relation rel, List *attnumlist, bool is_from);

/*
 * hooks.c : entrypoints of SE-PgSQL checks
 * ----------------------------------------
 */

/* Pg_database related hooks */
extern bool
sepgsql_database_common(Oid datOid, uint32 required, bool abort);
extern Value *
sepgsql_database_create(const char *datName, Node *datLabel);
extern void
sepgsql_database_alter(Oid datOid);
extern void
sepgsql_database_drop(Oid datOid);
extern Value *
sepgsql_database_relabel(Oid datOid, Node *datLabel);
extern void
sepgsql_database_grant(Oid datOid);
extern void
sepgsql_database_access(Oid datOid);
extern bool
sepgsql_database_superuser(Oid datOid);
extern void
sepgsql_database_load_module(const char *filename);

/* Pg_namespace related hooks */
extern bool
sepgsql_schema_common(Oid nspOid, uint32 required, bool abort);
extern Value *
sepgsql_schema_create(const char *nspName, bool isTemp, Node *nspLabel);
extern void
sepgsql_schema_alter(Oid nspOid);
extern void
sepgsql_schema_drop(Oid nspOid);
extern Value *
sepgsql_schema_relabel(Oid nspOid, Node *nspLabel);
extern void
sepgsql_schema_grant(Oid nspOid);
extern bool
sepgsql_schema_search(Oid nspOid, bool abort);

/* Pg_class related hooks */
extern bool
sepgsql_relation_common(Oid relOid, uint32 required, bool abort);
extern DatumPtr
sepgsql_relation_create(const char *relName,
                        char relkind,
                        TupleDesc tupDesc,
                        Oid nspOid,
                        Node *relLabel,
                        List *colList,
                        bool createAs);
extern void
sepgsql_relation_alter(Oid relOid, const char *newName, Oid newNsp);
extern void
sepgsql_relation_drop(Oid relOid);
extern void
sepgsql_relation_grant(Oid relOid);
extern Value *
sepgsql_relation_relabel(Oid relOid, Node *relLabel);
extern void
sepgsql_relation_truncate(Relation rel);
extern void
sepgsql_relation_lock(Oid relOid);
extern void
sepgsql_index_create(Oid relOid, Oid nspOid);

/* Pg_attribute related hooks */
extern bool
sepgsql_attribute_common(Oid relOid, AttrNumber attnum,
						 uint32 required, bool abort);
extern Value *
sepgsql_attribute_create(Oid relOid, ColumnDef *cdef);
extern void
sepgsql_attribute_alter(Oid relOid, const char *attname);
extern void
sepgsql_attribute_drop(Oid relOid, const char *attname);
extern void
sepgsql_attribute_grant(Oid relOid, AttrNumber attnum);
extern Value *
sepgsql_attribute_relabel(Oid relOid, const char *attname, Node *attLabel);

/* Misc database objects related hooks */
extern void
sepgsql_object_comment(Oid relOid, Oid objId, int32 subId);
extern void
sepgsql_object_drop(ObjectAddress *object);


/*
 * utils.c : SE-PgSQL related SQL functions
 * ----------------------------------------
 */

extern Datum sepgsql_fn_compute_create(PG_FUNCTION_ARGS);
extern Datum sepgsql_fn_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_fn_database_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_fn_schema_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_fn_table_getcon(PG_FUNCTION_ARGS);
extern Datum sepgsql_fn_column_getcon(PG_FUNCTION_ARGS);

#define secontext_cmp(a,b)						\
	((!(a) && !(b)) || ((a) && (b) && strcmp((a), (b)) == 0))

#endif	/* SEPGSQL_H */
