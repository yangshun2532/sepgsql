/*
 * src/backend/security/sepgsql/dummy.c
 *
 *   Dummy routines of SE-PgSQL hooks
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "security/sepgsql.h"

/*
 * This file is compiled only when SE-PgSQL is not enabled on the compile
 * time.
 * The routines in this file provides a harmless dummy state to the caller,
 * and called instead of the actual security hooks if it is disabled.
 * So, we don't need to put case handlings whether it is enabled, or not,
 * on the core routines.
 *
 * In the prior implementation, these dummy routines are implemented as
 * empty macros. But it makes impossible to load a third party module
 * both of binaries with/without SE-PostgreSQL.
 *
 * The specification details of each functions are described on the
 * actual implementation. See also, selinux.c, hooks.c and others.
 */

#define	unavailable_function()											\
	do {																\
		ereport(ERROR,													\
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),				\
				 errmsg("SE-PgSQL is disabled in this build.")));		\
	} while(0)															\

/*
 * Dummy routines for selinux.c
 * ----------------------------
 */
void
sepgsql_initialize(void)
{
	/* do nothing */
}

bool
sepgsql_is_enabled(void)
{
	return false;	/* always disabled */
}

/*
 * Dummy routines for checker.c
 * -----------------------------
 */
void
sepgsql_check_rte_perms(RangeTblEntry *rte)
{
	/* do nothging */
}

void
sepgsql_check_copy_perms(Relation rel, List *attnumlist, bool is_from)
{
	/* do nothing */
}

/*
 * Dummy routines for hooks.c
 * --------------------------
 */

/* ================ Pg_database ================ */
bool
sepgsql_database_common(Oid datOid, uint32 required, bool abort)
{
	return true;	/* always allow anything */
}

Value *
sepgsql_database_create(const char *datName, Oid srcDatOid, Node *datLabel)
{
	return NULL;	/* do nothing, and database shall be unlabeled */
}

void
sepgsql_database_alter(Oid datOid)
{
	/* do nothing */
}

void
sepgsql_database_drop(Oid datOid)
{
	/* do nothing */
}

Value *
sepgsql_database_relabel(Oid datOid, Node *datLabel)
{
	/*
	 * ALTER DATABASE with SECURITY_CONTEXT option is available
	 * only when SE-PostgreSQL is enabled.
	 */
	unavailable_function();
	return NULL;	/* for compiler quiet */
}

void
sepgsql_database_grant(Oid datOid)
{
	/* do nothing */
}

void
sepgsql_database_access(Oid datOid)
{
	return true;
}

bool
sepgsql_database_superuser(Oid datOid)
{
	return true;	/* only decided by DAC decision */
}

/* ================ Pg_namespace ================ */
bool
sepgsql_schema_common(Oid nspOid, uint32 required, bool abort)
{
	return true;	/* always allow anything */
}

Value *
sepgsql_schema_create(const char *nspName, bool isTemp, Node *nspLabel)
{
	return NULL;	/* do nothing, and the schema shall be unlabeled */
}

void
sepgsql_schema_alter(Oid nspOid)
{
	/* do nothing */
}

void
sepgsql_schema_drop(Oid nspOid)
{
	/* do nothing */
}

Value *
sepgsql_schema_relabel(Oid nspOid, Node *nspLabel)
{
	/*
	 * ALTER SCHEMA with SECURITY_CONTEXT option is available
     * only when SE-PostgreSQL is enabled.
     */
	unavailable_function();
	return NULL;	/* for compiler quiet */
}

void
sepgsql_schema_grant(Oid nspOid)
{
	/* do nothing */
}

bool
sepgsql_schema_search(Oid nspOid, bool abort)
{
	return true;	/* always allow */
}

/* ================ Pg_class ================ */
bool
sepgsql_relation_common(Oid relOid, uint32 required, bool abort)
{
	return true;	/* always allow anything */
}

DatumPtr
sepgsql_relation_create(const char *relName,
                        char relkind,
                        TupleDesc tupDesc,
                        Oid nspOid,
                        Node *relLabel,
                        List *colList,
                        bool createAs)
{
	return NULL;	/* do nothing, and the table/columns shall be unlabeled */
}

void
sepgsql_relation_alter(Oid relOid, const char *newName, Oid newNsp)
{
	/* do nothing */
}

void
sepgsql_relation_drop(Oid relOid)
{
	/* do nothing */
}

void
sepgsql_relation_grant(Oid relOid)
{
	/* do nothing */
}

Value *
sepgsql_relation_relabel(Oid relOid, Node *relLabel)
{
	/*
	 * ALTER TABLE with SECURITY_CONTEXT option is available
	 * only when SE-PostgreSQL is enabled.
	 */
	unavailable_function();
	return NULL;	/* for compiler quiet */
}

void
sepgsql_relation_truncate(Relation rel)
{
	/* do nothing */
}

void
sepgsql_relation_lock(Oid relOid)
{
	/* do nothing */
}

void
sepgsql_index_create(Oid relOid, Oid nspOid)
{
	/* do nothing */
}

/* ================ Pg_attribute ================ */
bool
sepgsql_attribute_common(Oid relOid, AttrNumber attnum,
                         uint32 required, bool abort)
{
	return true;	/* always allow anything */
}

Value *
sepgsql_attribute_create(Oid relOid, ColumnDef *cdef)
{
	return NULL;	/* do nothing, and the column shall be unlabeled */
}

void
sepgsql_attribute_alter(Oid relOid, const char *attname)
{
	/* do nothing */
}

void
sepgsql_attribute_drop(Oid relOid, const char *attname)
{
	/* do nothing */
}

void
sepgsql_attribute_grant(Oid relOid, AttrNumber attnum)
{
	/* do nothing */
}

Value *
sepgsql_attribute_relabel(Oid relOid, const char *attname, Node *attLabel)
{
	/*
	 * ALTER TABLE with SECURITY_CONTEXT option is available
	 * only when SE-PostgreSQL is enabled.
	 */
	return NULL;	/* for compiler quiet */
}

/* ================ Misc database objects ================ */
void
sepgsql_object_comment(Oid relOid, Oid objId, int32 subId)
{
	/* do nothing */
}

void
sepgsql_object_drop(ObjectAddress *object)
{
	/* do nothing */
}

/*
 * Dummy built-in SQL functions
 * ----------------------------
 */
Datum
sepgsql_template1_context(PG_FUNCTION_ARGS)
{
	unavailable_function();
	PG_RETURN_VOID();
}

Datum
sepgsql_default_context(PG_FUNCTION_ARGS)
{
	unavailable_function();
	PG_RETURN_VOID();
}

Datum
sepgsql_getcon(PG_FUNCTION_ARGS)
{
	unavailable_function();
	PG_RETURN_VOID();
}

Datum
sepgsql_database_getcon(PG_FUNCTION_ARGS)
{
	unavailable_function();
	PG_RETURN_VOID();
}

Datum
sepgsql_schema_getcon(PG_FUNCTION_ARGS)
{
	unavailable_function();
	PG_RETURN_VOID();
}

Datum
sepgsql_relation_getcon(PG_FUNCTION_ARGS)
{
	unavailable_function();
	PG_RETURN_VOID();
}

Datum
sepgsql_attribute_getcon(PG_FUNCTION_ARGS)
{
	unavailable_function();
	PG_RETURN_VOID();
}
