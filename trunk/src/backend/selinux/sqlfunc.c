/*
 * src/backend/selinux/rewrite.c
 *   SE-PostgreSQL implementation for SQL functons.
 *
 * Copyright (c) 2006 - 2007, KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "fmgr.h"
#include "lib/stringinfo.h"
#include "libpq/pqformat.h"
#include "sepgsql.h"

#include <selinux/selinux.h>

/* translate a raw formatted context into mcstrans'ed one */
static char *__psid_raw_to_trans_context(char *raw_context)
{
	security_context_t context;
	char *result;

	if (selinux_raw_to_trans_context(raw_context, &context))
		selerror("could not translate MLS label");
	PG_TRY();
	{
		result = pstrdup(context);
	}
	PG_CATCH();
	{
		freecon(context);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(context);

	return result;
}

/* translate a mcstrans'ed context into raw formatted one */
static char *__psid_trans_to_raw_context(char *context)
{
	security_context_t raw_context;
	char *result;

	if (selinux_trans_to_raw_context(context, &raw_context))
		selerror("could not translate MLS label");
	PG_TRY();
	{
		result = pstrdup(raw_context);
	}
	PG_CATCH();
	{
		freecon(raw_context);
		PG_RE_THROW();
	}
	PG_END_TRY();
	freecon(raw_context);

	return result;
}

/* psid_in() -- PSID input function */
Datum
psid_in(PG_FUNCTION_ARGS)
{
	char *context = PG_GETARG_CSTRING(0);
	psid sid;

	context = __psid_trans_to_raw_context(context);
	sid = sepgsql_context_to_psid(context);

	PG_RETURN_OID(sid);
}

/* psid_out() -- PSID output function */
Datum
psid_out(PG_FUNCTION_ARGS)
{
	psid sid = PG_GETARG_OID(0);
	char *context;

	context = sepgsql_psid_to_context(sid);
	context = __psid_raw_to_trans_context(context);

	PG_RETURN_CSTRING(context);
}

/* text_to_psid() -- PSID cast function */
Datum
text_to_psid(PG_FUNCTION_ARGS)
{
	text *tmp = PG_GETARG_TEXT_P(0);
	char *context;
	psid sid;

	context = VARDATA(tmp);
	context = __psid_trans_to_raw_context(context);
	sid = sepgsql_context_to_psid(context);

	PG_RETURN_OID(sid);
}

/* psid_to_text() -- PSID cast function */
Datum
psid_to_text(PG_FUNCTION_ARGS)
{
	psid sid = PG_GETARG_OID(0);
	char *context;
	text *result;

	context = sepgsql_psid_to_context(sid);
	context = __psid_raw_to_trans_context(context);

	result = palloc(VARHDRSZ + strlen(context));
	VARATT_SIZEP(result) = VARHDRSZ + strlen(context);
	memcpy(VARDATA(result), context, strlen(context));

	PG_RETURN_TEXT_P(result);
}

/* sepgsql_getcon() -- returns a security context of client */
Datum
sepgsql_getcon(PG_FUNCTION_ARGS)
{
	PG_RETURN_OID(sepgsqlGetClientPsid());
}

/*
 * sepgsql_tuple_perm(relid, objcon, perms)
 *   fileter access permission of SECCLASS_TUPLE bases on security context.
 */
Datum
sepgsql_tuple_perm(PG_FUNCTION_ARGS)
{
	Oid relid = PG_GETARG_OID(0);
	psid tupcon = PG_GETARG_OID(1);
	uint32 perms = PG_GETARG_UINT32(2);
	uint16 tclass = SECCLASS_TUPLE;
	char *audit;
	int rc;

	/* formalize tclass and perms */
	switch (relid) {
	case AttributeRelationId:
		tclass = SECCLASS_COLUMN;
		break;
	case RelationRelationId:
		tclass = SECCLASS_TABLE;
		break;
	case DatabaseRelationId:
		tclass = SECCLASS_DATABASE;
		break;
	case ProcedureRelationId:
		tclass = SECCLASS_PROCEDURE;
		break;
	case LargeObjectRelationId:
		tclass = SECCLASS_BLOB;
		break;
	default:
		/* do nothing */
		break;
	}

	if (tclass != SECCLASS_TUPLE) {
		uint32 __perms = 0;
		__perms |= ((perms & TUPLE__SELECT) ? COMMON_DATABASE__GETATTR : 0);
		__perms |= ((perms & TUPLE__UPDATE) ? COMMON_DATABASE__SETATTR : 0);
		__perms |= ((perms & TUPLE__INSERT) ? COMMON_DATABASE__CREATE  : 0);
		__perms |= ((perms & TUPLE__DELETE) ? COMMON_DATABASE__DROP    : 0);
		perms = __perms;
	}

	rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
								tupcon, tclass, perms, &audit);
	if (audit)
		ereport(NOTICE, (errcode(ERRCODE_INTERNAL_ERROR),
						 errmsg("SELinux: %s", audit)));
	PG_RETURN_BOOL(rc == 0);
}
