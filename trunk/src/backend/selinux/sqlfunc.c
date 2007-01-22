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

/* sepgsql_permission(objcon, tclass, perms)
 * sepgsql_permission_noaudit(objcon, tclass, perms)
 *   checks permission based on security context.
 * @objcon : security context of object
 * @tclass : security class
 * @perms  : permission set
 */
Datum
sepgsql_permission(PG_FUNCTION_ARGS)
{
	psid objcon = PG_GETARG_OID(0);
	uint16 tclass = PG_GETARG_UINT32(1);
	uint32 perms = PG_GETARG_UINT32(2);
	int rc;
	char *audit;

	rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
								objcon, tclass, perms, &audit);
	if (audit) {
		ereport(NOTICE, (errcode(ERRCODE_INTERNAL_ERROR),
						 errmsg("SELinux: %s", audit)));
	}
	PG_RETURN_BOOL(rc == 0);
}

Datum
sepgsql_permission_noaudit(PG_FUNCTION_ARGS)
{
	psid objcon = PG_GETARG_OID(0);
	uint16 tclass = PG_GETARG_UINT32(1);
	uint32 perms = PG_GETARG_UINT32(2);
	int rc;

	rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
								objcon, tclass, perms, NULL);
	PG_RETURN_BOOL(rc == 0);
}
