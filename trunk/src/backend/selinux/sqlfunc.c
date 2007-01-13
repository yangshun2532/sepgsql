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

/* sepgsql_check_insert() -- abort current transaction
 * if specified context is not allowed.
 * @newcon : new security context of the tuple
 * @tblcon : table's security context
 * @tclass : object class (normally SECCLASS_TUPLE)
 */
Datum
sepgsql_check_insert(PG_FUNCTION_ARGS)
{
	psid newcon = PG_GETARG_OID(0);
	psid tblcon = PG_GETARG_OID(1);
	uint16 tclass = PG_GETARG_INT32(2);
	psid impcon;
	uint32 perms;
	char *audit;
	int rc;

	/* compute implicit context */
	impcon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
								   tblcon, tclass);
	if (tclass == SECCLASS_TUPLE) {
		perms = TUPLE__INSERT;
		if (newcon != impcon)
			perms |= TUPLE__RELABELFROM;
	} else {
		perms = COMMON_DATABASE__CREATE;
		if (newcon != impcon)
			perms |= COMMON_DATABASE__RELABELFROM;
    }

	rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
								impcon, tclass, perms, &audit);
	sepgsql_audit(rc, audit, NULL);

	if (newcon != impcon) {
		perms = (tclass == SECCLASS_TUPLE)
			? TUPLE__RELABELTO
			: COMMON_DATABASE__RELABELTO;
		rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
									newcon, tclass, perms, &audit);
		sepgsql_audit(rc, audit, NULL);
	}
	PG_RETURN_OID(newcon);
}

/* sepgsql_check_update() -- abort current transaction
 * if specified context is not allowed.
 * @newcon : new security context of the tuple
 * @oldcon : old security context of the tuple
 * @tclass : object class (normally SECCLASS_TUPLE)
 */
Datum
sepgsql_check_update(PG_FUNCTION_ARGS)
{
	psid newcon = PG_GETARG_OID(0);
	psid oldcon = PG_GETARG_OID(1);
	uint16 tclass = PG_GETARG_INT32(2);
	uint32 perms;
	char *audit;
	int rc;

	if (tclass == SECCLASS_TUPLE) {
		perms = TUPLE__UPDATE;
		if (newcon != oldcon)
			perms |= TUPLE__RELABELFROM;
	} else {
		perms = COMMON_DATABASE__SETATTR;
		if (newcon != oldcon)
			perms |= COMMON_DATABASE__RELABELFROM;
	}
	rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
								oldcon, tclass, perms, &audit);
	sepgsql_audit(rc, audit, NULL);

	if (oldcon != newcon) {
		perms = (tclass == SECCLASS_TUPLE)
			? TUPLE__RELABELTO
			: COMMON_DATABASE__RELABELTO;
		rc = sepgsql_avc_permission(sepgsqlGetClientPsid(),
									newcon, tclass, perms, &audit);
		sepgsql_audit(rc, audit, NULL);
	}
	PG_RETURN_OID(newcon);
}
