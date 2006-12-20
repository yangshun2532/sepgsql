/*
 * src/backend/selinux/psid.c
 *    Persistent Security Identifier functions.
 *
 * Copyright (c) 2006 - 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "fmgr.h"
#include "lib/stringinfo.h"
#include "libpq/pqformat.h"
#include "sepgsql.h"

#include <selinux/selinux.h>
#include <selinux/flask.h>
#include <selinux/av_permissions.h>

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

Datum
psid_in(PG_FUNCTION_ARGS)
{
	char *context = PG_GETARG_CSTRING(0);
	psid sid;

	context = __psid_trans_to_raw_context(context);
	sid = libselinux_context_to_psid(context);

	PG_RETURN_OID(sid);
}

Datum
psid_out(PG_FUNCTION_ARGS)
{
	psid sid = PG_GETARG_OID(0);
	char *context;

	context = libselinux_psid_to_context(sid);
	context = __psid_raw_to_trans_context(context);

	PG_RETURN_CSTRING(context);
}

Datum
psid_recv(PG_FUNCTION_ARGS)
{
	StringInfo buf = (StringInfo) PG_GETARG_POINTER(0);
	char *context = pq_getmsgstring(buf);
	psid sid;

	context = __psid_trans_to_raw_context(context);
	sid = libselinux_context_to_psid(context);

	PG_RETURN_OID(sid);
}

Datum
psid_send(PG_FUNCTION_ARGS)
{
	psid sid = PG_GETARG_OID(0);
	char *context;

	context = libselinux_psid_to_context(sid);
	context = __psid_raw_to_trans_context(context);

	PG_RETURN_CSTRING(context);
}

Datum
text_to_psid(PG_FUNCTION_ARGS)
{
	text *tmp = PG_GETARG_TEXT_P(0);
	char *context;
	psid sid;

	context = VARDATA(tmp);
	context = __psid_trans_to_raw_context(context);
	sid = libselinux_context_to_psid(context);

	PG_RETURN_OID(sid);
}

Datum
psid_to_text(PG_FUNCTION_ARGS)
{
	psid sid = PG_GETARG_OID(0);
	char *context;
	text *result;

	context = libselinux_psid_to_context(sid);
	context = __psid_raw_to_trans_context(context);

	result = palloc(VARHDRSZ + strlen(context));
	VARATT_SIZEP(result) = VARHDRSZ + strlen(context);
	memcpy(VARDATA(result), context, strlen(context));

	PG_RETURN_TEXT_P(result);
}
