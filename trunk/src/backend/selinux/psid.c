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

#include <selinux/flask.h>
#include <selinux/av_permissions.h>

Datum
psid_in(PG_FUNCTION_ARGS)
{
	char *context = PG_GETARG_CSTRING(0);
	psid sid = libselinux_context_to_psid(context);
	
	PG_RETURN_OID(sid);
}

Datum
psid_out(PG_FUNCTION_ARGS)
{
	psid sid = PG_GETARG_OID(0);
	char *result = libselinux_psid_to_context(sid);

	PG_RETURN_CSTRING(result);
}

Datum
psid_recv(PG_FUNCTION_ARGS)
{
	StringInfo buf = (StringInfo) PG_GETARG_POINTER(0);
	psid sid = 1234;
	
	PG_RETURN_OID(sid);
}

Datum
psid_send(PG_FUNCTION_ARGS)
{
	psid sid = PG_GETARG_OID(0);
	char *result = pstrdup("hoge");

	PG_RETURN_CSTRING(result);
}

Datum
text_to_psid(PG_FUNCTION_ARGS)
{
	text *context = PG_GETARG_TEXT_P(0);
	psid sid = 1234;

	PG_RETURN_OID(sid);
}

Datum
psid_to_text(PG_FUNCTION_ARGS)
{
	psid sid = PG_GETARG_OID(0);
	char *tmp = "hoge";
	text *result;

	result = palloc(VARHDRSZ + strlen(tmp));
	VARATT_SIZEP(result) = VARHDRSZ + strlen(tmp);
	memcpy(VARDATA(result), tmp, strlen(tmp));

	PG_RETURN_TEXT_P(result);
}
