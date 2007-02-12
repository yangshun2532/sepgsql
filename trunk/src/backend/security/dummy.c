/*
 * src/backend/security/dummy.c
 *   dummy functions, if SE-PostgreSQL was disabled.
 * 
 * Copyright (c) 2006 - 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"
#include "security/sepgsql.h"

Datum psid_in(PG_FUNCTION_ARGS);
Datum psid_out(PG_FUNCTION_ARGS);
Datum text_to_psid(PG_FUNCTION_ARGS);
Datum psid_to_text(PG_FUNCTION_ARGS);
Datum sepgsql_getcon(PG_FUNCTION_ARGS);
Datum sepgsql_tuple_perm(PG_FUNCTION_ARGS);
Datum sepgsql_tuple_perm_abort(PG_FUNCTION_ARGS);

Datum psid_in(PG_FUNCTION_ARGS)
{
	return oidin(fcinfo);
}

Datum psid_out(PG_FUNCTION_ARGS)
{
	return oidout(fcinfo);
}

Datum text_to_psid(PG_FUNCTION_ARGS)
{
	return text_oid(fcinfo);
}

Datum psid_to_text(PG_FUNCTION_ARGS)
{
	return oid_text(fcinfo);
}

Datum sepgsql_getcon(PG_FUNCTION_ARGS)
{
	selerror("SE-PostgreSQL is not configured");
	PG_RETURN_OID(InvalidOid);
}

Datum sepgsql_tuple_perm(PG_FUNCTION_ARGS)
{
	selerror("SE-PostgreSQL is not configured");
	PG_RETURN_BOOL(false);
}

Datum sepgsql_tuple_perm_abort(PG_FUNCTION_ARGS)
{
	selerror("SE-PostgreSQL is not configured");
	PG_RETURN_BOOL(false);
}
