/*
 * src/backend/selinux/rewrite.c
 *   SE-PostgreSQL Query rewriting implementation.
 *
 * Copyright (c) 2006 - 2007, KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "sepgsql.h"

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
