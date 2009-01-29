/*
 * src/backend/utils/sepgsql/label.c
 *    SE-PostgreSQL security label management
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"










static Oid earlySecurityLabelToSid(const char *label)
{}

static char *earlySidToSecurityLabel(Oid sid)
{}

void sepgsqlPostBootstrapingMode(void)
{
	if (!sepgsqlIsEnabled())
		return;
}

Oid sepgsqlLookupSecurityId(char *raw_label)
{}

Oid sepgsqlSecurityLabelToSid(char *label)
{}

char *sepgsqlLookupSecurityLabel(Oid sid)
{}

char *sepgsqlSidToSecurityLabel(Oid sid)
{}


