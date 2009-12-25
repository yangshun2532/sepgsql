/*
 * ace_misc.c
 *
 * miscellaneous security hook routines
 *
 * Portions Copyright (c) 1996-2010, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "security/ace.h"

/*
 * init_ace_providers
 *
 * This hook allows security providers to initialize itself.
 */
void
check_provider_initialize(void)
{
	/* initialize the default PG privs */
	initialize_acl();
}
