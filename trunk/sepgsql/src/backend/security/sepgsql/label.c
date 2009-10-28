/*
 * src/backend/security/sepgsql/label.c
 * 
 * Routines to manage security context
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

/* GUC option to turn on/off mcstrans feature */
bool	sepostgresql_mcstrans;









/*
 * sepgsql_initial_labeling
 *
 * 
 * 
 *
 */
void
sepgsql_initial_labeling(void)
{


}

/*
 * sepgsql_on_create_database
 *
 * copies all the entries within pg_selinux refered by the source
 * database.
 */
sepgsql_on_create_database(Oid src_datid, Oid dst_datid)
{}

/*
 * sepgsql_on_drop_database
 *
 * removes all the entries within pg_selinux refered by the database
 * to be dropped.
 */
void
sepgsql_on_drop_database(Oid datid)
{}
