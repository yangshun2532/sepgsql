/*
 * src/backend/selinux/create_database.c
 *    CREATE DATABASE statement support
 * Copyright (c) 2006 - 2007 KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "catalog/pg_database.h"
#include "sepgsql.h"

#include <selinux/flask.h>
#include <selinux/av_permissions.h>

void selinuxHookCreateDatabase(Datum *values, char *nulls)
{
	psid db_psid = libselinux_avc_createcon(selinuxGetClientPsid(),
											selinuxGetServerPsid(),
											SECCLASS_DATABASE);
	values[Anum_pg_database_datselcon - 1] = ObjectIdGetDatum(db_psid);
	nulls[Anum_pg_database_datselcon - 1] = ' ';
}
