/*
 * src/backend/selinux/insert.c
 *     Security Enhanced PostgreSQL implementation.
 *     This file provides proxy hook for INSERT statement.
 *
 *     Copyright (c) 2006 - 2007, KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "sepgsql.h"
#include <selinux/flask.h>
#include <selinux/av_permissions.h>

Query *selinuxProxyInsert(Query *query)
{
	return query;
}

