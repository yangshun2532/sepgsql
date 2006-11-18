/*
 * src/backend/selinux/delete.c
 *     Security Enhanced PostgreSQL implementation.
 *     This file provides proxy hook for DELETE statement.
 *
 *     Copyright (c) 2006 - 2007, KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "sepgsql.h"
#include <selinux/flask.h>
#include <selinux/av_permissions.h>

Query *selinuxProxyDelete(Query *query)
{
	RangeTblEntry *rte;
	int index;

	/* 1. permission check on relation */
	index = query->resultRelation;
	rte = list_nth(query->rtable, index - 1);
	selinuxCheckRteRelation(query, rte, index, TABLE__DELETE);

	/* 2. check where clause */
	selinuxCheckExpr(query, (Expr *)query->jointree->quals);

	return query;
}
