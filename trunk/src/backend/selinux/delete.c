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

Query *sepgsqlProxyDelete(Query *query)
{
	ListCell *x;
	RangeTblEntry *rte;
	int index;

	/* 1. permission mark on target relation */
	index = query->resultRelation;
	rte = list_nth(query->rtable, index - 1);
	rte->access_vector |= TABLE__DELETE;

	/* 2. permission mark on using clause */
	foreach(x, query->jointree->fromlist) {
		Node *n = lfirst(x);
		Assert(IsA(n, RangeTblRef));
		index = ((RangeTblRef *)n)->rtindex;
		rte = list_nth(query->rtable, index - 1);
		rte->access_vector |= TABLE__SELECT;
	}

	/* 3. permission mark on returning clause, if necessary */
	sepgsqlCheckTargetList(query, query->returningList);

	/* 4. permission mark on where clause */
	sepgsqlCheckExpr(query, (Expr *)query->jointree->quals);

	/* 5. permission checking */
	index = 1;
	foreach (x, query->rtable) {
		rte = (RangeTblEntry *) lfirst(x);
		if (rte->rtekind == RTE_RELATION)
			sepgsqlCheckRteRelation(query, rte, index);
		index++;
	}

	return query;
}

