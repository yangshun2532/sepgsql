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
	uint32 perm;
	int index;

	/* 1. permission check on relation */
	index = query->resultRelation;
	rte = list_nth(query->rtable, index - 1);
	perm = TABLE__DELETE;
	if (query->returningList)
		perm |= TABLE__SELECT;
	selinuxCheckRteRelation(query, rte, index, perm);

	/* 2. permission check on using clause */
	if (query->jointree->fromlist) {
		ListCell *x;
		foreach(x, query->jointree->fromlist) {
			RangeTblEntry *rte;
			Node *n = lfirst(x);
			Assert(IsA(n, RangeTblRef));
			
			index = ((RangeTblRef *)n)->rtindex;
			rte = list_nth(query->rtable, index - 1);
			Assert(IsA(rte, RangeTblEntry));
			
			selinuxCheckRteRelation(query, rte, index, TABLE__SELECT);
		}
	}

	/* 3. check where clause */
	selinuxCheckExpr(query, (Expr *)query->jointree->quals);

	/* 4. check returning clause, if necessary*/
	selinuxCheckTargetList(query, query->returningList);

	return query;
}

