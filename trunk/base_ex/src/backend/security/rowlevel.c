/*
 * src/backend/security/rowlevel.c
 *    Common facilities for row-level access controls
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 */
#include "postgres.h"

#include "executor/executor.h"
#include "security/rowlevel.h"

void
rowlvSetScanPolicy(ScanState *sstate, EState *estate)
{
	MemoryContext	oldcxt;
	Relation		relation = sstate->ss_currentRelation;
	ExprState	   *policy;

	if (RelationGetRowLevelDac(relation) &&
		RelationGetRowLevelPolicy(relation))
	{
		char *tmp = RelationGetRowLevelPolicy(relation);

		policy = ExecPrepareExpr(stringToNode(tmp), estate);

		oldcxt = MemoryContextSwitchTo(estate->es_query_cxt);
		sstate->ps.qual = list_concat(list_make1(policy),
									  sstate->ps.qual);
		MemoryContextSwitchTo(oldcxt);
	}
}
