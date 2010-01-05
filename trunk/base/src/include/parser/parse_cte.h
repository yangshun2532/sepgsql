/*-------------------------------------------------------------------------
 *
 * parse_cte.h
 *	  handle CTEs (common table expressions) in parser
 *
 *
 * Portions Copyright (c) 1996-2010, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * $PostgreSQL: pgsql/src/include/parser/parse_cte.h,v 1.4 2010/01/02 16:58:07 momjian Exp $
 *
 *-------------------------------------------------------------------------
 */
#ifndef PARSE_CTE_H
#define PARSE_CTE_H

#include "parser/parse_node.h"

extern List *transformWithClause(ParseState *pstate, WithClause *withClause);

extern void analyzeCTETargetList(ParseState *pstate, CommonTableExpr *cte,
								 List *tlist);

#endif   /* PARSE_CTE_H */
