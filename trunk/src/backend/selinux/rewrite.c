/*
 * src/backend/selinux/rewrite.c
 *   SE-PostgreSQL Query rewriting implementation.
 *
 * Copyright (c) 2006 - 2007, KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "catalog/pg_type.h"
#include "nodes/makefuncs.h"
#include "nodes/plannodes.h"
#include "parser/parse_expr.h"
#include "parser/parse_coerce.h"
#include "sepgsql.h"
#include "utils/portal.h"
#include "utils/fmgroids.h"

static Expr *call_sepgsql_check_insert(Expr *expr, psid tblcon, uint16 tclass)
{
	FuncExpr *func;
	Const *con;
	List *args;

	/* @newcon (1st argument) */
	expr = (Expr *)coerce_to_target_type(NULL,   /* no unknown params here */
										 (Node *)expr, exprType((Node *)expr),
										 PSIDOID, -1,
										 COERCION_ASSIGNMENT,
										 COERCE_IMPLICIT_CAST);
	if (expr == NULL)
		selerror("could not call sepgsql_check_insert()"
				 " as argument imcompatibility with PSID");
	args = list_make1(expr);

	/* @tblcon (2nd argument) */
	con = makeConst(PSIDOID, sizeof(psid),
					ObjectIdGetDatum(tblcon),
					false, true);
	args = lappend(args, con);

	/* @tclass (3rd argument) */
	con = makeConst(INT4OID, sizeof(int32),
					Int32GetDatum(tclass),
					false, true);
	args = lappend(args, con);

	/* sepgsql_check_insert(newcon, tblcon, tclass) */
	func = makeFuncExpr(F_SEPGSQL_CHECK_INSERT,
						PSIDOID, args, COERCE_DONTCARE);
	return (Expr *)func;
}


/* sepgsqlExecuteQuery() -- add implicit labeling and relabel from/to
 * permission checking, when CREATE TABLE ... AS EXECUTE <prep>;
 * The arguments are copied object, so we can modify it to append
 * an additional conditions.
 */
void sepgsqlExecuteQuery(Query *query, Plan *plan)
{
	ListCell *l;
	TargetEntry *te;
	psid tblcon, tupcon;

	Assert(query->commandType == CMD_SELECT);
	Assert(query->into != NULL);

	/* compute implicit labeling */
	tblcon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
								   sepgsqlGetDatabasePsid(),
								   SECCLASS_TABLE);
	tupcon = sepgsql_avc_createcon(sepgsqlGetClientPsid(),
								   tblcon,
								   SECCLASS_TUPLE);

	/* check explicit labeling */
	foreach(l, plan->targetlist) {
		bool has_explicit = false;
		te = (TargetEntry *) lfirst(l);

		if (!strcmp(te->resname, TUPLE_SELCON)) {
			te->expr = call_sepgsql_check_insert(te->expr, tblcon,
												 SECCLASS_TABLE);
			has_explicit = true;
		}

		if (!has_explicit) {
			/* add implicit labeling */
			AttrNumber resno = list_length(plan->targetlist) + 1;
			Const *con = makeConst(PSIDOID, sizeof(psid),
								   ObjectIdGetDatum(tupcon),
								   false, true);
			Expr *expr = call_sepgsql_check_insert((Expr *)con, tblcon,
												   SECCLASS_TABLE);
			te = makeTargetEntry(expr, resno, TUPLE_SELCON, false);
			plan->targetlist = lappend(plan->targetlist, te);
		}
	}
}
