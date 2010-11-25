/*
 * hooks.c
 *
 * It dispatches callbacks from the hooks of PostgreSQL
 *
 * Author: KaiGai Kohei <kaigai@ak.jp.nec.com>
 *
 * Copyright (c) 2007 - 2010, NEC Corporation
 * Copyright (c) 2006 - 2007, KaiGai Kohei <kaigai@kaigai.gr.jp>
 */
#include "postgres.h"

#include "catalog/objectaccess.h"
#include "catalog/pg_class.h"
#include "catalog/pg_language.h"
#include "catalog/pg_largeobject.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_proc.h"
#include "executor/executor.h"
#include "fmgr.h"
#include "libpq/auth.h"

#include "sepgsql.h"

/*
 * chains to secondary modules
 */
static object_access_hook_type			object_access_next = NULL;
static ClientAuthentication_hook_type	ClientAuthentication_next = NULL;
static ExecutorCheckPerms_hook_type		ExecutorCheckPerms_next = NULL;
static needs_function_call_type			needs_function_call_next = NULL;
static function_call_type				function_call_next = NULL;

/*
 * sepgsql_client_authorization
 *
 * Entrypoint of the client authentication hook.
 * It switches the client label according to getpeercon(), and the current
 * performing mode according to the GUC setting.
 */
static void
sepgsql_client_authorization(Port *port, int status)
{
	if (client_authentication_next)
		(*client_authentication_next)(port, status);

	/*
	 * In the case when authentication failed, the supplied connection
	 * shall be closed soon, so we don't need to work anymore.
	 */
	if (status == STATUS_OK)
	{
		char   *context;

		if (getpeercon_raw(port->sock, &context) < 0)
			ereport(FATAL,
					(errcode(ERRCODE_INTERNAL_ERROR),
					 errmsg("selinux: failed to obtain the peer label")));

		sepgsql_set_client_label(context);

		if (sepgsql_get_permissive())
			sepgsql_set_mode(SEPGSQL_MODE_PERMISSIVE);
		else
			sepgsql_set_mode(SEPGSQL_MODE_DEFAULT);
	}
}

/*
 * sepgsql_object_access
 *
 * Entrypoint of the object_access_hook. It dispatches the supplied
 * access based on access type and object classes.
 */
static void
sepgsql_object_access(ObjectAccessType access,
					  Oid classId,
					  Oid objectId,
					  int subId)
{
	if (object_access_next)
		(*object_access_next)(access, classId, objectId, subId);

	switch (access)
	{
		case OAT_POST_CREATE:
			switch (classId)
			{
				case NamespaceRelationId:
					sepgsql_schema_post_create(objectId);
					break;

				case RelationRelationId:
					sepgsql_relation_post_create(objectId, subId);
					break;

				case ProcedureRelationId:
					sepgsql_proc_post_create(objectId);
					break;

				case LanguageRelationId:
					sepgsql_language_post_create(objectId);
					break;

				case LargeObjectRelationId:
					sepgsql_largeobject_post_create(objectId);
					break;

				default:
					/* ignore unsupported objects */
					break;
			}
			break;

		default:
			elog(ERROR, "unexpected object access type: %d", (int)access);
	}
}

/*
 * sepgsql_dml_privileges
 *
 * Entrypoint of DML permissions (SELECT, UPDATE, INSERT and DELETE).
 */
static bool
sepgsql_dml_privileges(List *rangeTabls, bool abort)
{
	bool	result_next = true;

	if (ExecutorCheckPerms_next)
		result = (*ExecutorCheckPerms_next)(rangeTabls, abort);

	if (!sepgsql_relation_privileges(rangeTabls, abort))
		return false;

	return result;
}

static bool
sepgsql_needs_function_call(Oid functionId)
{
	if (needs_function_call_next &&
		(*needs_function_call_next)(functionId))
		return true;

	return sepgsql_is_trusted_proc(functionId);
}

static void
sepgsql_function_call(FunctionCallEventType event,
					  FmgrInfo *flinfo, Datum *private)
{
	struct {
		char   *old_label;
		char   *new_label;
		Datum	next_private;
	} *stack;
	MemoryContext  *oldcxt;

	if (function_call_next)
		(*function_call_next)(event, flinfo, private);

	switch (event)
	{
		case FCET_PREPARE:
			oldcxt = MemoryContextSwitchTo(flinfo->fn_mcxt);
			stack = palloc(sizeof(*stack));
			stack->old_label = NULL;
			stack->new_label = sepgsql_get_trusted_proc(flinfo->fn_oid);
			stack->next_private = 0;
			MemoryContextSwitchTo(oldcxt);

			if (function_call_next)
				(*function_call_next)(event, flinfo, &stack->next_private);
			*private = PointerGetDatum(stack);
			break;

		case FCET_START:
			stack = (void *)DatumGetPointer(*private);
			Assert(!stack->old_label);
			stack->old_label = sepgsql_set_client_label(stack->new_label);
			break;

		case FCET_END:
		case FCET_ABORT:
			stack = (void *)DatumGetPointer(*private);
			sepgsql_set_client_label(stack->old_label);
			stack->old_label = NULL;
			break;

		default:
			elog(ERROR, "unexpected event type: %d", (int)event);
			break;
	}
}

void
sepgsql_register_hooks(void)
{
	/* security label provider hook */
	register_object_relabel_hook(SEPGSQL_LABEL_TAG,
								 sepgsql_object_relabel);

	/* client authentication hook */
	ClientAuthentication_next = ClientAuthentication_hook;
	ClientAuthentication_hook = sepgsql_client_authorization;

	/* object access hook */
	object_access_next = object_access_hook;
	object_access_hook = sepgsql_object_access;

	/* dml permission hook */
	ExecutorCheckPerms_next = ExecutorCheckPerms_hook;
	ExecutorCheckPerms_hook = sepgsql_dml_privileges;

	/* trusted procedure hook */

}
