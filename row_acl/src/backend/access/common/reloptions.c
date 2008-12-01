/*-------------------------------------------------------------------------
 *
 * reloptions.c
 *	  Core support for relation options (pg_class.reloptions)
 *
 * Portions Copyright (c) 1996-2008, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  $PostgreSQL: pgsql/src/backend/access/common/reloptions.c,v 1.11 2008/07/23 17:29:53 tgl Exp $
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/reloptions.h"
#include "catalog/pg_type.h"
#include "commands/defrem.h"
#include "nodes/makefuncs.h"
#include "security/pgace.h"
#include "utils/array.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/rel.h"


/*
 * Transform a relation options list (list of DefElem) into the text array
 * format that is kept in pg_class.reloptions.
 *
 * This is used for three cases: CREATE TABLE/INDEX, ALTER TABLE SET, and
 * ALTER TABLE RESET.  In the ALTER cases, oldOptions is the existing
 * reloptions value (possibly NULL), and we replace or remove entries
 * as needed.
 *
 * If ignoreOids is true, then we should ignore any occurrence of "oids"
 * in the list (it will be or has been handled by interpretOidsOption()).
 *
 * Note that this is not responsible for determining whether the options
 * are valid.
 *
 * Both oldOptions and the result are text arrays (or NULL for "default"),
 * but we declare them as Datums to avoid including array.h in reloptions.h.
 */
Datum
transformRelOptions(Datum oldOptions, List *defList,
					bool ignoreOids, bool isReset)
{
	Datum		result;
	ArrayBuildState *astate;
	ListCell   *cell;

	/* no change if empty list */
	if (defList == NIL)
		return oldOptions;

	/* We build new array using accumArrayResult */
	astate = NULL;

	/* Copy any oldOptions that aren't to be replaced */
	if (PointerIsValid(DatumGetPointer(oldOptions)))
	{
		ArrayType  *array = DatumGetArrayTypeP(oldOptions);
		Datum	   *oldoptions;
		int			noldoptions;
		int			i;

		Assert(ARR_ELEMTYPE(array) == TEXTOID);

		deconstruct_array(array, TEXTOID, -1, false, 'i',
						  &oldoptions, NULL, &noldoptions);

		for (i = 0; i < noldoptions; i++)
		{
			text	   *oldoption = DatumGetTextP(oldoptions[i]);
			char	   *text_str = VARDATA(oldoption);
			int			text_len = VARSIZE(oldoption) - VARHDRSZ;

			/* Search for a match in defList */
			foreach(cell, defList)
			{
				DefElem    *def = lfirst(cell);
				int			kw_len = strlen(def->defname);

				if (text_len > kw_len && text_str[kw_len] == '=' &&
					pg_strncasecmp(text_str, def->defname, kw_len) == 0)
					break;
			}
			if (!cell)
			{
				/* No match, so keep old option */
				astate = accumArrayResult(astate, oldoptions[i],
										  false, TEXTOID,
										  CurrentMemoryContext);
			}
		}
	}

	/*
	 * If CREATE/SET, add new options to array; if RESET, just check that the
	 * user didn't say RESET (option=val).  (Must do this because the grammar
	 * doesn't enforce it.)
	 */
	foreach(cell, defList)
	{
		DefElem    *def = lfirst(cell);

		pgaceGramTransformRelOptions(def, isReset);

		if (isReset)
		{
			if (def->arg != NULL)
				ereport(ERROR,
						(errcode(ERRCODE_SYNTAX_ERROR),
					errmsg("RESET must not include values for parameters")));
		}
		else
		{
			text	   *t;
			const char *value;
			Size		len;

			if (ignoreOids && pg_strcasecmp(def->defname, "oids") == 0)
				continue;

			/*
			 * Flatten the DefElem into a text string like "name=arg". If we
			 * have just "name", assume "name=true" is meant.
			 */
			if (def->arg != NULL)
				value = defGetString(def);
			else
				value = "true";
			len = VARHDRSZ + strlen(def->defname) + 1 + strlen(value);
			/* +1 leaves room for sprintf's trailing null */
			t = (text *) palloc(len + 1);
			SET_VARSIZE(t, len);
			sprintf(VARDATA(t), "%s=%s", def->defname, value);

			astate = accumArrayResult(astate, PointerGetDatum(t),
									  false, TEXTOID,
									  CurrentMemoryContext);
		}
	}

	if (astate)
		result = makeArrayResult(astate, CurrentMemoryContext);
	else
		result = (Datum) 0;

	return result;
}


/*
 * Convert the text-array format of reloptions into a List of DefElem.
 * This is the inverse of transformRelOptions().
 */
List *
untransformRelOptions(Datum options)
{
	List	   *result = NIL;
	ArrayType  *array;
	Datum	   *optiondatums;
	int			noptions;
	int			i;

	/* Nothing to do if no options */
	if (!PointerIsValid(DatumGetPointer(options)))
		return result;

	array = DatumGetArrayTypeP(options);

	Assert(ARR_ELEMTYPE(array) == TEXTOID);

	deconstruct_array(array, TEXTOID, -1, false, 'i',
					  &optiondatums, NULL, &noptions);

	for (i = 0; i < noptions; i++)
	{
		char	   *s;
		char	   *p;
		Node	   *val = NULL;

		s = TextDatumGetCString(optiondatums[i]);
		p = strchr(s, '=');
		if (p)
		{
			*p++ = '\0';
			val = (Node *) makeString(pstrdup(p));
		}
		result = lappend(result, makeDefElem(pstrdup(s), val));
	}

	return result;
}


/*
 * Interpret reloptions that are given in text-array format.
 *
 *	options: array of "keyword=value" strings, as built by transformRelOptions
 *	numkeywords: number of legal keywords
 *	keywords: the allowed keywords
 *	values: output area
 *	validate: if true, throw error for unrecognized keywords.
 *
 * The keywords and values arrays must both be of length numkeywords.
 * The values entry corresponding to a keyword is set to a palloc'd string
 * containing the corresponding value, or NULL if the keyword does not appear.
 */
void
parseRelOptions(Datum options, int numkeywords, const char *const * keywords,
				char **values, bool validate)
{
	ArrayType  *array;
	Datum	   *optiondatums;
	int			noptions;
	int			i;

	/* Initialize to "all defaulted" */
	MemSet(values, 0, numkeywords * sizeof(char *));

	/* Done if no options */
	if (!PointerIsValid(DatumGetPointer(options)))
		return;

	array = DatumGetArrayTypeP(options);

	Assert(ARR_ELEMTYPE(array) == TEXTOID);

	deconstruct_array(array, TEXTOID, -1, false, 'i',
					  &optiondatums, NULL, &noptions);

	for (i = 0; i < noptions; i++)
	{
		text	   *optiontext = DatumGetTextP(optiondatums[i]);
		char	   *text_str = VARDATA(optiontext);
		int			text_len = VARSIZE(optiontext) - VARHDRSZ;
		int			j;

		/* Search for a match in keywords */
		for (j = 0; j < numkeywords; j++)
		{
			int			kw_len = strlen(keywords[j]);

			if (text_len > kw_len && text_str[kw_len] == '=' &&
				pg_strncasecmp(text_str, keywords[j], kw_len) == 0)
			{
				char	   *value;
				int			value_len;

				if (values[j] && validate)
					ereport(ERROR,
							(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						  errmsg("parameter \"%s\" specified more than once",
								 keywords[j])));
				value_len = text_len - kw_len - 1;
				value = (char *) palloc(value_len + 1);
				memcpy(value, text_str + kw_len + 1, value_len);
				value[value_len] = '\0';
				values[j] = value;
				break;
			}
		}
		if (j >= numkeywords && validate)
		{
			char	   *s;
			char	   *p;

			s = TextDatumGetCString(optiondatums[i]);
			p = strchr(s, '=');
			if (p)
				*p = '\0';
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("unrecognized parameter \"%s\"", s)));
		}
	}
}

static bool
parse_fillfactor_reloption(const char *value, StdRdOptions *result, bool validate,
						   int minFillfactor, int defaultFillfactor)
{
	int fillfactor;

	/*
	 * Set default option
	 */
	result->fillfactor = defaultFillfactor;
	if (!value)
		return false;	/* no options */

	if (!parse_int(value, &fillfactor, 0, NULL))
	{
		if (validate)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("fillfactor must be an integer: \"%s\"", value)));
		return false;
	}

	if (fillfactor < minFillfactor || fillfactor > 100)
	{
		if (validate)
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("fillfactor=%d is out of range (should be between %d and 100)",
							fillfactor, minFillfactor)));
		return false;
	}

	result->fillfactor = fillfactor;

	return true;
}

/*
 * Parse reloptions for anything using StdRdOptions (ie, fillfactor only)
 */
bytea *
default_reloptions(Datum reloptions, bool validate,
				   int minFillfactor, int defaultFillfactor)
{
	static const char *const default_keywords[] = {
		"fillfactor",
#ifdef HAVE_ROW_ACL
		"row_level_acl",
		"default_row_acl",
#endif
	};
	char	   *values[lengthof(default_keywords)];
	int			index;
	bool		exist = false;
	StdRdOptions *result;

	parseRelOptions(reloptions,
					lengthof(default_keywords), default_keywords,
					values, validate);

	result = (StdRdOptions *) palloc0(sizeof(StdRdOptions));
	SET_VARSIZE(result, sizeof(StdRdOptions));

	for (index = 0; index < lengthof(default_keywords); index++)
	{
		if (strcmp("fillfactor", default_keywords[index]) == 0)
		{
			if (parse_fillfactor_reloption(values[index], result, validate,
										   minFillfactor, defaultFillfactor))
				exist = true;
		}
		else if (pgaceGramParseRelOptions(default_keywords[index],
										  values[index], result, validate))
		{
			exist = true;
		}
	}
	/*
	 * If no options, we can just return NULL rather than doing anything.
	 */
	if (exist == false)
	{
		pfree(result);
		return NULL;
	}

	return (bytea *) result;
}


/*
 * Parse options for heaps (and perhaps someday toast tables).
 */
bytea *
heap_reloptions(char relkind, Datum reloptions, bool validate)
{
	return default_reloptions(reloptions, validate,
							  HEAP_MIN_FILLFACTOR,
							  HEAP_DEFAULT_FILLFACTOR);
}


/*
 * Parse options for indexes.
 *
 *	amoptions	Oid of option parser
 *	reloptions	options as text[] datum
 *	validate	error flag
 */
bytea *
index_reloptions(RegProcedure amoptions, Datum reloptions, bool validate)
{
	FmgrInfo	flinfo;
	FunctionCallInfoData fcinfo;
	Datum		result;

	Assert(RegProcedureIsValid(amoptions));

	/* Assume function is strict */
	if (!PointerIsValid(DatumGetPointer(reloptions)))
		return NULL;

	/* Can't use OidFunctionCallN because we might get a NULL result */
	fmgr_info(amoptions, &flinfo);

	InitFunctionCallInfoData(fcinfo, &flinfo, 2, NULL, NULL);

	fcinfo.arg[0] = reloptions;
	fcinfo.arg[1] = BoolGetDatum(validate);
	fcinfo.argnull[0] = false;
	fcinfo.argnull[1] = false;

	result = FunctionCallInvoke(&fcinfo);

	if (fcinfo.isnull || DatumGetPointer(result) == NULL)
		return NULL;

	return DatumGetByteaP(result);
}
