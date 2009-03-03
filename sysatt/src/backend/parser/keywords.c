/*-------------------------------------------------------------------------
 *
 * keywords.c
 *	  lexical token lookup for key words in PostgreSQL
 *
 * NB: This file is also used by pg_dump.
 *
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  $PostgreSQL: pgsql/src/backend/parser/keywords.c,v 1.210 2009/02/24 10:06:33 petere Exp $
 *
 *-------------------------------------------------------------------------
 */

/* Use c.h so that this file can be built in either frontend or backend */
#include "c.h"

#include <ctype.h>

/*
 * This macro definition overrides the YYSTYPE union definition in gram.h.
 * We don't need that struct in this file, and including the real definition
 * would require sucking in some backend-only include files.
 */
#define YYSTYPE int

#include "parser/keywords.h"
#ifndef ECPG_COMPILE
#include "parser/gram.h"
#else
#include "preproc.h"
#endif

/*
 * List of keyword (name, token-value, category) entries.
 *
 * !!WARNING!!: This list must be sorted by ASCII name, because binary
 *		 search is used to locate entries.
 */
const ScanKeyword ScanKeywords[] = {
	/* name, value, category */
	{"abort", ABORT_P, UNRESERVED_KEYWORD},
	{"absolute", ABSOLUTE_P, UNRESERVED_KEYWORD},
	{"access", ACCESS, UNRESERVED_KEYWORD},
	{"action", ACTION, UNRESERVED_KEYWORD},
	{"add", ADD_P, UNRESERVED_KEYWORD},
	{"admin", ADMIN, UNRESERVED_KEYWORD},
	{"after", AFTER, UNRESERVED_KEYWORD},
	{"aggregate", AGGREGATE, UNRESERVED_KEYWORD},
	{"all", ALL, RESERVED_KEYWORD},
	{"also", ALSO, UNRESERVED_KEYWORD},
	{"alter", ALTER, UNRESERVED_KEYWORD},
	{"always", ALWAYS, UNRESERVED_KEYWORD},
	{"analyse", ANALYSE, RESERVED_KEYWORD},		/* British spelling */
	{"analyze", ANALYZE, RESERVED_KEYWORD},
	{"and", AND, RESERVED_KEYWORD},
	{"any", ANY, RESERVED_KEYWORD},
	{"array", ARRAY, RESERVED_KEYWORD},
	{"as", AS, RESERVED_KEYWORD},
	{"asc", ASC, RESERVED_KEYWORD},
	{"assertion", ASSERTION, UNRESERVED_KEYWORD},
	{"assignment", ASSIGNMENT, UNRESERVED_KEYWORD},
	{"asymmetric", ASYMMETRIC, RESERVED_KEYWORD},
	{"at", AT, UNRESERVED_KEYWORD},
	{"authorization", AUTHORIZATION, TYPE_FUNC_NAME_KEYWORD},
	{"backward", BACKWARD, UNRESERVED_KEYWORD},
	{"before", BEFORE, UNRESERVED_KEYWORD},
	{"begin", BEGIN_P, UNRESERVED_KEYWORD},
	{"between", BETWEEN, TYPE_FUNC_NAME_KEYWORD},
	{"bigint", BIGINT, COL_NAME_KEYWORD},
	{"binary", BINARY, TYPE_FUNC_NAME_KEYWORD},
	{"bit", BIT, COL_NAME_KEYWORD},
	{"boolean", BOOLEAN_P, COL_NAME_KEYWORD},
	{"both", BOTH, RESERVED_KEYWORD},
	{"by", BY, UNRESERVED_KEYWORD},
	{"cache", CACHE, UNRESERVED_KEYWORD},
	{"called", CALLED, UNRESERVED_KEYWORD},
	{"cascade", CASCADE, UNRESERVED_KEYWORD},
	{"cascaded", CASCADED, UNRESERVED_KEYWORD},
	{"case", CASE, RESERVED_KEYWORD},
	{"cast", CAST, RESERVED_KEYWORD},
	{"catalog", CATALOG_P, UNRESERVED_KEYWORD},
	{"chain", CHAIN, UNRESERVED_KEYWORD},
	{"char", CHAR_P, COL_NAME_KEYWORD},
	{"character", CHARACTER, COL_NAME_KEYWORD},
	{"characteristics", CHARACTERISTICS, UNRESERVED_KEYWORD},
	{"check", CHECK, RESERVED_KEYWORD},
	{"checkpoint", CHECKPOINT, UNRESERVED_KEYWORD},
	{"class", CLASS, UNRESERVED_KEYWORD},
	{"close", CLOSE, UNRESERVED_KEYWORD},
	{"cluster", CLUSTER, UNRESERVED_KEYWORD},
	{"coalesce", COALESCE, COL_NAME_KEYWORD},
	{"collate", COLLATE, RESERVED_KEYWORD},
	{"column", COLUMN, RESERVED_KEYWORD},
	{"comment", COMMENT, UNRESERVED_KEYWORD},
	{"commit", COMMIT, UNRESERVED_KEYWORD},
	{"committed", COMMITTED, UNRESERVED_KEYWORD},
	{"concurrently", CONCURRENTLY, UNRESERVED_KEYWORD},
	{"configuration", CONFIGURATION, UNRESERVED_KEYWORD},
	{"connection", CONNECTION, UNRESERVED_KEYWORD},
	{"constraint", CONSTRAINT, RESERVED_KEYWORD},
	{"constraints", CONSTRAINTS, UNRESERVED_KEYWORD},
	{"content", CONTENT_P, UNRESERVED_KEYWORD},
	{"continue", CONTINUE_P, UNRESERVED_KEYWORD},
	{"conversion", CONVERSION_P, UNRESERVED_KEYWORD},
	{"copy", COPY, UNRESERVED_KEYWORD},
	{"cost", COST, UNRESERVED_KEYWORD},
	{"create", CREATE, RESERVED_KEYWORD},
	{"createdb", CREATEDB, UNRESERVED_KEYWORD},
	{"createrole", CREATEROLE, UNRESERVED_KEYWORD},
	{"createuser", CREATEUSER, UNRESERVED_KEYWORD},
	{"cross", CROSS, TYPE_FUNC_NAME_KEYWORD},
	{"csv", CSV, UNRESERVED_KEYWORD},
	{"ctype", CTYPE, UNRESERVED_KEYWORD},
	{"current", CURRENT_P, UNRESERVED_KEYWORD},
	{"current_catalog", CURRENT_CATALOG, RESERVED_KEYWORD},
	{"current_date", CURRENT_DATE, RESERVED_KEYWORD},
	{"current_role", CURRENT_ROLE, RESERVED_KEYWORD},
	{"current_schema", CURRENT_SCHEMA, TYPE_FUNC_NAME_KEYWORD},
	{"current_time", CURRENT_TIME, RESERVED_KEYWORD},
	{"current_timestamp", CURRENT_TIMESTAMP, RESERVED_KEYWORD},
	{"current_user", CURRENT_USER, RESERVED_KEYWORD},
	{"cursor", CURSOR, UNRESERVED_KEYWORD},
	{"cycle", CYCLE, UNRESERVED_KEYWORD},
	{"data", DATA_P, UNRESERVED_KEYWORD},
	{"database", DATABASE, UNRESERVED_KEYWORD},
	{"day", DAY_P, UNRESERVED_KEYWORD},
	{"deallocate", DEALLOCATE, UNRESERVED_KEYWORD},
	{"dec", DEC, COL_NAME_KEYWORD},
	{"decimal", DECIMAL_P, COL_NAME_KEYWORD},
	{"declare", DECLARE, UNRESERVED_KEYWORD},
	{"default", DEFAULT, RESERVED_KEYWORD},
	{"defaults", DEFAULTS, UNRESERVED_KEYWORD},
	{"deferrable", DEFERRABLE, RESERVED_KEYWORD},
	{"deferred", DEFERRED, UNRESERVED_KEYWORD},
	{"definer", DEFINER, UNRESERVED_KEYWORD},
	{"delete", DELETE_P, UNRESERVED_KEYWORD},
	{"delimiter", DELIMITER, UNRESERVED_KEYWORD},
	{"delimiters", DELIMITERS, UNRESERVED_KEYWORD},
	{"desc", DESC, RESERVED_KEYWORD},
	{"dictionary", DICTIONARY, UNRESERVED_KEYWORD},
	{"disable", DISABLE_P, UNRESERVED_KEYWORD},
	{"discard", DISCARD, UNRESERVED_KEYWORD},
	{"distinct", DISTINCT, RESERVED_KEYWORD},
	{"do", DO, RESERVED_KEYWORD},
	{"document", DOCUMENT_P, UNRESERVED_KEYWORD},
	{"domain", DOMAIN_P, UNRESERVED_KEYWORD},
	{"double", DOUBLE_P, UNRESERVED_KEYWORD},
	{"drop", DROP, UNRESERVED_KEYWORD},
	{"each", EACH, UNRESERVED_KEYWORD},
	{"else", ELSE, RESERVED_KEYWORD},
	{"enable", ENABLE_P, UNRESERVED_KEYWORD},
	{"encoding", ENCODING, UNRESERVED_KEYWORD},
	{"encrypted", ENCRYPTED, UNRESERVED_KEYWORD},
	{"end", END_P, RESERVED_KEYWORD},
	{"enum", ENUM_P, UNRESERVED_KEYWORD},
	{"escape", ESCAPE, UNRESERVED_KEYWORD},
	{"except", EXCEPT, RESERVED_KEYWORD},
	{"excluding", EXCLUDING, UNRESERVED_KEYWORD},
	{"exclusive", EXCLUSIVE, UNRESERVED_KEYWORD},
	{"execute", EXECUTE, UNRESERVED_KEYWORD},
	{"exists", EXISTS, COL_NAME_KEYWORD},
	{"explain", EXPLAIN, UNRESERVED_KEYWORD},
	{"external", EXTERNAL, UNRESERVED_KEYWORD},
	{"extract", EXTRACT, COL_NAME_KEYWORD},
	{"false", FALSE_P, RESERVED_KEYWORD},
	{"family", FAMILY, UNRESERVED_KEYWORD},
	{"fetch", FETCH, RESERVED_KEYWORD},
	{"first", FIRST_P, UNRESERVED_KEYWORD},
	{"float", FLOAT_P, COL_NAME_KEYWORD},
	{"following", FOLLOWING, UNRESERVED_KEYWORD},
	{"for", FOR, RESERVED_KEYWORD},
	{"force", FORCE, UNRESERVED_KEYWORD},
	{"foreign", FOREIGN, RESERVED_KEYWORD},
	{"forward", FORWARD, UNRESERVED_KEYWORD},
	{"freeze", FREEZE, TYPE_FUNC_NAME_KEYWORD},
	{"from", FROM, RESERVED_KEYWORD},
	{"full", FULL, TYPE_FUNC_NAME_KEYWORD},
	{"function", FUNCTION, UNRESERVED_KEYWORD},
	{"global", GLOBAL, UNRESERVED_KEYWORD},
	{"grant", GRANT, RESERVED_KEYWORD},
	{"granted", GRANTED, UNRESERVED_KEYWORD},
	{"greatest", GREATEST, COL_NAME_KEYWORD},
	{"group", GROUP_P, RESERVED_KEYWORD},
	{"handler", HANDLER, UNRESERVED_KEYWORD},
	{"having", HAVING, RESERVED_KEYWORD},
	{"header", HEADER_P, UNRESERVED_KEYWORD},
	{"hold", HOLD, UNRESERVED_KEYWORD},
	{"hour", HOUR_P, UNRESERVED_KEYWORD},
	{"identity", IDENTITY_P, UNRESERVED_KEYWORD},
	{"if", IF_P, UNRESERVED_KEYWORD},
	{"ilike", ILIKE, TYPE_FUNC_NAME_KEYWORD},
	{"immediate", IMMEDIATE, UNRESERVED_KEYWORD},
	{"immutable", IMMUTABLE, UNRESERVED_KEYWORD},
	{"implicit", IMPLICIT_P, UNRESERVED_KEYWORD},
	{"in", IN_P, RESERVED_KEYWORD},
	{"including", INCLUDING, UNRESERVED_KEYWORD},
	{"increment", INCREMENT, UNRESERVED_KEYWORD},
	{"index", INDEX, UNRESERVED_KEYWORD},
	{"indexes", INDEXES, UNRESERVED_KEYWORD},
	{"inherit", INHERIT, UNRESERVED_KEYWORD},
	{"inherits", INHERITS, UNRESERVED_KEYWORD},
	{"initially", INITIALLY, RESERVED_KEYWORD},
	{"inner", INNER_P, TYPE_FUNC_NAME_KEYWORD},
	{"inout", INOUT, COL_NAME_KEYWORD},
	{"input", INPUT_P, UNRESERVED_KEYWORD},
	{"insensitive", INSENSITIVE, UNRESERVED_KEYWORD},
	{"insert", INSERT, UNRESERVED_KEYWORD},
	{"instead", INSTEAD, UNRESERVED_KEYWORD},
	{"int", INT_P, COL_NAME_KEYWORD},
	{"integer", INTEGER, COL_NAME_KEYWORD},
	{"intersect", INTERSECT, RESERVED_KEYWORD},
	{"interval", INTERVAL, COL_NAME_KEYWORD},
	{"into", INTO, RESERVED_KEYWORD},
	{"invoker", INVOKER, UNRESERVED_KEYWORD},
	{"is", IS, TYPE_FUNC_NAME_KEYWORD},
	{"isnull", ISNULL, TYPE_FUNC_NAME_KEYWORD},
	{"isolation", ISOLATION, UNRESERVED_KEYWORD},
	{"join", JOIN, TYPE_FUNC_NAME_KEYWORD},
	{"key", KEY, UNRESERVED_KEYWORD},
	{"lancompiler", LANCOMPILER, UNRESERVED_KEYWORD},
	{"language", LANGUAGE, UNRESERVED_KEYWORD},
	{"large", LARGE_P, UNRESERVED_KEYWORD},
	{"last", LAST_P, UNRESERVED_KEYWORD},
	{"leading", LEADING, RESERVED_KEYWORD},
	{"least", LEAST, COL_NAME_KEYWORD},
	{"left", LEFT, TYPE_FUNC_NAME_KEYWORD},
	{"level", LEVEL, UNRESERVED_KEYWORD},
	{"like", LIKE, TYPE_FUNC_NAME_KEYWORD},
	{"limit", LIMIT, RESERVED_KEYWORD},
	{"listen", LISTEN, UNRESERVED_KEYWORD},
	{"load", LOAD, UNRESERVED_KEYWORD},
	{"local", LOCAL, UNRESERVED_KEYWORD},
	{"localtime", LOCALTIME, RESERVED_KEYWORD},
	{"localtimestamp", LOCALTIMESTAMP, RESERVED_KEYWORD},
	{"location", LOCATION, UNRESERVED_KEYWORD},
	{"lock", LOCK_P, UNRESERVED_KEYWORD},
	{"login", LOGIN_P, UNRESERVED_KEYWORD},
	{"mapping", MAPPING, UNRESERVED_KEYWORD},
	{"match", MATCH, UNRESERVED_KEYWORD},
	{"maxvalue", MAXVALUE, UNRESERVED_KEYWORD},
	{"minute", MINUTE_P, UNRESERVED_KEYWORD},
	{"minvalue", MINVALUE, UNRESERVED_KEYWORD},
	{"mode", MODE, UNRESERVED_KEYWORD},
	{"month", MONTH_P, UNRESERVED_KEYWORD},
	{"move", MOVE, UNRESERVED_KEYWORD},
	{"name", NAME_P, UNRESERVED_KEYWORD},
	{"names", NAMES, UNRESERVED_KEYWORD},
	{"national", NATIONAL, COL_NAME_KEYWORD},
	{"natural", NATURAL, TYPE_FUNC_NAME_KEYWORD},
	{"nchar", NCHAR, COL_NAME_KEYWORD},
	{"new", NEW, RESERVED_KEYWORD},
	{"next", NEXT, UNRESERVED_KEYWORD},
	{"no", NO, UNRESERVED_KEYWORD},
	{"nocreatedb", NOCREATEDB, UNRESERVED_KEYWORD},
	{"nocreaterole", NOCREATEROLE, UNRESERVED_KEYWORD},
	{"nocreateuser", NOCREATEUSER, UNRESERVED_KEYWORD},
	{"noinherit", NOINHERIT, UNRESERVED_KEYWORD},
	{"nologin", NOLOGIN_P, UNRESERVED_KEYWORD},
	{"none", NONE, COL_NAME_KEYWORD},
	{"nosuperuser", NOSUPERUSER, UNRESERVED_KEYWORD},
	{"not", NOT, RESERVED_KEYWORD},
	{"nothing", NOTHING, UNRESERVED_KEYWORD},
	{"notify", NOTIFY, UNRESERVED_KEYWORD},
	{"notnull", NOTNULL, TYPE_FUNC_NAME_KEYWORD},
	{"nowait", NOWAIT, UNRESERVED_KEYWORD},
	{"null", NULL_P, RESERVED_KEYWORD},
	{"nullif", NULLIF, COL_NAME_KEYWORD},
	{"nulls", NULLS_P, UNRESERVED_KEYWORD},
	{"numeric", NUMERIC, COL_NAME_KEYWORD},
	{"object", OBJECT_P, UNRESERVED_KEYWORD},
	{"of", OF, UNRESERVED_KEYWORD},
	{"off", OFF, RESERVED_KEYWORD},
	{"offset", OFFSET, RESERVED_KEYWORD},
	{"oids", OIDS, UNRESERVED_KEYWORD},
	{"old", OLD, RESERVED_KEYWORD},
	{"on", ON, RESERVED_KEYWORD},
	{"only", ONLY, RESERVED_KEYWORD},
	{"operator", OPERATOR, UNRESERVED_KEYWORD},
	{"option", OPTION, UNRESERVED_KEYWORD},
	{"options", OPTIONS, UNRESERVED_KEYWORD},
	{"or", OR, RESERVED_KEYWORD},
	{"order", ORDER, RESERVED_KEYWORD},
	{"out", OUT_P, COL_NAME_KEYWORD},
	{"outer", OUTER_P, TYPE_FUNC_NAME_KEYWORD},
	{"over", OVER, TYPE_FUNC_NAME_KEYWORD},
	{"overlaps", OVERLAPS, TYPE_FUNC_NAME_KEYWORD},
	{"overlay", OVERLAY, COL_NAME_KEYWORD},
	{"owned", OWNED, UNRESERVED_KEYWORD},
	{"owner", OWNER, UNRESERVED_KEYWORD},
	{"parser", PARSER, UNRESERVED_KEYWORD},
	{"partial", PARTIAL, UNRESERVED_KEYWORD},
	{"partition", PARTITION, UNRESERVED_KEYWORD},
	{"password", PASSWORD, UNRESERVED_KEYWORD},
	{"placing", PLACING, RESERVED_KEYWORD},
	{"plans", PLANS, UNRESERVED_KEYWORD},
	{"position", POSITION, COL_NAME_KEYWORD},
	{"preceding", PRECEDING, UNRESERVED_KEYWORD},
	{"precision", PRECISION, COL_NAME_KEYWORD},
	{"prepare", PREPARE, UNRESERVED_KEYWORD},
	{"prepared", PREPARED, UNRESERVED_KEYWORD},
	{"preserve", PRESERVE, UNRESERVED_KEYWORD},
	{"primary", PRIMARY, RESERVED_KEYWORD},
	{"prior", PRIOR, UNRESERVED_KEYWORD},
	{"privileges", PRIVILEGES, UNRESERVED_KEYWORD},
	{"procedural", PROCEDURAL, UNRESERVED_KEYWORD},
	{"procedure", PROCEDURE, UNRESERVED_KEYWORD},
	{"quote", QUOTE, UNRESERVED_KEYWORD},
	{"range", RANGE, UNRESERVED_KEYWORD},
	{"read", READ, UNRESERVED_KEYWORD},
	{"real", REAL, COL_NAME_KEYWORD},
	{"reassign", REASSIGN, UNRESERVED_KEYWORD},
	{"recheck", RECHECK, UNRESERVED_KEYWORD},
	{"recursive", RECURSIVE, UNRESERVED_KEYWORD},
	{"references", REFERENCES, RESERVED_KEYWORD},
	{"reindex", REINDEX, UNRESERVED_KEYWORD},
	{"relative", RELATIVE_P, UNRESERVED_KEYWORD},
	{"release", RELEASE, UNRESERVED_KEYWORD},
	{"rename", RENAME, UNRESERVED_KEYWORD},
	{"repeatable", REPEATABLE, UNRESERVED_KEYWORD},
	{"replace", REPLACE, UNRESERVED_KEYWORD},
	{"replica", REPLICA, UNRESERVED_KEYWORD},
	{"reset", RESET, UNRESERVED_KEYWORD},
	{"restart", RESTART, UNRESERVED_KEYWORD},
	{"restrict", RESTRICT, UNRESERVED_KEYWORD},
	{"returning", RETURNING, RESERVED_KEYWORD},
	{"returns", RETURNS, UNRESERVED_KEYWORD},
	{"revoke", REVOKE, UNRESERVED_KEYWORD},
	{"right", RIGHT, TYPE_FUNC_NAME_KEYWORD},
	{"role", ROLE, UNRESERVED_KEYWORD},
	{"rollback", ROLLBACK, UNRESERVED_KEYWORD},
	{"row", ROW, COL_NAME_KEYWORD},
	{"rows", ROWS, UNRESERVED_KEYWORD},
	{"rule", RULE, UNRESERVED_KEYWORD},
	{"savepoint", SAVEPOINT, UNRESERVED_KEYWORD},
	{"schema", SCHEMA, UNRESERVED_KEYWORD},
	{"scroll", SCROLL, UNRESERVED_KEYWORD},
	{"search", SEARCH, UNRESERVED_KEYWORD},
	{"second", SECOND_P, UNRESERVED_KEYWORD},
	{"security", SECURITY, UNRESERVED_KEYWORD},
	{"select", SELECT, RESERVED_KEYWORD},
	{"sequence", SEQUENCE, UNRESERVED_KEYWORD},
	{"serializable", SERIALIZABLE, UNRESERVED_KEYWORD},
	{"server", SERVER, UNRESERVED_KEYWORD},
	{"session", SESSION, UNRESERVED_KEYWORD},
	{"session_user", SESSION_USER, RESERVED_KEYWORD},
	{"set", SET, UNRESERVED_KEYWORD},
	{"setof", SETOF, COL_NAME_KEYWORD},
	{"share", SHARE, UNRESERVED_KEYWORD},
	{"show", SHOW, UNRESERVED_KEYWORD},
	{"similar", SIMILAR, TYPE_FUNC_NAME_KEYWORD},
	{"simple", SIMPLE, UNRESERVED_KEYWORD},
	{"smallint", SMALLINT, COL_NAME_KEYWORD},
	{"some", SOME, RESERVED_KEYWORD},
	{"stable", STABLE, UNRESERVED_KEYWORD},
	{"standalone", STANDALONE_P, UNRESERVED_KEYWORD},
	{"start", START, UNRESERVED_KEYWORD},
	{"statement", STATEMENT, UNRESERVED_KEYWORD},
	{"statistics", STATISTICS, UNRESERVED_KEYWORD},
	{"stdin", STDIN, UNRESERVED_KEYWORD},
	{"stdout", STDOUT, UNRESERVED_KEYWORD},
	{"storage", STORAGE, UNRESERVED_KEYWORD},
	{"strict", STRICT_P, UNRESERVED_KEYWORD},
	{"strip", STRIP_P, UNRESERVED_KEYWORD},
	{"substring", SUBSTRING, COL_NAME_KEYWORD},
	{"superuser", SUPERUSER_P, UNRESERVED_KEYWORD},
	{"symmetric", SYMMETRIC, RESERVED_KEYWORD},
	{"sysid", SYSID, UNRESERVED_KEYWORD},
	{"system", SYSTEM_P, UNRESERVED_KEYWORD},
	{"table", TABLE, RESERVED_KEYWORD},
	{"tablespace", TABLESPACE, UNRESERVED_KEYWORD},
	{"temp", TEMP, UNRESERVED_KEYWORD},
	{"template", TEMPLATE, UNRESERVED_KEYWORD},
	{"temporary", TEMPORARY, UNRESERVED_KEYWORD},
	{"text", TEXT_P, UNRESERVED_KEYWORD},
	{"then", THEN, RESERVED_KEYWORD},
	{"time", TIME, COL_NAME_KEYWORD},
	{"timestamp", TIMESTAMP, COL_NAME_KEYWORD},
	{"to", TO, RESERVED_KEYWORD},
	{"trailing", TRAILING, RESERVED_KEYWORD},
	{"transaction", TRANSACTION, UNRESERVED_KEYWORD},
	{"treat", TREAT, COL_NAME_KEYWORD},
	{"trigger", TRIGGER, UNRESERVED_KEYWORD},
	{"trim", TRIM, COL_NAME_KEYWORD},
	{"true", TRUE_P, RESERVED_KEYWORD},
	{"truncate", TRUNCATE, UNRESERVED_KEYWORD},
	{"trusted", TRUSTED, UNRESERVED_KEYWORD},
	{"type", TYPE_P, UNRESERVED_KEYWORD},
	{"unbounded", UNBOUNDED, UNRESERVED_KEYWORD},
	{"uncommitted", UNCOMMITTED, UNRESERVED_KEYWORD},
	{"unencrypted", UNENCRYPTED, UNRESERVED_KEYWORD},
	{"union", UNION, RESERVED_KEYWORD},
	{"unique", UNIQUE, RESERVED_KEYWORD},
	{"unknown", UNKNOWN, UNRESERVED_KEYWORD},
	{"unlisten", UNLISTEN, UNRESERVED_KEYWORD},
	{"until", UNTIL, UNRESERVED_KEYWORD},
	{"update", UPDATE, UNRESERVED_KEYWORD},
	{"user", USER, RESERVED_KEYWORD},
	{"using", USING, RESERVED_KEYWORD},
	{"vacuum", VACUUM, UNRESERVED_KEYWORD},
	{"valid", VALID, UNRESERVED_KEYWORD},
	{"validator", VALIDATOR, UNRESERVED_KEYWORD},
	{"value", VALUE_P, UNRESERVED_KEYWORD},
	{"values", VALUES, COL_NAME_KEYWORD},
	{"varchar", VARCHAR, COL_NAME_KEYWORD},
	{"variadic", VARIADIC, RESERVED_KEYWORD},
	{"varying", VARYING, UNRESERVED_KEYWORD},
	{"verbose", VERBOSE, TYPE_FUNC_NAME_KEYWORD},
	{"version", VERSION_P, UNRESERVED_KEYWORD},
	{"view", VIEW, UNRESERVED_KEYWORD},
	{"volatile", VOLATILE, UNRESERVED_KEYWORD},
	{"when", WHEN, RESERVED_KEYWORD},
	{"where", WHERE, RESERVED_KEYWORD},
	{"whitespace", WHITESPACE_P, UNRESERVED_KEYWORD},
	{"window", WINDOW, RESERVED_KEYWORD},
	{"with", WITH, RESERVED_KEYWORD},
	{"without", WITHOUT, UNRESERVED_KEYWORD},
	{"work", WORK, UNRESERVED_KEYWORD},
	{"wrapper", WRAPPER, UNRESERVED_KEYWORD},
	{"write", WRITE, UNRESERVED_KEYWORD},
	{"xml", XML_P, UNRESERVED_KEYWORD},
	{"xmlattributes", XMLATTRIBUTES, COL_NAME_KEYWORD},
	{"xmlconcat", XMLCONCAT, COL_NAME_KEYWORD},
	{"xmlelement", XMLELEMENT, COL_NAME_KEYWORD},
	{"xmlforest", XMLFOREST, COL_NAME_KEYWORD},
	{"xmlparse", XMLPARSE, COL_NAME_KEYWORD},
	{"xmlpi", XMLPI, COL_NAME_KEYWORD},
	{"xmlroot", XMLROOT, COL_NAME_KEYWORD},
	{"xmlserialize", XMLSERIALIZE, COL_NAME_KEYWORD},
	{"year", YEAR_P, UNRESERVED_KEYWORD},
	{"yes", YES_P, UNRESERVED_KEYWORD},
	{"zone", ZONE, UNRESERVED_KEYWORD},
};

/* End of ScanKeywords, for use elsewhere */
const ScanKeyword *LastScanKeyword = endof(ScanKeywords);

/*
 * ScanKeywordLookup - see if a given word is a keyword
 *
 * Returns a pointer to the ScanKeyword table entry, or NULL if no match.
 *
 * The match is done case-insensitively.  Note that we deliberately use a
 * dumbed-down case conversion that will only translate 'A'-'Z' into 'a'-'z',
 * even if we are in a locale where tolower() would produce more or different
 * translations.  This is to conform to the SQL99 spec, which says that
 * keywords are to be matched in this way even though non-keyword identifiers
 * receive a different case-normalization mapping.
 */
const ScanKeyword *
ScanKeywordLookup(const char *text)
{
	int			len,
				i;
	char		word[NAMEDATALEN];
	const ScanKeyword *low;
	const ScanKeyword *high;

	len = strlen(text);
	/* We assume all keywords are shorter than NAMEDATALEN. */
	if (len >= NAMEDATALEN)
		return NULL;

	/*
	 * Apply an ASCII-only downcasing.	We must not use tolower() since it may
	 * produce the wrong translation in some locales (eg, Turkish).
	 */
	for (i = 0; i < len; i++)
	{
		char		ch = text[i];

		if (ch >= 'A' && ch <= 'Z')
			ch += 'a' - 'A';
		word[i] = ch;
	}
	word[len] = '\0';

	/*
	 * Now do a binary search using plain strcmp() comparison.
	 */
	low = &ScanKeywords[0];
	high = endof(ScanKeywords) - 1;
	while (low <= high)
	{
		const ScanKeyword *middle;
		int			difference;

		middle = low + (high - low) / 2;
		difference = strcmp(middle->name, word);
		if (difference == 0)
			return middle;
		else if (difference < 0)
			low = middle + 1;
		else
			high = middle - 1;
	}

	return NULL;
}