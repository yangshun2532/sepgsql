%{

/*#define YYDEBUG 1*/
/*-------------------------------------------------------------------------
 *
 * gram.y
 *	  POSTGRES SQL YACC rules/actions
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  $PostgreSQL: pgsql/src/backend/parser/gram.y,v 2.659 2009/02/24 10:06:33 petere Exp $
 *
 * HISTORY
 *	  AUTHOR			DATE			MAJOR EVENT
 *	  Andrew Yu			Sept, 1994		POSTQUEL to SQL conversion
 *	  Andrew Yu			Oct, 1994		lispy code conversion
 *
 * NOTES
 *	  CAPITALS are used to represent terminal symbols.
 *	  non-capitals are used to represent non-terminals.
 *	  SQL92-specific syntax is separated from plain SQL/Postgres syntax
 *	  to help isolate the non-extensible portions of the parser.
 *
 *	  In general, nothing in this file should initiate database accesses
 *	  nor depend on changeable state (such as SET variables).  If you do
 *	  database accesses, your code will fail when we have aborted the
 *	  current transaction and are just parsing commands to find the next
 *	  ROLLBACK or COMMIT.  If you make use of SET variables, then you
 *	  will do the wrong thing in multi-query strings like this:
 *			SET SQL_inheritance TO off; SELECT * FROM foo;
 *	  because the entire string is parsed by gram.y before the SET gets
 *	  executed.  Anything that depends on the database or changeable state
 *	  should be handled during parse analysis so that it happens at the
 *	  right time not the wrong time.  The handling of SQL_inheritance is
 *	  a good example.
 *
 * WARNINGS
 *	  If you use a list, make sure the datum is a node so that the printing
 *	  routines work.
 *
 *	  Sometimes we assign constants to makeStrings. Make sure we don't free
 *	  those.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <ctype.h>
#include <limits.h>

#include "catalog/index.h"
#include "catalog/namespace.h"
#include "commands/defrem.h"
#include "nodes/makefuncs.h"
#include "nodes/nodeFuncs.h"
#include "parser/gramparse.h"
#include "security/sepgsql.h"
#include "storage/lmgr.h"
#include "utils/date.h"
#include "utils/datetime.h"
#include "utils/numeric.h"
#include "utils/xml.h"


/* Location tracking support --- simpler than bison's default */
#define YYLLOC_DEFAULT(Current, Rhs, N) \
	do { \
		if (N) \
			(Current) = (Rhs)[1]; \
		else \
			(Current) = (Rhs)[0]; \
	} while (0)

/*
 * The %name-prefix option below will make bison call base_yylex, but we
 * really want it to call filtered_base_yylex (see parser.c).
 */
#define base_yylex filtered_base_yylex

/*
 * Bison doesn't allocate anything that needs to live across parser calls,
 * so we can easily have it use palloc instead of malloc.  This prevents
 * memory leaks if we error out during parsing.  Note this only works with
 * bison >= 2.0.  However, in bison 1.875 the default is to use alloca()
 * if possible, so there's not really much problem anyhow, at least if
 * you're building with gcc.
 */
#define YYMALLOC palloc
#define YYFREE   pfree

extern List *parsetree;			/* final parse result is delivered here */

static bool QueryIsRule = FALSE;

/* Private struct for the result of privilege_target production */
typedef struct PrivTarget
{
	GrantObjectType objtype;
	List	   *objs;
} PrivTarget;

/*
 * If you need access to certain yacc-generated variables and find that
 * they're static by default, uncomment the next line.  (this is not a
 * problem, yet.)
 */
/*#define __YYSCLASS*/

static Node *makeColumnRef(char *colname, List *indirection, int location);
static Node *makeTypeCast(Node *arg, TypeName *typename, int location);
static Node *makeStringConst(char *str, int location);
static Node *makeStringConstCast(char *str, int location, TypeName *typename);
static Node *makeIntConst(int val, int location);
static Node *makeFloatConst(char *str, int location);
static Node *makeBitStringConst(char *str, int location);
static Node *makeNullAConst(int location);
static Node *makeAConst(Value *v, int location);
static Node *makeBoolAConst(bool state, int location);
static FuncCall *makeOverlaps(List *largs, List *rargs, int location);
static void check_qualified_name(List *names);
static List *check_func_name(List *names);
static List *check_indirection(List *indirection);
static List *extractArgTypes(List *parameters);
static SelectStmt *findLeftmostSelect(SelectStmt *node);
static void insertSelectOptions(SelectStmt *stmt,
								List *sortClause, List *lockingClause,
								Node *limitOffset, Node *limitCount,
								WithClause *withClause);
static Node *makeSetOp(SetOperation op, bool all, Node *larg, Node *rarg);
static Node *doNegate(Node *n, int location);
static void doNegateFloat(Value *v);
static Node *makeAArrayExpr(List *elements, int location);
static Node *makeXmlExpr(XmlExprOp op, char *name, List *named_args,
						 List *args, int location);
static List *mergeTableFuncParameters(List *func_args, List *columns);
static TypeName *TableFuncTypeName(List *columns);

%}

%expect 0
%name-prefix="base_yy"
%locations

%union
{
	int					ival;
	char				chr;
	char				*str;
	const char			*keyword;
	bool				boolean;
	JoinType			jtype;
	DropBehavior		dbehavior;
	OnCommitAction		oncommit;
	List				*list;
	Node				*node;
	Value				*value;
	ObjectType			objtype;

	TypeName			*typnam;
	FunctionParameter   *fun_param;
	FunctionParameterMode fun_param_mode;
	FuncWithArgs		*funwithargs;
	DefElem				*defelt;
	OptionDefElem		*optdef;
	ReloptElem			*reloptel;
	SortBy				*sortby;
	WindowDef			*windef;
	JoinExpr			*jexpr;
	IndexElem			*ielem;
	Alias				*alias;
	RangeVar			*range;
	IntoClause			*into;
	WithClause			*with;
	A_Indices			*aind;
	ResTarget			*target;
	struct PrivTarget	*privtarget;
	AccessPriv			*accesspriv;

	InsertStmt			*istmt;
	VariableSetStmt		*vsetstmt;
}

%type <node>	stmt schema_stmt
		AlterDatabaseStmt AlterDatabaseSetStmt AlterDomainStmt AlterFdwStmt
		AlterForeignServerStmt AlterGroupStmt
		AlterObjectSchemaStmt AlterOwnerStmt AlterSeqStmt AlterTableStmt
		AlterUserStmt AlterUserMappingStmt AlterUserSetStmt AlterRoleStmt AlterRoleSetStmt
		AnalyzeStmt ClosePortalStmt ClusterStmt CommentStmt
		ConstraintsSetStmt CopyStmt CreateAsStmt CreateCastStmt
		CreateDomainStmt CreateGroupStmt CreateOpClassStmt
		CreateOpFamilyStmt AlterOpFamilyStmt CreatePLangStmt
		CreateSchemaStmt CreateSeqStmt CreateStmt CreateTableSpaceStmt
		CreateFdwStmt CreateForeignServerStmt CreateAssertStmt CreateTrigStmt
		CreateUserStmt CreateUserMappingStmt CreateRoleStmt
		CreatedbStmt DeclareCursorStmt DefineStmt DeleteStmt DiscardStmt
		DropGroupStmt DropOpClassStmt DropOpFamilyStmt DropPLangStmt DropStmt
		DropAssertStmt DropTrigStmt DropRuleStmt DropCastStmt DropRoleStmt
		DropUserStmt DropdbStmt DropTableSpaceStmt DropFdwStmt
		DropForeignServerStmt DropUserMappingStmt ExplainStmt FetchStmt
		GrantStmt GrantRoleStmt IndexStmt InsertStmt ListenStmt LoadStmt
		LockStmt NotifyStmt ExplainableStmt PreparableStmt
		CreateFunctionStmt AlterFunctionStmt ReindexStmt RemoveAggrStmt
		RemoveFuncStmt RemoveOperStmt RenameStmt RevokeStmt RevokeRoleStmt
		RuleActionStmt RuleActionStmtOrEmpty RuleStmt
		SelectStmt TransactionStmt TruncateStmt
		UnlistenStmt UpdateStmt VacuumStmt
		VariableResetStmt VariableSetStmt VariableShowStmt
		ViewStmt CheckPointStmt CreateConversionStmt
		DeallocateStmt PrepareStmt ExecuteStmt
		DropOwnedStmt ReassignOwnedStmt
		AlterTSConfigurationStmt AlterTSDictionaryStmt

%type <node>	select_no_parens select_with_parens select_clause
				simple_select values_clause

%type <node>	alter_column_default opclass_item opclass_drop alter_using
%type <ival>	add_drop opt_asc_desc opt_nulls_order

%type <node>	alter_table_cmd
%type <list>	alter_table_cmds

%type <dbehavior>	opt_drop_behavior

%type <list>	createdb_opt_list alterdb_opt_list copy_opt_list
				transaction_mode_list
%type <defelt>	createdb_opt_item alterdb_opt_item copy_opt_item
				transaction_mode_item

%type <ival>	opt_lock lock_type cast_context
%type <boolean>	opt_force opt_or_replace
				opt_grant_grant_option opt_grant_admin_option
				opt_nowait opt_if_exists opt_with_data

%type <list>	OptRoleList
%type <defelt>	OptRoleElem

%type <str>		opt_type
%type <str>		foreign_server_version opt_foreign_server_version
%type <str>		auth_ident

%type <str>		OptSchemaName
%type <list>	OptSchemaEltList

%type <boolean> TriggerActionTime TriggerForSpec opt_trusted opt_restart_seqs
%type <str>		opt_lancompiler

%type <str>		TriggerEvents
%type <value>	TriggerFuncArg

%type <str>		relation_name copy_file_name
				database_name access_method_clause access_method attr_name
				index_name name file_name cluster_index_specification

%type <list>	func_name handler_name qual_Op qual_all_Op subquery_Op
				opt_class opt_validator validator_clause

%type <range>	qualified_name OptConstrFromTable

%type <str>		all_Op MathOp SpecialRuleRelation

%type <str>		iso_level opt_encoding
%type <node>	grantee
%type <list>	grantee_list
%type <accesspriv> privilege
%type <list>	privileges privilege_list
%type <privtarget> privilege_target
%type <funwithargs> function_with_argtypes
%type <list>	function_with_argtypes_list
%type <chr> 	TriggerOneEvent

%type <list>	stmtblock stmtmulti
				OptTableElementList TableElementList OptInherit definition
				reloptions opt_reloptions
				OptWith opt_distinct opt_definition func_args func_args_list
				func_args_with_defaults func_args_with_defaults_list
				func_as createfunc_opt_list alterfunc_opt_list
				aggr_args old_aggr_definition old_aggr_list
				oper_argtypes RuleActionList RuleActionMulti
				opt_column_list columnList opt_name_list
				sort_clause opt_sort_clause sortby_list index_params
				name_list from_clause from_list opt_array_bounds
				qualified_name_list any_name any_name_list
				any_operator expr_list attrs
				target_list insert_column_list set_target_list
				set_clause_list set_clause multiple_set_clause
				ctext_expr_list ctext_row def_list indirection opt_indirection
				reloption_list group_clause TriggerFuncArgs select_limit
				opt_select_limit opclass_item_list opclass_drop_list
				opt_opfamily transaction_mode_list_or_empty
				TableFuncElementList opt_type_modifiers
				prep_type_clause
				execute_param_clause using_clause returning_clause
				enum_val_list table_func_column_list
				create_generic_options alter_generic_options
				relation_expr_list

%type <range>	OptTempTableName
%type <into>	into_clause create_as_target

%type <defelt>	createfunc_opt_item common_func_opt_item
%type <fun_param> func_arg func_arg_with_default table_func_column
%type <fun_param_mode> arg_class
%type <typnam>	func_return func_type

%type <boolean>  TriggerForType OptTemp
%type <oncommit> OnCommitOption

%type <node>	for_locking_item
%type <list>	for_locking_clause opt_for_locking_clause for_locking_items
%type <list>	locked_rels_list
%type <boolean>	opt_all

%type <node>	join_outer join_qual
%type <jtype>	join_type

%type <list>	extract_list overlay_list position_list
%type <list>	substr_list trim_list
%type <list>	opt_interval interval_second
%type <node>	overlay_placing substr_from substr_for

%type <boolean> opt_instead opt_analyze
%type <boolean> index_opt_unique opt_verbose opt_full
%type <boolean> opt_freeze opt_default opt_recheck
%type <defelt>	opt_binary opt_oids copy_delimiter

%type <boolean> copy_from

%type <ival>	opt_column event cursor_options opt_hold opt_set_data
%type <objtype>	reindex_type drop_type comment_type

%type <node>	fetch_direction select_limit_value select_offset_value
				select_offset_value2 opt_select_fetch_first_value
%type <ival>	row_or_rows first_or_next

%type <list>	OptSeqOptList SeqOptList
%type <defelt>	SeqOptElem

%type <istmt>	insert_rest

%type <vsetstmt> set_rest SetResetClause

%type <node>	TableElement ConstraintElem TableFuncElement
%type <node>	columnDef
%type <defelt>	def_elem old_aggr_elem
%type <reloptel> reloption_elem
%type <node>	def_arg columnElem where_clause where_or_current_clause
				a_expr b_expr c_expr func_expr AexprConst indirection_el
				columnref in_expr having_clause func_table array_expr
%type <list>	row type_list array_expr_list
%type <node>	case_expr case_arg when_clause case_default
%type <list>	when_clause_list
%type <ival>	sub_type
%type <list>	OptCreateAs CreateAsList
%type <node>	CreateAsElement ctext_expr
%type <value>	NumericOnly
%type <alias>	alias_clause
%type <sortby>	sortby
%type <ielem>	index_elem
%type <node>	table_ref
%type <jexpr>	joined_table
%type <range>	relation_expr
%type <range>	relation_expr_opt_alias
%type <target>	target_el single_set_clause set_target insert_column_item

%type <str>		generic_option_name
%type <node>	generic_option_arg
%type <defelt>	generic_option_elem
%type <optdef>	alter_generic_option_elem
%type <list>	generic_option_list alter_generic_option_list

%type <typnam>	Typename SimpleTypename ConstTypename
				GenericType Numeric opt_float
				Character ConstCharacter
				CharacterWithLength CharacterWithoutLength
				ConstDatetime ConstInterval
				Bit ConstBit BitWithLength BitWithoutLength
%type <str>		character
%type <str>		extract_arg
%type <str>		opt_charset
%type <boolean> opt_varying opt_timezone

%type <ival>	Iconst SignedIconst
%type <str>		Sconst comment_text
%type <str>		RoleId opt_granted_by opt_boolean ColId_or_Sconst
%type <list>	var_list
%type <str>		ColId ColLabel var_name type_function_name param_name
%type <node>	var_value zone_value

%type <keyword> unreserved_keyword type_func_name_keyword
%type <keyword> col_name_keyword reserved_keyword

%type <node>	TableConstraint TableLikeClause
%type <list>	TableLikeOptionList
%type <ival>	TableLikeOption
%type <list>	ColQualList
%type <node>	ColConstraint ColConstraintElem ConstraintAttr
%type <ival>	key_actions key_delete key_match key_update key_action
%type <ival>	ConstraintAttributeSpec ConstraintDeferrabilitySpec
				ConstraintTimeSpec

%type <list>	constraints_set_list
%type <boolean> constraints_set_mode
%type <str>		OptTableSpace OptConsTableSpace OptTableSpaceOwner
%type <list>	opt_check_option

%type <defelt> OptSecurityItem SecurityItem

%type <target>	xml_attribute_el
%type <list>	xml_attribute_list xml_attributes
%type <node>	xml_root_version opt_xml_root_standalone
%type <ival>	document_or_content
%type <boolean> xml_whitespace_option

%type <node> 	common_table_expr
%type <with> 	with_clause
%type <list>	cte_list

%type <list>	window_clause window_definition_list opt_partition_clause
%type <windef>	window_definition over_clause window_specification
%type <str>		opt_existing_window_name
%type <ival>	opt_frame_clause frame_extent frame_bound


/*
 * If you make any token changes, update the keyword table in
 * parser/keywords.c and add new keywords to the appropriate one of
 * the reserved-or-not-so-reserved keyword lists, below; search
 * this file for "Name classification hierarchy".
 */

/* ordinary key words in alphabetical order */
%token <keyword> ABORT_P ABSOLUTE_P ACCESS ACTION ADD_P ADMIN AFTER
	AGGREGATE ALL ALSO ALTER ALWAYS ANALYSE ANALYZE AND ANY ARRAY AS ASC
	ASSERTION ASSIGNMENT ASYMMETRIC AT AUTHORIZATION

	BACKWARD BEFORE BEGIN_P BETWEEN BIGINT BINARY BIT
	BOOLEAN_P BOTH BY

	CACHE CALLED CASCADE CASCADED CASE CAST CATALOG_P CHAIN CHAR_P
	CHARACTER CHARACTERISTICS CHECK CHECKPOINT CLASS CLOSE
	CLUSTER COALESCE COLLATE COLUMN COMMENT COMMIT
	COMMITTED CONCURRENTLY CONFIGURATION CONNECTION CONSTRAINT CONSTRAINTS
	CONTENT_P CONTINUE_P CONVERSION_P COPY COST CREATE CREATEDB
	CREATEROLE CREATEUSER CROSS CSV CTYPE CURRENT_P
	CURRENT_CATALOG CURRENT_DATE CURRENT_ROLE CURRENT_SCHEMA
	CURRENT_TIME CURRENT_TIMESTAMP CURRENT_USER CURSOR CYCLE

	DATA_P DATABASE DAY_P DEALLOCATE DEC DECIMAL_P DECLARE DEFAULT DEFAULTS
	DEFERRABLE DEFERRED DEFINER DELETE_P DELIMITER DELIMITERS DESC
	DICTIONARY DISABLE_P DISCARD DISTINCT DO DOCUMENT_P DOMAIN_P DOUBLE_P DROP

	EACH ELSE ENABLE_P ENCODING ENCRYPTED END_P ENUM_P ESCAPE EXCEPT
	EXCLUDING EXCLUSIVE EXECUTE EXISTS EXPLAIN EXTERNAL EXTRACT

	FALSE_P FAMILY FETCH FIRST_P FLOAT_P FOLLOWING FOR FORCE FOREIGN FORWARD
	FREEZE FROM FULL FUNCTION

	GLOBAL GRANT GRANTED GREATEST GROUP_P

	HANDLER HAVING HEADER_P HOLD HOUR_P

	IDENTITY_P IF_P ILIKE IMMEDIATE IMMUTABLE IMPLICIT_P IN_P
	INCLUDING INCREMENT INDEX INDEXES INHERIT INHERITS INITIALLY
	INNER_P INOUT INPUT_P INSENSITIVE INSERT INSTEAD INT_P INTEGER
	INTERSECT INTERVAL INTO INVOKER IS ISNULL ISOLATION

	JOIN

	KEY

	LANCOMPILER LANGUAGE LARGE_P LAST_P LEADING LEAST LEFT LEVEL
	LIKE LIMIT LISTEN LOAD LOCAL LOCALTIME LOCALTIMESTAMP LOCATION
	LOCK_P LOGIN_P

	MAPPING MATCH MAXVALUE MINUTE_P MINVALUE MODE MONTH_P MOVE

	NAME_P NAMES NATIONAL NATURAL NCHAR NEW NEXT NO NOCREATEDB
	NOCREATEROLE NOCREATEUSER NOINHERIT NOLOGIN_P NONE NOSUPERUSER
	NOT NOTHING NOTIFY NOTNULL NOWAIT NULL_P NULLIF NULLS_P NUMERIC

	OBJECT_P OF OFF OFFSET OIDS OLD ON ONLY OPERATOR OPTION OPTIONS OR
	ORDER OUT_P OUTER_P OVER OVERLAPS OVERLAY OWNED OWNER

	PARSER PARTIAL PARTITION PASSWORD PLACING PLANS POSITION
	PRECEDING PRECISION PRESERVE PREPARE PREPARED PRIMARY
	PRIOR PRIVILEGES PROCEDURAL PROCEDURE

	QUOTE

	RANGE READ REAL REASSIGN RECHECK RECURSIVE REFERENCES REINDEX
	RELATIVE_P RELEASE RENAME REPEATABLE REPLACE REPLICA RESET RESTART
	RESTRICT RETURNING RETURNS REVOKE RIGHT ROLE ROLLBACK ROW ROWS RULE

	SAVEPOINT SCHEMA SCROLL SEARCH SECOND_P SECURITY SELECT SEQUENCE
	SERIALIZABLE SERVER SESSION SESSION_USER SET SETOF SHARE
	SHOW SIMILAR SIMPLE SMALLINT SOME STABLE STANDALONE_P START STATEMENT
	STATISTICS STDIN STDOUT STORAGE STRICT_P STRIP_P SUBSTRING SUPERUSER_P
	SYMMETRIC SYSID SYSTEM_P

	TABLE TABLESPACE TEMP TEMPLATE TEMPORARY TEXT_P THEN TIME TIMESTAMP
	TO TRAILING TRANSACTION TREAT TRIGGER TRIM TRUE_P
	TRUNCATE TRUSTED TYPE_P

	UNBOUNDED UNCOMMITTED UNENCRYPTED UNION UNIQUE UNKNOWN UNLISTEN UNTIL
	UPDATE USER USING

	VACUUM VALID VALIDATOR VALUE_P VALUES VARCHAR VARIADIC VARYING
	VERBOSE VERSION_P VIEW VOLATILE

	WHEN WHERE WHITESPACE_P WINDOW WITH WITHOUT WORK WRAPPER WRITE

	XML_P XMLATTRIBUTES XMLCONCAT XMLELEMENT XMLFOREST XMLPARSE
	XMLPI XMLROOT XMLSERIALIZE

	YEAR_P YES_P

	ZONE

/* The grammar thinks these are keywords, but they are not in the keywords.c
 * list and so can never be entered directly.  The filter in parser.c
 * creates these tokens when required.
 */
%token			NULLS_FIRST NULLS_LAST WITH_TIME

/* Special token types, not actually keywords - see the "lex" file */
%token <str>	IDENT FCONST SCONST BCONST XCONST Op
%token <ival>	ICONST PARAM

/* precedence: lowest to highest */
%nonassoc	SET				/* see relation_expr_opt_alias */
%left		UNION EXCEPT
%left		INTERSECT
%left		OR
%left		AND
%right		NOT
%right		'='
%nonassoc	'<' '>'
%nonassoc	LIKE ILIKE SIMILAR
%nonassoc	ESCAPE
%nonassoc	OVERLAPS
%nonassoc	BETWEEN
%nonassoc	IN_P
%left		POSTFIXOP		/* dummy for postfix Op rules */
/*
 * To support target_el without AS, we must give IDENT an explicit priority
 * between POSTFIXOP and Op.  We can safely assign the same priority to
 * various unreserved keywords as needed to resolve ambiguities (this can't
 * have any bad effects since obviously the keywords will still behave the
 * same as if they weren't keywords).  We need to do this for PARTITION,
 * RANGE, ROWS to support opt_existing_window_name; and for RANGE, ROWS
 * so that they can follow a_expr without creating
 * postfix-operator problems.
 */
%nonassoc	IDENT PARTITION RANGE ROWS
%left		Op OPERATOR		/* multi-character ops and user-defined operators */
%nonassoc	NOTNULL
%nonassoc	ISNULL
%nonassoc	IS NULL_P TRUE_P FALSE_P UNKNOWN /* sets precedence for IS NULL, etc */
%left		'+' '-'
%left		'*' '/' '%'
%left		'^'
/* Unary Operators */
%left		AT ZONE			/* sets precedence for AT TIME ZONE */
%right		UMINUS
%left		'[' ']'
%left		'(' ')'
%left		TYPECAST
%left		'.'
/*
 * These might seem to be low-precedence, but actually they are not part
 * of the arithmetic hierarchy at all in their use as JOIN operators.
 * We make them high-precedence to support their use as function names.
 * They wouldn't be given a precedence at all, were it not that we need
 * left-associativity among the JOIN rules themselves.
 */
%left		JOIN CROSS LEFT FULL RIGHT INNER_P NATURAL
/* kluge to keep xml_whitespace_option from causing shift/reduce conflicts */
%right		PRESERVE STRIP_P
%%

/*
 *	Handle comment-only lines, and ;; SELECT * FROM pg_class ;;;
 *	psql already handles such cases, but other interfaces don't.
 *	bjm 1999/10/05
 */
stmtblock:	stmtmulti								{ parsetree = $1; }
		;

/* the thrashing around here is to discard "empty" statements... */
stmtmulti:	stmtmulti ';' stmt
				{ if ($3 != NULL)
					$$ = lappend($1, $3);
				  else
					$$ = $1;
				}
			| stmt
					{ if ($1 != NULL)
						$$ = list_make1($1);
					  else
						$$ = NIL;
					}
		;

stmt :
			AlterDatabaseStmt
			| AlterDatabaseSetStmt
			| AlterDomainStmt
			| AlterFdwStmt
			| AlterForeignServerStmt
			| AlterFunctionStmt
			| AlterGroupStmt
			| AlterObjectSchemaStmt
			| AlterOwnerStmt
			| AlterSeqStmt
			| AlterTableStmt
			| AlterRoleSetStmt
			| AlterRoleStmt
			| AlterTSConfigurationStmt
			| AlterTSDictionaryStmt
			| AlterUserMappingStmt
			| AlterUserSetStmt
			| AlterUserStmt
			| AnalyzeStmt
			| CheckPointStmt
			| ClosePortalStmt
			| ClusterStmt
			| CommentStmt
			| ConstraintsSetStmt
			| CopyStmt
			| CreateAsStmt
			| CreateAssertStmt
			| CreateCastStmt
			| CreateConversionStmt
			| CreateDomainStmt
			| CreateFdwStmt
			| CreateForeignServerStmt
			| CreateFunctionStmt
			| CreateGroupStmt
			| CreateOpClassStmt
			| CreateOpFamilyStmt
			| AlterOpFamilyStmt
			| CreatePLangStmt
			| CreateSchemaStmt
			| CreateSeqStmt
			| CreateStmt
			| CreateTableSpaceStmt
			| CreateTrigStmt
			| CreateRoleStmt
			| CreateUserStmt
			| CreateUserMappingStmt
			| CreatedbStmt
			| DeallocateStmt
			| DeclareCursorStmt
			| DefineStmt
			| DeleteStmt
			| DiscardStmt
			| DropAssertStmt
			| DropCastStmt
			| DropFdwStmt
			| DropForeignServerStmt
			| DropGroupStmt
			| DropOpClassStmt
			| DropOpFamilyStmt
			| DropOwnedStmt
			| DropPLangStmt
			| DropRuleStmt
			| DropStmt
			| DropTableSpaceStmt
			| DropTrigStmt
			| DropRoleStmt
			| DropUserStmt
			| DropUserMappingStmt
			| DropdbStmt
			| ExecuteStmt
			| ExplainStmt
			| FetchStmt
			| GrantStmt
			| GrantRoleStmt
			| IndexStmt
			| InsertStmt
			| ListenStmt
			| LoadStmt
			| LockStmt
			| NotifyStmt
			| PrepareStmt
			| ReassignOwnedStmt
			| ReindexStmt
			| RemoveAggrStmt
			| RemoveFuncStmt
			| RemoveOperStmt
			| RenameStmt
			| RevokeStmt
			| RevokeRoleStmt
			| RuleStmt
			| SelectStmt
			| TransactionStmt
			| TruncateStmt
			| UnlistenStmt
			| UpdateStmt
			| VacuumStmt
			| VariableResetStmt
			| VariableSetStmt
			| VariableShowStmt
			| ViewStmt
			| /*EMPTY*/
				{ $$ = NULL; }
		;

/*****************************************************************************
 *
 * Create a new Postgres DBMS role
 *
 *****************************************************************************/

CreateRoleStmt:
			CREATE ROLE RoleId opt_with OptRoleList
				{
					CreateRoleStmt *n = makeNode(CreateRoleStmt);
					n->stmt_type = ROLESTMT_ROLE;
					n->role = $3;
					n->options = $5;
					$$ = (Node *)n;
				}
		;


opt_with:	WITH									{}
			| /*EMPTY*/								{}
		;

/*
 * Options for CREATE ROLE and ALTER ROLE (also used by CREATE/ALTER USER
 * for backwards compatibility).  Note: the only option required by SQL99
 * is "WITH ADMIN name".
 */
OptRoleList:
			OptRoleList OptRoleElem					{ $$ = lappend($1, $2); }
			| /* EMPTY */							{ $$ = NIL; }
		;

OptRoleElem:
			PASSWORD Sconst
				{
					$$ = makeDefElem("password",
									 (Node *)makeString($2));
				}
			| PASSWORD NULL_P
				{
					$$ = makeDefElem("password", NULL);
				}
			| ENCRYPTED PASSWORD Sconst
				{
					$$ = makeDefElem("encryptedPassword",
									 (Node *)makeString($3));
				}
			| UNENCRYPTED PASSWORD Sconst
				{
					$$ = makeDefElem("unencryptedPassword",
									 (Node *)makeString($3));
				}
			| SUPERUSER_P
				{
					$$ = makeDefElem("superuser", (Node *)makeInteger(TRUE));
				}
			| NOSUPERUSER
				{
					$$ = makeDefElem("superuser", (Node *)makeInteger(FALSE));
				}
			| INHERIT
				{
					$$ = makeDefElem("inherit", (Node *)makeInteger(TRUE));
				}
			| NOINHERIT
				{
					$$ = makeDefElem("inherit", (Node *)makeInteger(FALSE));
				}
			| CREATEDB
				{
					$$ = makeDefElem("createdb", (Node *)makeInteger(TRUE));
				}
			| NOCREATEDB
				{
					$$ = makeDefElem("createdb", (Node *)makeInteger(FALSE));
				}
			| CREATEROLE
				{
					$$ = makeDefElem("createrole", (Node *)makeInteger(TRUE));
				}
			| NOCREATEROLE
				{
					$$ = makeDefElem("createrole", (Node *)makeInteger(FALSE));
				}
			| CREATEUSER
				{
					/* For backwards compatibility, synonym for SUPERUSER */
					$$ = makeDefElem("superuser", (Node *)makeInteger(TRUE));
				}
			| NOCREATEUSER
				{
					$$ = makeDefElem("superuser", (Node *)makeInteger(FALSE));
				}
			| LOGIN_P
				{
					$$ = makeDefElem("canlogin", (Node *)makeInteger(TRUE));
				}
			| NOLOGIN_P
				{
					$$ = makeDefElem("canlogin", (Node *)makeInteger(FALSE));
				}
			| CONNECTION LIMIT SignedIconst
				{
					$$ = makeDefElem("connectionlimit", (Node *)makeInteger($3));
				}
			| VALID UNTIL Sconst
				{
					$$ = makeDefElem("validUntil", (Node *)makeString($3));
				}
		/*	Supported but not documented for roles, for use by ALTER GROUP. */
			| USER name_list
				{
					$$ = makeDefElem("rolemembers", (Node *)$2);
				}
		/* The following are not supported by ALTER ROLE/USER/GROUP */
			| SYSID Iconst
				{
					$$ = makeDefElem("sysid", (Node *)makeInteger($2));
				}
			| ADMIN name_list
				{
					$$ = makeDefElem("adminmembers", (Node *)$2);
				}
			| ROLE name_list
				{
					$$ = makeDefElem("rolemembers", (Node *)$2);
				}
			| IN_P ROLE name_list
				{
					$$ = makeDefElem("addroleto", (Node *)$3);
				}
			| IN_P GROUP_P name_list
				{
					$$ = makeDefElem("addroleto", (Node *)$3);
				}
		;


/*****************************************************************************
 *
 * Create a new Postgres DBMS user (role with implied login ability)
 *
 *****************************************************************************/

CreateUserStmt:
			CREATE USER RoleId opt_with OptRoleList
				{
					CreateRoleStmt *n = makeNode(CreateRoleStmt);
					n->stmt_type = ROLESTMT_USER;
					n->role = $3;
					n->options = $5;
					$$ = (Node *)n;
				}
		;


/*****************************************************************************
 *
 * Alter a postgresql DBMS role
 *
 *****************************************************************************/

AlterRoleStmt:
			ALTER ROLE RoleId opt_with OptRoleList
				 {
					AlterRoleStmt *n = makeNode(AlterRoleStmt);
					n->role = $3;
					n->action = +1;	/* add, if there are members */
					n->options = $5;
					$$ = (Node *)n;
				 }
		;

AlterRoleSetStmt:
			ALTER ROLE RoleId SetResetClause
				{
					AlterRoleSetStmt *n = makeNode(AlterRoleSetStmt);
					n->role = $3;
					n->setstmt = $4;
					$$ = (Node *)n;
				}
		;


/*****************************************************************************
 *
 * Alter a postgresql DBMS user
 *
 *****************************************************************************/

AlterUserStmt:
			ALTER USER RoleId opt_with OptRoleList
				 {
					AlterRoleStmt *n = makeNode(AlterRoleStmt);
					n->role = $3;
					n->action = +1;	/* add, if there are members */
					n->options = $5;
					$$ = (Node *)n;
				 }
		;


AlterUserSetStmt:
			ALTER USER RoleId SetResetClause
				{
					AlterRoleSetStmt *n = makeNode(AlterRoleSetStmt);
					n->role = $3;
					n->setstmt = $4;
					$$ = (Node *)n;
				}
			;


/*****************************************************************************
 *
 * Drop a postgresql DBMS role
 *
 * XXX Ideally this would have CASCADE/RESTRICT options, but since a role
 * might own objects in multiple databases, there is presently no way to
 * implement either cascading or restricting.  Caveat DBA.
 *****************************************************************************/

DropRoleStmt:
			DROP ROLE name_list
				{
					DropRoleStmt *n = makeNode(DropRoleStmt);
					n->missing_ok = FALSE;
					n->roles = $3;
					$$ = (Node *)n;
				}
			| DROP ROLE IF_P EXISTS name_list
				{
					DropRoleStmt *n = makeNode(DropRoleStmt);
					n->missing_ok = TRUE;
					n->roles = $5;
					$$ = (Node *)n;
				}
			;

/*****************************************************************************
 *
 * Drop a postgresql DBMS user
 *
 * XXX Ideally this would have CASCADE/RESTRICT options, but since a user
 * might own objects in multiple databases, there is presently no way to
 * implement either cascading or restricting.  Caveat DBA.
 *****************************************************************************/

DropUserStmt:
			DROP USER name_list
				{
					DropRoleStmt *n = makeNode(DropRoleStmt);
					n->missing_ok = FALSE;
					n->roles = $3;
					$$ = (Node *)n;
				}
			| DROP USER IF_P EXISTS name_list
				{
					DropRoleStmt *n = makeNode(DropRoleStmt);
					n->roles = $5;
					n->missing_ok = TRUE;
					$$ = (Node *)n;
				}
			;


/*****************************************************************************
 *
 * Create a postgresql group (role without login ability)
 *
 *****************************************************************************/

CreateGroupStmt:
			CREATE GROUP_P RoleId opt_with OptRoleList
				{
					CreateRoleStmt *n = makeNode(CreateRoleStmt);
					n->stmt_type = ROLESTMT_GROUP;
					n->role = $3;
					n->options = $5;
					$$ = (Node *)n;
				}
		;


/*****************************************************************************
 *
 * Alter a postgresql group
 *
 *****************************************************************************/

AlterGroupStmt:
			ALTER GROUP_P RoleId add_drop USER name_list
				{
					AlterRoleStmt *n = makeNode(AlterRoleStmt);
					n->role = $3;
					n->action = $4;
					n->options = list_make1(makeDefElem("rolemembers",
														(Node *)$6));
					$$ = (Node *)n;
				}
		;

add_drop:	ADD_P									{ $$ = +1; }
			| DROP									{ $$ = -1; }
		;


/*****************************************************************************
 *
 * Drop a postgresql group
 *
 * XXX see above notes about cascading DROP USER; groups have same problem.
 *****************************************************************************/

DropGroupStmt:
			DROP GROUP_P name_list
				{
					DropRoleStmt *n = makeNode(DropRoleStmt);
					n->missing_ok = FALSE;
					n->roles = $3;
					$$ = (Node *)n;
				}
			| DROP GROUP_P IF_P EXISTS name_list
				{
					DropRoleStmt *n = makeNode(DropRoleStmt);
					n->missing_ok = TRUE;
					n->roles = $5;
					$$ = (Node *)n;
				}
		;


/*****************************************************************************
 *
 * Manipulate a schema
 *
 *****************************************************************************/

CreateSchemaStmt:
			CREATE SCHEMA OptSchemaName AUTHORIZATION RoleId OptSchemaEltList
				{
					CreateSchemaStmt *n = makeNode(CreateSchemaStmt);
					/* One can omit the schema name or the authorization id. */
					if ($3 != NULL)
						n->schemaname = $3;
					else
						n->schemaname = $5;
					n->authid = $5;
					n->schemaElts = $6;
					$$ = (Node *)n;
				}
			| CREATE SCHEMA ColId OptSchemaEltList
				{
					CreateSchemaStmt *n = makeNode(CreateSchemaStmt);
					/* ...but not both */
					n->schemaname = $3;
					n->authid = NULL;
					n->schemaElts = $4;
					$$ = (Node *)n;
				}
		;

OptSchemaName:
			ColId									{ $$ = $1; }
			| /* EMPTY */							{ $$ = NULL; }
		;

OptSchemaEltList:
			OptSchemaEltList schema_stmt			{ $$ = lappend($1, $2); }
			| /* EMPTY */							{ $$ = NIL; }
		;

/*
 *	schema_stmt are the ones that can show up inside a CREATE SCHEMA
 *	statement (in addition to by themselves).
 */
schema_stmt:
			CreateStmt
			| IndexStmt
			| CreateSeqStmt
			| CreateTrigStmt
			| GrantStmt
			| ViewStmt
		;


/*****************************************************************************
 *
 * Set PG internal variable
 *	  SET name TO 'var_value'
 * Include SQL92 syntax (thomas 1997-10-22):
 *	  SET TIME ZONE 'var_value'
 *
 *****************************************************************************/

VariableSetStmt:
			SET set_rest
				{
					VariableSetStmt *n = $2;
					n->is_local = false;
					$$ = (Node *) n;
				}
			| SET LOCAL set_rest
				{
					VariableSetStmt *n = $3;
					n->is_local = true;
					$$ = (Node *) n;
				}
			| SET SESSION set_rest
				{
					VariableSetStmt *n = $3;
					n->is_local = false;
					$$ = (Node *) n;
				}
		;

set_rest:	/* Generic SET syntaxes: */
			var_name TO var_list
				{
					VariableSetStmt *n = makeNode(VariableSetStmt);
					n->kind = VAR_SET_VALUE;
					n->name = $1;
					n->args = $3;
					$$ = n;
				}
			| var_name '=' var_list
				{
					VariableSetStmt *n = makeNode(VariableSetStmt);
					n->kind = VAR_SET_VALUE;
					n->name = $1;
					n->args = $3;
					$$ = n;
				}
			| var_name TO DEFAULT
				{
					VariableSetStmt *n = makeNode(VariableSetStmt);
					n->kind = VAR_SET_DEFAULT;
					n->name = $1;
					$$ = n;
				}
			| var_name '=' DEFAULT
				{
					VariableSetStmt *n = makeNode(VariableSetStmt);
					n->kind = VAR_SET_DEFAULT;
					n->name = $1;
					$$ = n;
				}
			| var_name FROM CURRENT_P
				{
					VariableSetStmt *n = makeNode(VariableSetStmt);
					n->kind = VAR_SET_CURRENT;
					n->name = $1;
					$$ = n;
				}
			/* Special syntaxes mandated by SQL standard: */
			| TIME ZONE zone_value
				{
					VariableSetStmt *n = makeNode(VariableSetStmt);
					n->kind = VAR_SET_VALUE;
					n->name = "timezone";
					if ($3 != NULL)
						n->args = list_make1($3);
					else
						n->kind = VAR_SET_DEFAULT;
					$$ = n;
				}
			| TRANSACTION transaction_mode_list
				{
					VariableSetStmt *n = makeNode(VariableSetStmt);
					n->kind = VAR_SET_MULTI;
					n->name = "TRANSACTION";
					n->args = $2;
					$$ = n;
				}
			| SESSION CHARACTERISTICS AS TRANSACTION transaction_mode_list
				{
					VariableSetStmt *n = makeNode(VariableSetStmt);
					n->kind = VAR_SET_MULTI;
					n->name = "SESSION CHARACTERISTICS";
					n->args = $5;
					$$ = n;
				}
			| CATALOG_P Sconst
				{
					ereport(ERROR,
							(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
							 errmsg("current database cannot be changed"),
							 scanner_errposition(@2)));
					$$ = NULL; /*not reached*/
				}
			| SCHEMA Sconst
				{
					VariableSetStmt *n = makeNode(VariableSetStmt);
					n->kind = VAR_SET_VALUE;
					n->name = "search_path";
					n->args = list_make1(makeStringConst($2, @2));
					$$ = n;
				}
			| NAMES opt_encoding
				{
					VariableSetStmt *n = makeNode(VariableSetStmt);
					n->kind = VAR_SET_VALUE;
					n->name = "client_encoding";
					if ($2 != NULL)
						n->args = list_make1(makeStringConst($2, @2));
					else
						n->kind = VAR_SET_DEFAULT;
					$$ = n;
				}
			| ROLE ColId_or_Sconst
				{
					VariableSetStmt *n = makeNode(VariableSetStmt);
					n->kind = VAR_SET_VALUE;
					n->name = "role";
					n->args = list_make1(makeStringConst($2, @2));
					$$ = n;
				}
			| SESSION AUTHORIZATION ColId_or_Sconst
				{
					VariableSetStmt *n = makeNode(VariableSetStmt);
					n->kind = VAR_SET_VALUE;
					n->name = "session_authorization";
					n->args = list_make1(makeStringConst($3, @3));
					$$ = n;
				}
			| SESSION AUTHORIZATION DEFAULT
				{
					VariableSetStmt *n = makeNode(VariableSetStmt);
					n->kind = VAR_SET_DEFAULT;
					n->name = "session_authorization";
					$$ = n;
				}
			| XML_P OPTION document_or_content
				{
					VariableSetStmt *n = makeNode(VariableSetStmt);
					n->kind = VAR_SET_VALUE;
					n->name = "xmloption";
					n->args = list_make1(makeStringConst($3 == XMLOPTION_DOCUMENT ? "DOCUMENT" : "CONTENT", @3));
					$$ = n;
				}
		;

var_name:	ColId								{ $$ = $1; }
			| var_name '.' ColId
				{
					$$ = palloc(strlen($1) + strlen($3) + 2);
					sprintf($$, "%s.%s", $1, $3);
				}
		;

var_list:	var_value								{ $$ = list_make1($1); }
			| var_list ',' var_value				{ $$ = lappend($1, $3); }
		;

var_value:	opt_boolean
				{ $$ = makeStringConst($1, @1); }
			| ColId_or_Sconst
				{ $$ = makeStringConst($1, @1); }
			| NumericOnly
				{ $$ = makeAConst($1, @1); }
		;

iso_level:	READ UNCOMMITTED						{ $$ = "read uncommitted"; }
			| READ COMMITTED						{ $$ = "read committed"; }
			| REPEATABLE READ						{ $$ = "repeatable read"; }
			| SERIALIZABLE							{ $$ = "serializable"; }
		;

opt_boolean:
			TRUE_P									{ $$ = "true"; }
			| FALSE_P								{ $$ = "false"; }
			| ON									{ $$ = "on"; }
			| OFF									{ $$ = "off"; }
		;

/* Timezone values can be:
 * - a string such as 'pst8pdt'
 * - an identifier such as "pst8pdt"
 * - an integer or floating point number
 * - a time interval per SQL99
 * ColId gives reduce/reduce errors against ConstInterval and LOCAL,
 * so use IDENT (meaning we reject anything that is a key word).
 */
zone_value:
			Sconst
				{
					$$ = makeStringConst($1, @1);
				}
			| IDENT
				{
					$$ = makeStringConst($1, @1);
				}
			| ConstInterval Sconst opt_interval
				{
					TypeName *t = $1;
					if ($3 != NIL)
					{
						A_Const *n = (A_Const *) linitial($3);
						if ((n->val.val.ival & ~(INTERVAL_MASK(HOUR) | INTERVAL_MASK(MINUTE))) != 0)
							ereport(ERROR,
									(errcode(ERRCODE_SYNTAX_ERROR),
									 errmsg("time zone interval must be HOUR or HOUR TO MINUTE"),
									 scanner_errposition(@3)));
					}
					t->typmods = $3;
					$$ = makeStringConstCast($2, @2, t);
				}
			| ConstInterval '(' Iconst ')' Sconst opt_interval
				{
					TypeName *t = $1;
					if ($6 != NIL)
					{
						A_Const *n = (A_Const *) linitial($6);
						if ((n->val.val.ival & ~(INTERVAL_MASK(HOUR) | INTERVAL_MASK(MINUTE))) != 0)
							ereport(ERROR,
									(errcode(ERRCODE_SYNTAX_ERROR),
									 errmsg("time zone interval must be HOUR or HOUR TO MINUTE"),
									 scanner_errposition(@6)));
						if (list_length($6) != 1)
							ereport(ERROR,
									(errcode(ERRCODE_SYNTAX_ERROR),
									 errmsg("interval precision specified twice"),
									 scanner_errposition(@1)));
						t->typmods = lappend($6, makeIntConst($3, @3));
					}
					else
						t->typmods = list_make2(makeIntConst(INTERVAL_FULL_RANGE, -1),
												makeIntConst($3, @3));
					$$ = makeStringConstCast($5, @5, t);
				}
			| NumericOnly							{ $$ = makeAConst($1, @1); }
			| DEFAULT								{ $$ = NULL; }
			| LOCAL									{ $$ = NULL; }
		;

opt_encoding:
			Sconst									{ $$ = $1; }
			| DEFAULT								{ $$ = NULL; }
			| /*EMPTY*/								{ $$ = NULL; }
		;

ColId_or_Sconst:
			ColId									{ $$ = $1; }
			| Sconst								{ $$ = $1; }
		;

VariableResetStmt:
			RESET var_name
				{
					VariableSetStmt *n = makeNode(VariableSetStmt);
					n->kind = VAR_RESET;
					n->name = $2;
					$$ = (Node *) n;
				}
			| RESET TIME ZONE
				{
					VariableSetStmt *n = makeNode(VariableSetStmt);
					n->kind = VAR_RESET;
					n->name = "timezone";
					$$ = (Node *) n;
				}
			| RESET TRANSACTION ISOLATION LEVEL
				{
					VariableSetStmt *n = makeNode(VariableSetStmt);
					n->kind = VAR_RESET;
					n->name = "transaction_isolation";
					$$ = (Node *) n;
				}
			| RESET SESSION AUTHORIZATION
				{
					VariableSetStmt *n = makeNode(VariableSetStmt);
					n->kind = VAR_RESET;
					n->name = "session_authorization";
					$$ = (Node *) n;
				}
			| RESET ALL
				{
					VariableSetStmt *n = makeNode(VariableSetStmt);
					n->kind = VAR_RESET_ALL;
					$$ = (Node *) n;
				}
		;

/* SetResetClause allows SET or RESET without LOCAL */
SetResetClause:
			SET set_rest					{ $$ = $2; }
			| VariableResetStmt				{ $$ = (VariableSetStmt *) $1; }
		;


VariableShowStmt:
			SHOW var_name
				{
					VariableShowStmt *n = makeNode(VariableShowStmt);
					n->name = $2;
					$$ = (Node *) n;
				}
			| SHOW TIME ZONE
				{
					VariableShowStmt *n = makeNode(VariableShowStmt);
					n->name = "timezone";
					$$ = (Node *) n;
				}
			| SHOW TRANSACTION ISOLATION LEVEL
				{
					VariableShowStmt *n = makeNode(VariableShowStmt);
					n->name = "transaction_isolation";
					$$ = (Node *) n;
				}
			| SHOW SESSION AUTHORIZATION
				{
					VariableShowStmt *n = makeNode(VariableShowStmt);
					n->name = "session_authorization";
					$$ = (Node *) n;
				}
			| SHOW ALL
				{
					VariableShowStmt *n = makeNode(VariableShowStmt);
					n->name = "all";
					$$ = (Node *) n;
				}
		;


ConstraintsSetStmt:
			SET CONSTRAINTS constraints_set_list constraints_set_mode
				{
					ConstraintsSetStmt *n = makeNode(ConstraintsSetStmt);
					n->constraints = $3;
					n->deferred    = $4;
					$$ = (Node *) n;
				}
		;

constraints_set_list:
			ALL										{ $$ = NIL; }
			| qualified_name_list					{ $$ = $1; }
		;

constraints_set_mode:
			DEFERRED								{ $$ = TRUE; }
			| IMMEDIATE								{ $$ = FALSE; }
		;


/*
 * Checkpoint statement
 */
CheckPointStmt:
			CHECKPOINT
				{
					CheckPointStmt *n = makeNode(CheckPointStmt);
					$$ = (Node *)n;
				}
		;


/*****************************************************************************
 *
 * DISCARD { ALL | TEMP | PLANS }
 *
 *****************************************************************************/

DiscardStmt:
			DISCARD ALL
				{
					DiscardStmt *n = makeNode(DiscardStmt);
					n->target = DISCARD_ALL;
					$$ = (Node *) n;
				}
			| DISCARD TEMP
				{
					DiscardStmt *n = makeNode(DiscardStmt);
					n->target = DISCARD_TEMP;
					$$ = (Node *) n;
				}
			| DISCARD TEMPORARY
				{
					DiscardStmt *n = makeNode(DiscardStmt);
					n->target = DISCARD_TEMP;
					$$ = (Node *) n;
				}
			| DISCARD PLANS
				{
					DiscardStmt *n = makeNode(DiscardStmt);
					n->target = DISCARD_PLANS;
					$$ = (Node *) n;
				}
		;


/*****************************************************************************
 *
 *	ALTER [ TABLE | INDEX | SEQUENCE | VIEW ] variations
 *
 * Note: we accept all subcommands for each of the four variants, and sort
 * out what's really legal at execution time.
 *****************************************************************************/

AlterTableStmt:
			ALTER TABLE relation_expr alter_table_cmds
				{
					AlterTableStmt *n = makeNode(AlterTableStmt);
					n->relation = $3;
					n->cmds = $4;
					n->relkind = OBJECT_TABLE;
					$$ = (Node *)n;
				}
		|	ALTER INDEX qualified_name alter_table_cmds
				{
					AlterTableStmt *n = makeNode(AlterTableStmt);
					n->relation = $3;
					n->cmds = $4;
					n->relkind = OBJECT_INDEX;
					$$ = (Node *)n;
				}
		|	ALTER SEQUENCE qualified_name alter_table_cmds
				{
					AlterTableStmt *n = makeNode(AlterTableStmt);
					n->relation = $3;
					n->cmds = $4;
					n->relkind = OBJECT_SEQUENCE;
					$$ = (Node *)n;
				}
		|	ALTER VIEW qualified_name alter_table_cmds
				{
					AlterTableStmt *n = makeNode(AlterTableStmt);
					n->relation = $3;
					n->cmds = $4;
					n->relkind = OBJECT_VIEW;
					$$ = (Node *)n;
				}
		;

alter_table_cmds:
			alter_table_cmd							{ $$ = list_make1($1); }
			| alter_table_cmds ',' alter_table_cmd	{ $$ = lappend($1, $3); }
		;

alter_table_cmd:
			/* ALTER TABLE <name> ADD [COLUMN] <coldef> */
			ADD_P opt_column columnDef
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_AddColumn;
					n->def = $3;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> ALTER [COLUMN] <colname> {SET DEFAULT <expr>|DROP DEFAULT} */
			| ALTER opt_column ColId alter_column_default
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_ColumnDefault;
					n->name = $3;
					n->def = $4;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> ALTER [COLUMN] <colname> DROP NOT NULL */
			| ALTER opt_column ColId DROP NOT NULL_P
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_DropNotNull;
					n->name = $3;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> ALTER [COLUMN] <colname> SET NOT NULL */
			| ALTER opt_column ColId SET NOT NULL_P
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_SetNotNull;
					n->name = $3;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> ALTER [COLUMN] <colname> SET STATISTICS <SignedIconst> */
			| ALTER opt_column ColId SET STATISTICS SignedIconst
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_SetStatistics;
					n->name = $3;
					n->def = (Node *) makeInteger($6);
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> ALTER [COLUMN] <colname> SET STORAGE <storagemode> */
			| ALTER opt_column ColId SET STORAGE ColId
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_SetStorage;
					n->name = $3;
					n->def = (Node *) makeString($6);
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> DROP [COLUMN] <colname> [RESTRICT|CASCADE] */
			| DROP opt_column ColId opt_drop_behavior
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_DropColumn;
					n->name = $3;
					n->behavior = $4;
					$$ = (Node *)n;
				}
			/*
			 * ALTER TABLE <name> ALTER [COLUMN] <colname> [SET DATA] TYPE <typename>
			 *		[ USING <expression> ]
			 */
			| ALTER opt_column ColId opt_set_data TYPE_P Typename alter_using
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_AlterColumnType;
					n->name = $3;
					n->def = (Node *) $6;
					n->transform = $7;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> ADD CONSTRAINT ... */
			| ADD_P TableConstraint
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_AddConstraint;
					n->def = $2;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> DROP CONSTRAINT <name> [RESTRICT|CASCADE] */
			| DROP CONSTRAINT name opt_drop_behavior
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_DropConstraint;
					n->name = $3;
					n->behavior = $4;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> SET WITH OIDS  */
			| SET WITH OIDS
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_AddOids;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> SET WITHOUT OIDS  */
			| SET WITHOUT OIDS
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_DropOids;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> CLUSTER ON <indexname> */
			| CLUSTER ON name
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_ClusterOn;
					n->name = $3;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> SET WITHOUT CLUSTER */
			| SET WITHOUT CLUSTER
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_DropCluster;
					n->name = NULL;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> ENABLE TRIGGER <trig> */
			| ENABLE_P TRIGGER name
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_EnableTrig;
					n->name = $3;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> ENABLE ALWAYS TRIGGER <trig> */
			| ENABLE_P ALWAYS TRIGGER name
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_EnableAlwaysTrig;
					n->name = $4;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> ENABLE REPLICA TRIGGER <trig> */
			| ENABLE_P REPLICA TRIGGER name
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_EnableReplicaTrig;
					n->name = $4;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> ENABLE TRIGGER ALL */
			| ENABLE_P TRIGGER ALL
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_EnableTrigAll;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> ENABLE TRIGGER USER */
			| ENABLE_P TRIGGER USER
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_EnableTrigUser;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> DISABLE TRIGGER <trig> */
			| DISABLE_P TRIGGER name
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_DisableTrig;
					n->name = $3;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> DISABLE TRIGGER ALL */
			| DISABLE_P TRIGGER ALL
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_DisableTrigAll;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> DISABLE TRIGGER USER */
			| DISABLE_P TRIGGER USER
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_DisableTrigUser;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> ENABLE RULE <rule> */
			| ENABLE_P RULE name
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_EnableRule;
					n->name = $3;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> ENABLE ALWAYS RULE <rule> */
			| ENABLE_P ALWAYS RULE name
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_EnableAlwaysRule;
					n->name = $4;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> ENABLE REPLICA RULE <rule> */
			| ENABLE_P REPLICA RULE name
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_EnableReplicaRule;
					n->name = $4;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> DISABLE RULE <rule> */
			| DISABLE_P RULE name
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_DisableRule;
					n->name = $3;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> INHERIT <parent> */
			| INHERIT qualified_name
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_AddInherit;
					n->def = (Node *) $2;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> NO INHERIT <parent> */
			| NO INHERIT qualified_name
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_DropInherit;
					n->def = (Node *) $3;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> OWNER TO RoleId */
			| OWNER TO RoleId
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_ChangeOwner;
					n->name = $3;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> SET TABLESPACE <tablespacename> */
			| SET TABLESPACE name
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_SetTableSpace;
					n->name = $3;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> SET (...) */
			| SET reloptions
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_SetRelOptions;
					n->def = (Node *)$2;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <name> RESET (...) */
			| RESET reloptions
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_ResetRelOptions;
					n->def = (Node *)$2;
					$$ = (Node *)n;
				}
			/* ALTER TABLE <relation> CONTEXT = '...' */
			| SecurityItem
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_SetSecurityLabel;
					n->name = NULL;
					n->def = (Node *) $1;
					$$ = (Node *) n;
				}
			/* ALTER TABLE <relation> ALTER [COLUMN] <colname> CONTEXT = '...' */
			| ALTER opt_column ColId SecurityItem
				{
					AlterTableCmd *n = makeNode(AlterTableCmd);
					n->subtype = AT_SetSecurityLabel;
					n->name = $3;
					n->def = (Node *) $4;
					$$ = (Node *) n;
				}
		;

alter_column_default:
			SET DEFAULT a_expr			{ $$ = $3; }
			| DROP DEFAULT				{ $$ = NULL; }
		;

opt_drop_behavior:
			CASCADE						{ $$ = DROP_CASCADE; }
			| RESTRICT					{ $$ = DROP_RESTRICT; }
			| /* EMPTY */				{ $$ = DROP_RESTRICT; /* default */ }
		;

alter_using:
			USING a_expr				{ $$ = $2; }
			| /* EMPTY */				{ $$ = NULL; }
		;

reloptions:
		  	'(' reloption_list ')'					{ $$ = $2; }
		;

opt_reloptions:		WITH reloptions					{ $$ = $2; }
			 |		/* EMPTY */						{ $$ = NIL; }
		;

reloption_list:
			reloption_elem							{ $$ = list_make1($1); }
			| reloption_list ',' reloption_elem		{ $$ = lappend($1, $3); }
		;

reloption_elem:	
			ColLabel '=' def_arg
				{
					$$ = makeReloptElem($1, NULL, (Node *) $3);
				}
			| ColLabel
				{
					$$ = makeReloptElem($1, NULL, NULL);
				}
			| ColLabel '.' ColLabel '=' def_arg
				{
					$$ = makeReloptElem($3, $1, (Node *) $5);
				}
			| ColLabel '.' ColLabel
				{
					$$ = makeReloptElem($3, $1, NULL);
				}
		;


/*****************************************************************************
 *
 *		QUERY :
 *				close <portalname>
 *
 *****************************************************************************/

ClosePortalStmt:
			CLOSE name
				{
					ClosePortalStmt *n = makeNode(ClosePortalStmt);
					n->portalname = $2;
					$$ = (Node *)n;
				}
			| CLOSE ALL
				{
					ClosePortalStmt *n = makeNode(ClosePortalStmt);
					n->portalname = NULL;
					$$ = (Node *)n;
				}
		;


/*****************************************************************************
 *
 *		QUERY :
 *				COPY relname ['(' columnList ')'] FROM/TO file [WITH options]
 *
 *				BINARY, OIDS, and DELIMITERS kept in old locations
 *				for backward compatibility.  2002-06-18
 *
 *				COPY ( SELECT ... ) TO file [WITH options]
 *				This form doesn't have the backwards-compatible option
 *				syntax.
 *
 *****************************************************************************/

CopyStmt:	COPY opt_binary qualified_name opt_column_list opt_oids
			copy_from copy_file_name copy_delimiter opt_with copy_opt_list
				{
					CopyStmt *n = makeNode(CopyStmt);
					n->relation = $3;
					n->query = NULL;
					n->attlist = $4;
					n->is_from = $6;
					n->filename = $7;

					n->options = NIL;
					/* Concatenate user-supplied flags */
					if ($2)
						n->options = lappend(n->options, $2);
					if ($5)
						n->options = lappend(n->options, $5);
					if ($8)
						n->options = lappend(n->options, $8);
					if ($10)
						n->options = list_concat(n->options, $10);
					$$ = (Node *)n;
				}
			| COPY select_with_parens TO copy_file_name opt_with
			  copy_opt_list
				{
					CopyStmt *n = makeNode(CopyStmt);
					n->relation = NULL;
					n->query = $2;
					n->attlist = NIL;
					n->is_from = false;
					n->filename = $4;
					n->options = $6;
					$$ = (Node *)n;
				}
		;

copy_from:
			FROM									{ $$ = TRUE; }
			| TO									{ $$ = FALSE; }
		;

/*
 * copy_file_name NULL indicates stdio is used. Whether stdin or stdout is
 * used depends on the direction. (It really doesn't make sense to copy from
 * stdout. We silently correct the "typo".)		 - AY 9/94
 */
copy_file_name:
			Sconst									{ $$ = $1; }
			| STDIN									{ $$ = NULL; }
			| STDOUT								{ $$ = NULL; }
		;



copy_opt_list:
			copy_opt_list copy_opt_item				{ $$ = lappend($1, $2); }
			| /* EMPTY */							{ $$ = NIL; }
		;


copy_opt_item:
			BINARY
				{
					$$ = makeDefElem("binary", (Node *)makeInteger(TRUE));
				}
			| OIDS
				{
					$$ = makeDefElem("oids", (Node *)makeInteger(TRUE));
				}
			| DELIMITER opt_as Sconst
				{
					$$ = makeDefElem("delimiter", (Node *)makeString($3));
				}
			| NULL_P opt_as Sconst
				{
					$$ = makeDefElem("null", (Node *)makeString($3));
				}
			| CSV
				{
					$$ = makeDefElem("csv", (Node *)makeInteger(TRUE));
				}
			| HEADER_P
				{
					$$ = makeDefElem("header", (Node *)makeInteger(TRUE));
				}
			| QUOTE opt_as Sconst
				{
					$$ = makeDefElem("quote", (Node *)makeString($3));
				}
			| ESCAPE opt_as Sconst
				{
					$$ = makeDefElem("escape", (Node *)makeString($3));
				}
			| FORCE QUOTE columnList
				{
					$$ = makeDefElem("force_quote", (Node *)$3);
				}
			| FORCE NOT NULL_P columnList
				{
					$$ = makeDefElem("force_notnull", (Node *)$4);
				}
		;

/* The following exist for backward compatibility */

opt_binary:
			BINARY
				{
					$$ = makeDefElem("binary", (Node *)makeInteger(TRUE));
				}
			| /*EMPTY*/								{ $$ = NULL; }
		;

opt_oids:
			WITH OIDS
				{
					$$ = makeDefElem("oids", (Node *)makeInteger(TRUE));
				}
			| /*EMPTY*/								{ $$ = NULL; }
		;

copy_delimiter:
			/* USING DELIMITERS kept for backward compatibility. 2002-06-15 */
			opt_using DELIMITERS Sconst
				{
					$$ = makeDefElem("delimiter", (Node *)makeString($3));
				}
			| /*EMPTY*/								{ $$ = NULL; }
		;

opt_using:
			USING									{}
			| /*EMPTY*/								{}
		;


/*****************************************************************************
 *
 *		QUERY :
 *				CREATE TABLE relname
 *
 *****************************************************************************/

CreateStmt:	CREATE OptTemp TABLE qualified_name '(' OptTableElementList ')'
			OptInherit OptWith OnCommitOption OptTableSpace OptSecurityItem
				{
					CreateStmt *n = makeNode(CreateStmt);
					$4->istemp = $2;
					n->relation = $4;
					n->tableElts = $6;
					n->inhRelations = $8;
					n->constraints = NIL;
					n->options = $9;
					n->oncommit = $10;
					n->tablespacename = $11;
					n->secLabel = (Node *) $12;
					$$ = (Node *)n;
				}
		| CREATE OptTemp TABLE qualified_name OF qualified_name
			'(' OptTableElementList ')' OptWith OnCommitOption OptTableSpace OptSecurityItem
				{
					/* SQL99 CREATE TABLE OF <UDT> (cols) seems to be satisfied
					 * by our inheritance capabilities. Let's try it...
					 */
					CreateStmt *n = makeNode(CreateStmt);
					$4->istemp = $2;
					n->relation = $4;
					n->tableElts = $8;
					n->inhRelations = list_make1($6);
					n->constraints = NIL;
					n->options = $10;
					n->oncommit = $11;
					n->tablespacename = $12;
					n->secLabel = (Node *) $13;
					$$ = (Node *)n;
				}
		;

/*
 * Redundancy here is needed to avoid shift/reduce conflicts,
 * since TEMP is not a reserved word.  See also OptTempTableName.
 *
 * NOTE: we accept both GLOBAL and LOCAL options; since we have no modules
 * the LOCAL keyword is really meaningless.
 */
OptTemp:	TEMPORARY						{ $$ = TRUE; }
			| TEMP							{ $$ = TRUE; }
			| LOCAL TEMPORARY				{ $$ = TRUE; }
			| LOCAL TEMP					{ $$ = TRUE; }
			| GLOBAL TEMPORARY				{ $$ = TRUE; }
			| GLOBAL TEMP					{ $$ = TRUE; }
			| /*EMPTY*/						{ $$ = FALSE; }
		;

OptTableElementList:
			TableElementList					{ $$ = $1; }
			| /*EMPTY*/							{ $$ = NIL; }
		;

TableElementList:
			TableElement
				{
					$$ = list_make1($1);
				}
			| TableElementList ',' TableElement
				{
					$$ = lappend($1, $3);
				}
		;

TableElement:
			columnDef							{ $$ = $1; }
			| TableLikeClause					{ $$ = $1; }
			| TableConstraint					{ $$ = $1; }
		;

columnDef:	ColId Typename ColQualList OptSecurityItem
				{
					ColumnDef *n = makeNode(ColumnDef);
					n->colname = $1;
					n->typename = $2;
					n->constraints = $3;
					n->is_local = true;
					n->secLabel = (Node *) $4;
					$$ = (Node *)n;
				}
		;

ColQualList:
			ColQualList ColConstraint				{ $$ = lappend($1, $2); }
			| /*EMPTY*/								{ $$ = NIL; }
		;

ColConstraint:
			CONSTRAINT name ColConstraintElem
				{
					switch (nodeTag($3))
					{
						case T_Constraint:
							{
								Constraint *n = (Constraint *)$3;
								n->name = $2;
							}
							break;
						case T_FkConstraint:
							{
								FkConstraint *n = (FkConstraint *)$3;
								n->constr_name = $2;
							}
							break;
						default:
							break;
					}
					$$ = $3;
				}
			| ColConstraintElem						{ $$ = $1; }
			| ConstraintAttr						{ $$ = $1; }
		;

/* DEFAULT NULL is already the default for Postgres.
 * But define it here and carry it forward into the system
 * to make it explicit.
 * - thomas 1998-09-13
 *
 * WITH NULL and NULL are not SQL92-standard syntax elements,
 * so leave them out. Use DEFAULT NULL to explicitly indicate
 * that a column may have that value. WITH NULL leads to
 * shift/reduce conflicts with WITH TIME ZONE anyway.
 * - thomas 1999-01-08
 *
 * DEFAULT expression must be b_expr not a_expr to prevent shift/reduce
 * conflict on NOT (since NOT might start a subsequent NOT NULL constraint,
 * or be part of a_expr NOT LIKE or similar constructs).
 */
ColConstraintElem:
			NOT NULL_P
				{
					Constraint *n = makeNode(Constraint);
					n->contype = CONSTR_NOTNULL;
					n->name = NULL;
					n->raw_expr = NULL;
					n->cooked_expr = NULL;
					n->keys = NULL;
					n->indexspace = NULL;
					$$ = (Node *)n;
				}
			| NULL_P
				{
					Constraint *n = makeNode(Constraint);
					n->contype = CONSTR_NULL;
					n->name = NULL;
					n->raw_expr = NULL;
					n->cooked_expr = NULL;
					n->keys = NULL;
					n->indexspace = NULL;
					$$ = (Node *)n;
				}
			| UNIQUE opt_definition OptConsTableSpace
				{
					Constraint *n = makeNode(Constraint);
					n->contype = CONSTR_UNIQUE;
					n->name = NULL;
					n->raw_expr = NULL;
					n->cooked_expr = NULL;
					n->keys = NULL;
					n->options = $2;
					n->indexspace = $3;
					$$ = (Node *)n;
				}
			| PRIMARY KEY opt_definition OptConsTableSpace
				{
					Constraint *n = makeNode(Constraint);
					n->contype = CONSTR_PRIMARY;
					n->name = NULL;
					n->raw_expr = NULL;
					n->cooked_expr = NULL;
					n->keys = NULL;
					n->options = $3;
					n->indexspace = $4;
					$$ = (Node *)n;
				}
			| CHECK '(' a_expr ')'
				{
					Constraint *n = makeNode(Constraint);
					n->contype = CONSTR_CHECK;
					n->name = NULL;
					n->raw_expr = $3;
					n->cooked_expr = NULL;
					n->keys = NULL;
					n->indexspace = NULL;
					$$ = (Node *)n;
				}
			| DEFAULT b_expr
				{
					Constraint *n = makeNode(Constraint);
					n->contype = CONSTR_DEFAULT;
					n->name = NULL;
					n->raw_expr = $2;
					n->cooked_expr = NULL;
					n->keys = NULL;
					n->indexspace = NULL;
					$$ = (Node *)n;
				}
			| REFERENCES qualified_name opt_column_list key_match key_actions
				{
					FkConstraint *n = makeNode(FkConstraint);
					n->constr_name		= NULL;
					n->pktable			= $2;
					n->fk_attrs			= NIL;
					n->pk_attrs			= $3;
					n->fk_matchtype		= $4;
					n->fk_upd_action	= (char) ($5 >> 8);
					n->fk_del_action	= (char) ($5 & 0xFF);
					n->deferrable		= FALSE;
					n->initdeferred		= FALSE;
					$$ = (Node *)n;
				}
		;

/*
 * ConstraintAttr represents constraint attributes, which we parse as if
 * they were independent constraint clauses, in order to avoid shift/reduce
 * conflicts (since NOT might start either an independent NOT NULL clause
 * or an attribute).  parse_utilcmd.c is responsible for attaching the
 * attribute information to the preceding "real" constraint node, and for
 * complaining if attribute clauses appear in the wrong place or wrong
 * combinations.
 *
 * See also ConstraintAttributeSpec, which can be used in places where
 * there is no parsing conflict.
 */
ConstraintAttr:
			DEFERRABLE
				{
					Constraint *n = makeNode(Constraint);
					n->contype = CONSTR_ATTR_DEFERRABLE;
					$$ = (Node *)n;
				}
			| NOT DEFERRABLE
				{
					Constraint *n = makeNode(Constraint);
					n->contype = CONSTR_ATTR_NOT_DEFERRABLE;
					$$ = (Node *)n;
				}
			| INITIALLY DEFERRED
				{
					Constraint *n = makeNode(Constraint);
					n->contype = CONSTR_ATTR_DEFERRED;
					$$ = (Node *)n;
				}
			| INITIALLY IMMEDIATE
				{
					Constraint *n = makeNode(Constraint);
					n->contype = CONSTR_ATTR_IMMEDIATE;
					$$ = (Node *)n;
				}
		;


/*
 * SQL99 supports wholesale borrowing of a table definition via the LIKE clause.
 * This seems to be a poor man's inheritance capability, with the resulting
 * tables completely decoupled except for the original commonality in definitions.
 *
 * This is very similar to CREATE TABLE AS except for the INCLUDING DEFAULTS extension
 * which is a part of SQL:2003.
 */
TableLikeClause:
			LIKE qualified_name TableLikeOptionList
				{
					InhRelation *n = makeNode(InhRelation);
					n->relation = $2;
					n->options = $3;
					$$ = (Node *)n;
				}
		;

TableLikeOptionList:
				TableLikeOptionList TableLikeOption	{ $$ = lappend_int($1, $2); }
				| /* EMPTY */						{ $$ = NIL; }
		;

TableLikeOption:
				INCLUDING DEFAULTS					{ $$ = 	CREATE_TABLE_LIKE_INCLUDING_DEFAULTS; }
				| EXCLUDING DEFAULTS				{ $$ = 	CREATE_TABLE_LIKE_EXCLUDING_DEFAULTS; }
				| INCLUDING CONSTRAINTS				{ $$ = 	CREATE_TABLE_LIKE_INCLUDING_CONSTRAINTS; }
				| EXCLUDING CONSTRAINTS				{ $$ = 	CREATE_TABLE_LIKE_EXCLUDING_CONSTRAINTS; }
				| INCLUDING INDEXES					{ $$ = 	CREATE_TABLE_LIKE_INCLUDING_INDEXES; }
				| EXCLUDING INDEXES					{ $$ = 	CREATE_TABLE_LIKE_EXCLUDING_INDEXES; }
		;


/* ConstraintElem specifies constraint syntax which is not embedded into
 *	a column definition. ColConstraintElem specifies the embedded form.
 * - thomas 1997-12-03
 */
TableConstraint:
			CONSTRAINT name ConstraintElem
				{
					switch (nodeTag($3))
					{
						case T_Constraint:
							{
								Constraint *n = (Constraint *)$3;
								n->name = $2;
							}
							break;
						case T_FkConstraint:
							{
								FkConstraint *n = (FkConstraint *)$3;
								n->constr_name = $2;
							}
							break;
						default:
							break;
					}
					$$ = $3;
				}
			| ConstraintElem						{ $$ = $1; }
		;

ConstraintElem:
			CHECK '(' a_expr ')'
				{
					Constraint *n = makeNode(Constraint);
					n->contype = CONSTR_CHECK;
					n->name = NULL;
					n->raw_expr = $3;
					n->cooked_expr = NULL;
					n->indexspace = NULL;
					$$ = (Node *)n;
				}
			| UNIQUE '(' columnList ')' opt_definition OptConsTableSpace
				{
					Constraint *n = makeNode(Constraint);
					n->contype = CONSTR_UNIQUE;
					n->name = NULL;
					n->raw_expr = NULL;
					n->cooked_expr = NULL;
					n->keys = $3;
					n->options = $5;
					n->indexspace = $6;
					$$ = (Node *)n;
				}
			| PRIMARY KEY '(' columnList ')' opt_definition OptConsTableSpace
				{
					Constraint *n = makeNode(Constraint);
					n->contype = CONSTR_PRIMARY;
					n->name = NULL;
					n->raw_expr = NULL;
					n->cooked_expr = NULL;
					n->keys = $4;
					n->options = $6;
					n->indexspace = $7;
					$$ = (Node *)n;
				}
			| FOREIGN KEY '(' columnList ')' REFERENCES qualified_name
				opt_column_list key_match key_actions ConstraintAttributeSpec
				{
					FkConstraint *n = makeNode(FkConstraint);
					n->constr_name		= NULL;
					n->pktable			= $7;
					n->fk_attrs			= $4;
					n->pk_attrs			= $8;
					n->fk_matchtype		= $9;
					n->fk_upd_action	= (char) ($10 >> 8);
					n->fk_del_action	= (char) ($10 & 0xFF);
					n->deferrable		= ($11 & 1) != 0;
					n->initdeferred		= ($11 & 2) != 0;
					$$ = (Node *)n;
				}
		;

opt_column_list:
			'(' columnList ')'						{ $$ = $2; }
			| /*EMPTY*/								{ $$ = NIL; }
		;

columnList:
			columnElem								{ $$ = list_make1($1); }
			| columnList ',' columnElem				{ $$ = lappend($1, $3); }
		;

columnElem: ColId
				{
					$$ = (Node *) makeString($1);
				}
		;

key_match:  MATCH FULL
			{
				$$ = FKCONSTR_MATCH_FULL;
			}
		| MATCH PARTIAL
			{
				ereport(ERROR,
						(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
						 errmsg("MATCH PARTIAL not yet implemented"),
						 scanner_errposition(@1)));
				$$ = FKCONSTR_MATCH_PARTIAL;
			}
		| MATCH SIMPLE
			{
				$$ = FKCONSTR_MATCH_UNSPECIFIED;
			}
		| /*EMPTY*/
			{
				$$ = FKCONSTR_MATCH_UNSPECIFIED;
			}
		;

/*
 * We combine the update and delete actions into one value temporarily
 * for simplicity of parsing, and then break them down again in the
 * calling production.  update is in the left 8 bits, delete in the right.
 * Note that NOACTION is the default.
 */
key_actions:
			key_update
				{ $$ = ($1 << 8) | (FKCONSTR_ACTION_NOACTION & 0xFF); }
			| key_delete
				{ $$ = (FKCONSTR_ACTION_NOACTION << 8) | ($1 & 0xFF); }
			| key_update key_delete
				{ $$ = ($1 << 8) | ($2 & 0xFF); }
			| key_delete key_update
				{ $$ = ($2 << 8) | ($1 & 0xFF); }
			| /*EMPTY*/
				{ $$ = (FKCONSTR_ACTION_NOACTION << 8) | (FKCONSTR_ACTION_NOACTION & 0xFF); }
		;

key_update: ON UPDATE key_action		{ $$ = $3; }
		;

key_delete: ON DELETE_P key_action		{ $$ = $3; }
		;

key_action:
			NO ACTION					{ $$ = FKCONSTR_ACTION_NOACTION; }
			| RESTRICT					{ $$ = FKCONSTR_ACTION_RESTRICT; }
			| CASCADE					{ $$ = FKCONSTR_ACTION_CASCADE; }
			| SET NULL_P				{ $$ = FKCONSTR_ACTION_SETNULL; }
			| SET DEFAULT				{ $$ = FKCONSTR_ACTION_SETDEFAULT; }
		;

OptInherit: INHERITS '(' qualified_name_list ')'	{ $$ = $3; }
			| /*EMPTY*/								{ $$ = NIL; }
		;

/* WITH (options) is preferred, WITH OIDS and WITHOUT OIDS are legacy forms */
OptWith:
			WITH reloptions				{ $$ = $2; }
			| WITH OIDS					{ $$ = list_make1(reloptWithOids(true)); }
			| WITHOUT OIDS				{ $$ = list_make1(reloptWithOids(false)); }
			| /*EMPTY*/					{ $$ = NIL; }
		;

OnCommitOption:  ON COMMIT DROP				{ $$ = ONCOMMIT_DROP; }
			| ON COMMIT DELETE_P ROWS		{ $$ = ONCOMMIT_DELETE_ROWS; }
			| ON COMMIT PRESERVE ROWS		{ $$ = ONCOMMIT_PRESERVE_ROWS; }
			| /*EMPTY*/						{ $$ = ONCOMMIT_NOOP; }
		;

OptTableSpace:   TABLESPACE name					{ $$ = $2; }
			| /*EMPTY*/								{ $$ = NULL; }
		;

OptConsTableSpace:   USING INDEX TABLESPACE name	{ $$ = $4; }
			| /*EMPTY*/								{ $$ = NULL; }
		;


/*
 * Note: CREATE TABLE ... AS SELECT ... is just another spelling for
 * SELECT ... INTO.
 */

CreateAsStmt:
		CREATE OptTemp TABLE create_as_target AS SelectStmt opt_with_data
				{
					/*
					 * When the SelectStmt is a set-operation tree, we must
					 * stuff the INTO information into the leftmost component
					 * Select, because that's where analyze.c will expect
					 * to find it.	Similarly, the output column names must
					 * be attached to that Select's target list.
					 */
					SelectStmt *n = findLeftmostSelect((SelectStmt *) $6);
					if (n->intoClause != NULL)
						ereport(ERROR,
								(errcode(ERRCODE_SYNTAX_ERROR),
								 errmsg("CREATE TABLE AS cannot specify INTO"),
								 scanner_errposition(exprLocation((Node *) n->intoClause))));
					$4->rel->istemp = $2;
					n->intoClause = $4;
					/* Implement WITH NO DATA by forcing top-level LIMIT 0 */
					if (!$7)
						((SelectStmt *) $6)->limitCount = makeIntConst(0, -1);
					$$ = $6;
				}
		;

create_as_target:
			qualified_name OptCreateAs OptWith OnCommitOption OptTableSpace
				{
					$$ = makeNode(IntoClause);
					$$->rel = $1;
					$$->colNames = $2;
					$$->options = $3;
					$$->onCommit = $4;
					$$->tableSpaceName = $5;
				}
		;

OptCreateAs:
			'(' CreateAsList ')'					{ $$ = $2; }
			| /*EMPTY*/								{ $$ = NIL; }
		;

CreateAsList:
			CreateAsElement							{ $$ = list_make1($1); }
			| CreateAsList ',' CreateAsElement		{ $$ = lappend($1, $3); }
		;

CreateAsElement:
			ColId
				{
					ColumnDef *n = makeNode(ColumnDef);
					n->colname = $1;
					n->typename = NULL;
					n->inhcount = 0;
					n->is_local = true;
					n->is_not_null = false;
					n->raw_default = NULL;
					n->cooked_default = NULL;
					n->constraints = NIL;
					$$ = (Node *)n;
				}
		;

opt_with_data:
			WITH DATA_P								{ $$ = TRUE; }
			| WITH NO DATA_P						{ $$ = FALSE; }
			| /*EMPTY*/								{ $$ = TRUE; }
		;


/*****************************************************************************
 *
 *		QUERY :
 *				CREATE SEQUENCE seqname
 *				ALTER SEQUENCE seqname
 *
 *****************************************************************************/

CreateSeqStmt:
			CREATE OptTemp SEQUENCE qualified_name OptSeqOptList
				{
					CreateSeqStmt *n = makeNode(CreateSeqStmt);
					$4->istemp = $2;
					n->sequence = $4;
					n->options = $5;
					$$ = (Node *)n;
				}
		;

AlterSeqStmt:
			ALTER SEQUENCE qualified_name SeqOptList
				{
					AlterSeqStmt *n = makeNode(AlterSeqStmt);
					n->sequence = $3;
					n->options = $4;
					$$ = (Node *)n;
				}
		;

OptSeqOptList: SeqOptList							{ $$ = $1; }
			| /*EMPTY*/								{ $$ = NIL; }
		;

SeqOptList: SeqOptElem								{ $$ = list_make1($1); }
			| SeqOptList SeqOptElem					{ $$ = lappend($1, $2); }
		;

SeqOptElem: CACHE NumericOnly
				{
					$$ = makeDefElem("cache", (Node *)$2);
				}
			| CYCLE
				{
					$$ = makeDefElem("cycle", (Node *)makeInteger(TRUE));
				}
			| NO CYCLE
				{
					$$ = makeDefElem("cycle", (Node *)makeInteger(FALSE));
				}
			| INCREMENT opt_by NumericOnly
				{
					$$ = makeDefElem("increment", (Node *)$3);
				}
			| MAXVALUE NumericOnly
				{
					$$ = makeDefElem("maxvalue", (Node *)$2);
				}
			| MINVALUE NumericOnly
				{
					$$ = makeDefElem("minvalue", (Node *)$2);
				}
			| NO MAXVALUE
				{
					$$ = makeDefElem("maxvalue", NULL);
				}
			| NO MINVALUE
				{
					$$ = makeDefElem("minvalue", NULL);
				}
			| OWNED BY any_name
				{
					$$ = makeDefElem("owned_by", (Node *)$3);
				}
			| START opt_with NumericOnly
				{
					$$ = makeDefElem("start", (Node *)$3);
				}
			| RESTART
				{
					$$ = makeDefElem("restart", NULL);
				}
			| RESTART opt_with NumericOnly
				{
					$$ = makeDefElem("restart", (Node *)$3);
				}
		;

opt_by:		BY				{}
			| /* empty */	{}
	  ;

NumericOnly:
		FCONST									{ $$ = makeFloat($1); }
			| '-' FCONST
				{
					$$ = makeFloat($2);
					doNegateFloat($$);
				}
			| SignedIconst                                                  { $$ = makeInteger($1); };
		;

/*****************************************************************************
 *
 *		QUERIES :
 *				CREATE PROCEDURAL LANGUAGE ...
 *				DROP PROCEDURAL LANGUAGE ...
 *
 *****************************************************************************/

CreatePLangStmt:
			CREATE opt_trusted opt_procedural LANGUAGE ColId_or_Sconst
			{
				CreatePLangStmt *n = makeNode(CreatePLangStmt);
				n->plname = $5;
				/* parameters are all to be supplied by system */
				n->plhandler = NIL;
				n->plvalidator = NIL;
				n->pltrusted = false;
				$$ = (Node *)n;
			}
			| CREATE opt_trusted opt_procedural LANGUAGE ColId_or_Sconst
			  HANDLER handler_name opt_validator opt_lancompiler
			{
				CreatePLangStmt *n = makeNode(CreatePLangStmt);
				n->plname = $5;
				n->plhandler = $7;
				n->plvalidator = $8;
				n->pltrusted = $2;
				/* LANCOMPILER is now ignored entirely */
				$$ = (Node *)n;
			}
		;

opt_trusted:
			TRUSTED									{ $$ = TRUE; }
			| /*EMPTY*/								{ $$ = FALSE; }
		;

/* This ought to be just func_name, but that causes reduce/reduce conflicts
 * (CREATE LANGUAGE is the only place where func_name isn't followed by '(').
 * Work around by using simple names, instead.
 */
handler_name:
			name						{ $$ = list_make1(makeString($1)); }
			| name attrs				{ $$ = lcons(makeString($1), $2); }
		;

validator_clause:
			VALIDATOR handler_name					{ $$ = $2; }
			| NO VALIDATOR							{ $$ = NIL; }
		;

opt_validator:
			validator_clause						{ $$ = $1; }
			| /*EMPTY*/								{ $$ = NIL; }
		;

opt_lancompiler:
			LANCOMPILER Sconst						{ $$ = $2; }
			| /*EMPTY*/								{ $$ = NULL; }
		;

DropPLangStmt:
			DROP opt_procedural LANGUAGE ColId_or_Sconst opt_drop_behavior
				{
					DropPLangStmt *n = makeNode(DropPLangStmt);
					n->plname = $4;
					n->behavior = $5;
					n->missing_ok = false;
					$$ = (Node *)n;
				}
			| DROP opt_procedural LANGUAGE IF_P EXISTS ColId_or_Sconst opt_drop_behavior
				{
					DropPLangStmt *n = makeNode(DropPLangStmt);
					n->plname = $6;
					n->behavior = $7;
					n->missing_ok = true;
					$$ = (Node *)n;
				}
		;

opt_procedural:
			PROCEDURAL								{}
			| /*EMPTY*/								{}
		;

/*****************************************************************************
 *
 * 		QUERY:
 *             CREATE TABLESPACE tablespace LOCATION '/path/to/tablespace/'
 *
 *****************************************************************************/

CreateTableSpaceStmt: CREATE TABLESPACE name OptTableSpaceOwner LOCATION Sconst
				{
					CreateTableSpaceStmt *n = makeNode(CreateTableSpaceStmt);
					n->tablespacename = $3;
					n->owner = $4;
					n->location = $6;
					$$ = (Node *) n;
				}
		;

OptTableSpaceOwner: OWNER name			{ $$ = $2; }
			| /*EMPTY */				{ $$ = NULL; }
		;

/*****************************************************************************
 *
 * 		QUERY :
 *				DROP TABLESPACE <tablespace>
 *
 *		No need for drop behaviour as we cannot implement dependencies for
 *		objects in other databases; we can only support RESTRICT.
 *
 ****************************************************************************/

DropTableSpaceStmt: DROP TABLESPACE name
				{
					DropTableSpaceStmt *n = makeNode(DropTableSpaceStmt);
					n->tablespacename = $3;
					n->missing_ok = false;
					$$ = (Node *) n;
				}
				|  DROP TABLESPACE IF_P EXISTS name
                {
					DropTableSpaceStmt *n = makeNode(DropTableSpaceStmt);
					n->tablespacename = $5;
					n->missing_ok = true;
					$$ = (Node *) n;
				}
		;

/*****************************************************************************
 *
 * 		QUERY:
 *             CREATE FOREIGN DATA WRAPPER name [ VALIDATOR name ]
 *
 *****************************************************************************/

CreateFdwStmt: CREATE FOREIGN DATA_P WRAPPER name opt_validator create_generic_options
				{
					CreateFdwStmt *n = makeNode(CreateFdwStmt);
					n->fdwname = $5;
					n->validator = $6;
					n->options = $7;
					$$ = (Node *) n;
				}
		;

/*****************************************************************************
 *
 * 		QUERY :
 *				DROP FOREIGN DATA WRAPPER name
 *
 ****************************************************************************/

DropFdwStmt: DROP FOREIGN DATA_P WRAPPER name opt_drop_behavior
				{
					DropFdwStmt *n = makeNode(DropFdwStmt);
					n->fdwname = $5;
					n->missing_ok = false;
					n->behavior = $6;
					$$ = (Node *) n;
				}
				|  DROP FOREIGN DATA_P WRAPPER IF_P EXISTS name opt_drop_behavior
                {
					DropFdwStmt *n = makeNode(DropFdwStmt);
					n->fdwname = $7;
					n->missing_ok = true;
					n->behavior = $8;
					$$ = (Node *) n;
				}
		;

/*****************************************************************************
 *
 * 		QUERY :
 *				ALTER FOREIGN DATA WRAPPER name
 *
 ****************************************************************************/

AlterFdwStmt: ALTER FOREIGN DATA_P WRAPPER name validator_clause alter_generic_options
				{
					AlterFdwStmt *n = makeNode(AlterFdwStmt);
					n->fdwname = $5;
					n->validator = $6;
					n->change_validator = true;
					n->options = $7;
					$$ = (Node *) n;
				}
			| ALTER FOREIGN DATA_P WRAPPER name validator_clause
				{
					AlterFdwStmt *n = makeNode(AlterFdwStmt);
					n->fdwname = $5;
					n->validator = $6;
					n->change_validator = true;
					$$ = (Node *) n;
				}
			| ALTER FOREIGN DATA_P WRAPPER name alter_generic_options
				{
					AlterFdwStmt *n = makeNode(AlterFdwStmt);
					n->fdwname = $5;
					n->options = $6;
					$$ = (Node *) n;
				}
		;

/* Options definition for CREATE FDW, SERVER and USER MAPPING */
create_generic_options:
				OPTIONS '(' generic_option_list ')'			{ $$ = $3; }
				| /*EMPTY*/									{ $$ = NIL; }
		;

generic_option_list:		generic_option_elem
					{
						$$ = list_make1(makeOptionDefElem(ALTER_OPT_ADD, $1));
					}
				| generic_option_list ',' generic_option_elem
					{
						$$ = lappend($1, makeOptionDefElem(ALTER_OPT_ADD, $3));
					}
		;

/* Options definition for ALTER FDW, SERVER and USER MAPPING */
alter_generic_options:
				OPTIONS	'(' alter_generic_option_list ')'	{ $$ = $3; }
		;

alter_generic_option_list:
				alter_generic_option_elem
					{
						$$ = list_make1($1);
					}
				| generic_option_elem
					{
						$$ = list_make1(makeOptionDefElem(ALTER_OPT_ADD, $1));
					}
				| alter_generic_option_list ',' alter_generic_option_elem
					{
						$$ = lappend($1, $3);
					}
				| alter_generic_option_list ',' generic_option_elem
					{
						$$ = lappend($1, makeOptionDefElem(ALTER_OPT_ADD, $3));
					}
		;

alter_generic_option_elem:
				ADD_P generic_option_elem
					{
						$$ = makeOptionDefElem(ALTER_OPT_ADD, $2);
					}
				| SET generic_option_elem
					{
						$$ = makeOptionDefElem(ALTER_OPT_SET, $2);
					}
				| DROP generic_option_name
					{
						$$ = makeOptionDefElem(ALTER_OPT_DROP,
											   makeDefElem($2, NULL));
					}
		;

generic_option_elem:
				generic_option_name generic_option_arg			{ $$ = makeDefElem($1, $2); }
		;

generic_option_name:
				attr_name			{ $$ = $1; }
		;

generic_option_arg:
				Sconst				{ $$ = (Node *)makeString($1); }
		;

/*****************************************************************************
 *
 * 		QUERY:
 *             CREATE SERVER name [TYPE] [VERSION] [OPTIONS]
 *
 *****************************************************************************/

CreateForeignServerStmt: CREATE SERVER name opt_type opt_foreign_server_version
						 FOREIGN DATA_P WRAPPER name create_generic_options
				{
					CreateForeignServerStmt *n = makeNode(CreateForeignServerStmt);
					n->servername = $3;
					n->servertype = $4;
					n->version = $5;
					n->fdwname = $9;
					n->options = $10;
					$$ = (Node *) n;
				}
		;

opt_type:
			TYPE_P Sconst			{ $$ = $2; }
			| /*EMPTY*/				{ $$ = NULL; }
		;


foreign_server_version:
			VERSION_P Sconst		{ $$ = $2; }
		|	VERSION_P NULL_P		{ $$ = NULL; }
		;

opt_foreign_server_version:
			foreign_server_version 	{ $$ = $1; }
			| /*EMPTY*/				{ $$ = NULL; }
		;

/*****************************************************************************
 *
 * 		QUERY :
 *				DROP SERVER name
 *
 ****************************************************************************/

DropForeignServerStmt: DROP SERVER name opt_drop_behavior
				{
					DropForeignServerStmt *n = makeNode(DropForeignServerStmt);
					n->servername = $3;
					n->missing_ok = false;
					n->behavior = $4;
					$$ = (Node *) n;
				}
				|  DROP SERVER IF_P EXISTS name opt_drop_behavior
                {
					DropForeignServerStmt *n = makeNode(DropForeignServerStmt);
					n->servername = $5;
					n->missing_ok = true;
					n->behavior = $6;
					$$ = (Node *) n;
				}
		;

/*****************************************************************************
 *
 * 		QUERY :
 *				ALTER SERVER name [VERSION] [OPTIONS]
 *
 ****************************************************************************/

AlterForeignServerStmt: ALTER SERVER name foreign_server_version alter_generic_options
				{
					AlterForeignServerStmt *n = makeNode(AlterForeignServerStmt);
					n->servername = $3;
					n->version = $4;
					n->options = $5;
					n->has_version = true;
					$$ = (Node *) n;
				}
			| ALTER SERVER name foreign_server_version
				{
					AlterForeignServerStmt *n = makeNode(AlterForeignServerStmt);
					n->servername = $3;
					n->version = $4;
					n->has_version = true;
					$$ = (Node *) n;
				}
			| ALTER SERVER name alter_generic_options
				{
					AlterForeignServerStmt *n = makeNode(AlterForeignServerStmt);
					n->servername = $3;
					n->options = $4;
					$$ = (Node *) n;
				}
		;

/*****************************************************************************
 *
 * 		QUERY:
 *             CREATE USER MAPPING FOR auth_ident SERVER name [OPTIONS]
 *
 *****************************************************************************/

CreateUserMappingStmt: CREATE USER MAPPING FOR auth_ident SERVER name create_generic_options
				{
					CreateUserMappingStmt *n = makeNode(CreateUserMappingStmt);
					n->username = $5;
					n->servername = $7;
					n->options = $8;
					$$ = (Node *) n;
				}
		;

/* User mapping authorization identifier */
auth_ident:
			CURRENT_USER 	{ $$ = "current_user"; }
		|	USER			{ $$ = "current_user"; }
		|	RoleId 			{ $$ = (strcmp($1, "public") == 0) ? NULL : $1; }
		;

/*****************************************************************************
 *
 * 		QUERY :
 *				DROP USER MAPPING FOR auth_ident SERVER name
 *
 ****************************************************************************/

DropUserMappingStmt: DROP USER MAPPING FOR auth_ident SERVER name
				{
					DropUserMappingStmt *n = makeNode(DropUserMappingStmt);
					n->username = $5;
					n->servername = $7;
					n->missing_ok = false;
					$$ = (Node *) n;
				}
				|  DROP USER MAPPING IF_P EXISTS FOR auth_ident SERVER name
                {
					DropUserMappingStmt *n = makeNode(DropUserMappingStmt);
					n->username = $7;
					n->servername = $9;
					n->missing_ok = true;
					$$ = (Node *) n;
				}
		;

/*****************************************************************************
 *
 * 		QUERY :
 *				ALTER USER MAPPING FOR auth_ident SERVER name OPTIONS
 *
 ****************************************************************************/

AlterUserMappingStmt: ALTER USER MAPPING FOR auth_ident SERVER name alter_generic_options
				{
					AlterUserMappingStmt *n = makeNode(AlterUserMappingStmt);
					n->username = $5;
					n->servername = $7;
					n->options = $8;
					$$ = (Node *) n;
				}
		;

/*****************************************************************************
 *
 *		QUERIES :
 *				CREATE TRIGGER ...
 *				DROP TRIGGER ...
 *
 *****************************************************************************/

CreateTrigStmt:
			CREATE TRIGGER name TriggerActionTime TriggerEvents ON
			qualified_name TriggerForSpec EXECUTE PROCEDURE
			func_name '(' TriggerFuncArgs ')'
				{
					CreateTrigStmt *n = makeNode(CreateTrigStmt);
					n->trigname = $3;
					n->relation = $7;
					n->funcname = $11;
					n->args = $13;
					n->before = $4;
					n->row = $8;
					memcpy(n->actions, $5, 4);
					n->isconstraint  = FALSE;
					n->deferrable	 = FALSE;
					n->initdeferred  = FALSE;
					n->constrrel = NULL;
					$$ = (Node *)n;
				}
			| CREATE CONSTRAINT TRIGGER name AFTER TriggerEvents ON
			qualified_name OptConstrFromTable
			ConstraintAttributeSpec
			FOR EACH ROW EXECUTE PROCEDURE
			func_name '(' TriggerFuncArgs ')'
				{
					CreateTrigStmt *n = makeNode(CreateTrigStmt);
					n->trigname = $4;
					n->relation = $8;
					n->funcname = $16;
					n->args = $18;
					n->before = FALSE;
					n->row = TRUE;
					memcpy(n->actions, $6, 4);
					n->isconstraint  = TRUE;
					n->deferrable = ($10 & 1) != 0;
					n->initdeferred = ($10 & 2) != 0;

					n->constrrel = $9;
					$$ = (Node *)n;
				}
		;

TriggerActionTime:
			BEFORE									{ $$ = TRUE; }
			| AFTER									{ $$ = FALSE; }
		;

TriggerEvents:
			TriggerOneEvent
				{
					char *e = palloc(4);
					e[0] = $1; e[1] = '\0';
					$$ = e;
				}
			| TriggerOneEvent OR TriggerOneEvent
				{
					char *e = palloc(4);
					e[0] = $1; e[1] = $3; e[2] = '\0';
					$$ = e;
				}
			| TriggerOneEvent OR TriggerOneEvent OR TriggerOneEvent
				{
					char *e = palloc(4);
					e[0] = $1; e[1] = $3; e[2] = $5; e[3] = '\0';
					$$ = e;
				}
		;

TriggerOneEvent:
			INSERT									{ $$ = 'i'; }
			| DELETE_P								{ $$ = 'd'; }
			| UPDATE								{ $$ = 'u'; }
			| TRUNCATE								{ $$ = 't'; }
		;

TriggerForSpec:
			FOR TriggerForOpt TriggerForType
				{
					$$ = $3;
				}
			| /* EMPTY */
				{
					/*
					 * If ROW/STATEMENT not specified, default to
					 * STATEMENT, per SQL
					 */
					$$ = FALSE;
				}
		;

TriggerForOpt:
			EACH									{}
			| /*EMPTY*/								{}
		;

TriggerForType:
			ROW										{ $$ = TRUE; }
			| STATEMENT								{ $$ = FALSE; }
		;

TriggerFuncArgs:
			TriggerFuncArg							{ $$ = list_make1($1); }
			| TriggerFuncArgs ',' TriggerFuncArg	{ $$ = lappend($1, $3); }
			| /*EMPTY*/								{ $$ = NIL; }
		;

TriggerFuncArg:
			Iconst
				{
					char buf[64];
					snprintf(buf, sizeof(buf), "%d", $1);
					$$ = makeString(pstrdup(buf));
				}
			| FCONST								{ $$ = makeString($1); }
			| Sconst								{ $$ = makeString($1); }
			| BCONST								{ $$ = makeString($1); }
			| XCONST								{ $$ = makeString($1); }
			| ColId									{ $$ = makeString($1); }
		;

OptConstrFromTable:
			FROM qualified_name						{ $$ = $2; }
			| /*EMPTY*/								{ $$ = NULL; }
		;

ConstraintAttributeSpec:
			ConstraintDeferrabilitySpec
				{ $$ = $1; }
			| ConstraintDeferrabilitySpec ConstraintTimeSpec
				{
					if ($1 == 0 && $2 != 0)
						ereport(ERROR,
								(errcode(ERRCODE_SYNTAX_ERROR),
								 errmsg("constraint declared INITIALLY DEFERRED must be DEFERRABLE"),
								 scanner_errposition(@1)));
					$$ = $1 | $2;
				}
			| ConstraintTimeSpec
				{
					if ($1 != 0)
						$$ = 3;
					else
						$$ = 0;
				}
			| ConstraintTimeSpec ConstraintDeferrabilitySpec
				{
					if ($2 == 0 && $1 != 0)
						ereport(ERROR,
								(errcode(ERRCODE_SYNTAX_ERROR),
								 errmsg("constraint declared INITIALLY DEFERRED must be DEFERRABLE"),
								 scanner_errposition(@1)));
					$$ = $1 | $2;
				}
			| /*EMPTY*/
				{ $$ = 0; }
		;

ConstraintDeferrabilitySpec:
			NOT DEFERRABLE							{ $$ = 0; }
			| DEFERRABLE							{ $$ = 1; }
		;

ConstraintTimeSpec:
			INITIALLY IMMEDIATE						{ $$ = 0; }
			| INITIALLY DEFERRED					{ $$ = 2; }
		;


DropTrigStmt:
			DROP TRIGGER name ON qualified_name opt_drop_behavior
				{
					DropPropertyStmt *n = makeNode(DropPropertyStmt);
					n->relation = $5;
					n->property = $3;
					n->behavior = $6;
					n->removeType = OBJECT_TRIGGER;
					n->missing_ok = false;
					$$ = (Node *) n;
				}
			| DROP TRIGGER IF_P EXISTS name ON qualified_name opt_drop_behavior
				{
					DropPropertyStmt *n = makeNode(DropPropertyStmt);
					n->relation = $7;
					n->property = $5;
					n->behavior = $8;
					n->removeType = OBJECT_TRIGGER;
					n->missing_ok = true;
					$$ = (Node *) n;
				}
		;


/*****************************************************************************
 *
 *		QUERIES :
 *				CREATE ASSERTION ...
 *				DROP ASSERTION ...
 *
 *****************************************************************************/

CreateAssertStmt:
			CREATE ASSERTION name CHECK '(' a_expr ')'
			ConstraintAttributeSpec
				{
					CreateTrigStmt *n = makeNode(CreateTrigStmt);
					n->trigname = $3;
					n->args = list_make1($6);
					n->isconstraint  = TRUE;
					n->deferrable = ($8 & 1) != 0;
					n->initdeferred = ($8 & 2) != 0;

					ereport(ERROR,
							(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
							 errmsg("CREATE ASSERTION is not yet implemented")));

					$$ = (Node *)n;
				}
		;

DropAssertStmt:
			DROP ASSERTION name opt_drop_behavior
				{
					DropPropertyStmt *n = makeNode(DropPropertyStmt);
					n->relation = NULL;
					n->property = $3;
					n->behavior = $4;
					n->removeType = OBJECT_TRIGGER; /* XXX */
					ereport(ERROR,
							(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
							 errmsg("DROP ASSERTION is not yet implemented")));
					$$ = (Node *) n;
				}
		;


/*****************************************************************************
 *
 *		QUERY :
 *				define (aggregate,operator,type)
 *
 *****************************************************************************/

DefineStmt:
			CREATE AGGREGATE func_name aggr_args definition
				{
					DefineStmt *n = makeNode(DefineStmt);
					n->kind = OBJECT_AGGREGATE;
					n->oldstyle = false;
					n->defnames = $3;
					n->args = $4;
					n->definition = $5;
					$$ = (Node *)n;
				}
			| CREATE AGGREGATE func_name old_aggr_definition
				{
					/* old-style (pre-8.2) syntax for CREATE AGGREGATE */
					DefineStmt *n = makeNode(DefineStmt);
					n->kind = OBJECT_AGGREGATE;
					n->oldstyle = true;
					n->defnames = $3;
					n->args = NIL;
					n->definition = $4;
					$$ = (Node *)n;
				}
			| CREATE OPERATOR any_operator definition
				{
					DefineStmt *n = makeNode(DefineStmt);
					n->kind = OBJECT_OPERATOR;
					n->oldstyle = false;
					n->defnames = $3;
					n->args = NIL;
					n->definition = $4;
					$$ = (Node *)n;
				}
			| CREATE TYPE_P any_name definition
				{
					DefineStmt *n = makeNode(DefineStmt);
					n->kind = OBJECT_TYPE;
					n->oldstyle = false;
					n->defnames = $3;
					n->args = NIL;
					n->definition = $4;
					$$ = (Node *)n;
				}
			| CREATE TYPE_P any_name
				{
					/* Shell type (identified by lack of definition) */
					DefineStmt *n = makeNode(DefineStmt);
					n->kind = OBJECT_TYPE;
					n->oldstyle = false;
					n->defnames = $3;
					n->args = NIL;
					n->definition = NIL;
					$$ = (Node *)n;
				}
			| CREATE TYPE_P any_name AS '(' TableFuncElementList ')'
				{
					CompositeTypeStmt *n = makeNode(CompositeTypeStmt);
					RangeVar *r = makeNode(RangeVar);

					/* can't use qualified_name, sigh */
					switch (list_length($3))
					{
						case 1:
							r->catalogname = NULL;
							r->schemaname = NULL;
							r->relname = strVal(linitial($3));
							break;
						case 2:
							r->catalogname = NULL;
							r->schemaname = strVal(linitial($3));
							r->relname = strVal(lsecond($3));
							break;
						case 3:
							r->catalogname = strVal(linitial($3));
							r->schemaname = strVal(lsecond($3));
							r->relname = strVal(lthird($3));
							break;
						default:
							ereport(ERROR,
									(errcode(ERRCODE_SYNTAX_ERROR),
									 errmsg("improper qualified name (too many dotted names): %s",
											NameListToString($3)),
											scanner_errposition(@3)));
							break;
					}
					r->location = @3;
					n->typevar = r;
					n->coldeflist = $6;
					$$ = (Node *)n;
				}
			| CREATE TYPE_P any_name AS ENUM_P '(' enum_val_list ')'
				{
					CreateEnumStmt *n = makeNode(CreateEnumStmt);
					n->typename = $3;
					n->vals = $7;
					$$ = (Node *)n;
				}
			| CREATE TEXT_P SEARCH PARSER any_name definition
				{
					DefineStmt *n = makeNode(DefineStmt);
					n->kind = OBJECT_TSPARSER;
					n->args = NIL;
					n->defnames = $5;
					n->definition = $6;
					$$ = (Node *)n;
				}
			| CREATE TEXT_P SEARCH DICTIONARY any_name definition
				{
					DefineStmt *n = makeNode(DefineStmt);
					n->kind = OBJECT_TSDICTIONARY;
					n->args = NIL;
					n->defnames = $5;
					n->definition = $6;
					$$ = (Node *)n;
				}
			| CREATE TEXT_P SEARCH TEMPLATE any_name definition
				{
					DefineStmt *n = makeNode(DefineStmt);
					n->kind = OBJECT_TSTEMPLATE;
					n->args = NIL;
					n->defnames = $5;
					n->definition = $6;
					$$ = (Node *)n;
				}
			| CREATE TEXT_P SEARCH CONFIGURATION any_name definition
				{
					DefineStmt *n = makeNode(DefineStmt);
					n->kind = OBJECT_TSCONFIGURATION;
					n->args = NIL;
					n->defnames = $5;
					n->definition = $6;
					$$ = (Node *)n;
				}
		;

definition: '(' def_list ')'						{ $$ = $2; }
		;

def_list:  	def_elem								{ $$ = list_make1($1); }
			| def_list ',' def_elem					{ $$ = lappend($1, $3); }
		;

def_elem:  ColLabel '=' def_arg
				{
					$$ = makeDefElem($1, (Node *)$3);
				}
			| ColLabel
				{
					$$ = makeDefElem($1, NULL);
				}
		;

/* Note: any simple identifier will be returned as a type name! */
def_arg:	func_type						{ $$ = (Node *)$1; }
			| reserved_keyword				{ $$ = (Node *)makeString(pstrdup($1)); }
			| qual_all_Op					{ $$ = (Node *)$1; }
			| NumericOnly					{ $$ = (Node *)$1; }
			| Sconst						{ $$ = (Node *)makeString($1); }
		;

aggr_args:	'(' type_list ')'						{ $$ = $2; }
			| '(' '*' ')'							{ $$ = NIL; }
		;

old_aggr_definition: '(' old_aggr_list ')'			{ $$ = $2; }
		;

old_aggr_list: old_aggr_elem						{ $$ = list_make1($1); }
			| old_aggr_list ',' old_aggr_elem		{ $$ = lappend($1, $3); }
		;

/*
 * Must use IDENT here to avoid reduce/reduce conflicts; fortunately none of
 * the item names needed in old aggregate definitions are likely to become
 * SQL keywords.
 */
old_aggr_elem:  IDENT '=' def_arg
				{
					$$ = makeDefElem($1, (Node *)$3);
				}
		;

enum_val_list:	Sconst
				{ $$ = list_make1(makeString($1)); }
			| enum_val_list ',' Sconst
				{ $$ = lappend($1, makeString($3)); }
		;


/*****************************************************************************
 *
 *		QUERIES :
 *				CREATE OPERATOR CLASS ...
 *				CREATE OPERATOR FAMILY ...
 *				ALTER OPERATOR FAMILY ...
 *				DROP OPERATOR CLASS ...
 *				DROP OPERATOR FAMILY ...
 *
 *****************************************************************************/

CreateOpClassStmt:
			CREATE OPERATOR CLASS any_name opt_default FOR TYPE_P Typename
			USING access_method opt_opfamily AS opclass_item_list
				{
					CreateOpClassStmt *n = makeNode(CreateOpClassStmt);
					n->opclassname = $4;
					n->isDefault = $5;
					n->datatype = $8;
					n->amname = $10;
					n->opfamilyname = $11;
					n->items = $13;
					$$ = (Node *) n;
				}
		;

opclass_item_list:
			opclass_item							{ $$ = list_make1($1); }
			| opclass_item_list ',' opclass_item	{ $$ = lappend($1, $3); }
		;

opclass_item:
			OPERATOR Iconst any_operator opt_recheck
				{
					CreateOpClassItem *n = makeNode(CreateOpClassItem);
					n->itemtype = OPCLASS_ITEM_OPERATOR;
					n->name = $3;
					n->args = NIL;
					n->number = $2;
					$$ = (Node *) n;
				}
			| OPERATOR Iconst any_operator oper_argtypes opt_recheck
				{
					CreateOpClassItem *n = makeNode(CreateOpClassItem);
					n->itemtype = OPCLASS_ITEM_OPERATOR;
					n->name = $3;
					n->args = $4;
					n->number = $2;
					$$ = (Node *) n;
				}
			| FUNCTION Iconst func_name func_args
				{
					CreateOpClassItem *n = makeNode(CreateOpClassItem);
					n->itemtype = OPCLASS_ITEM_FUNCTION;
					n->name = $3;
					n->args = extractArgTypes($4);
					n->number = $2;
					$$ = (Node *) n;
				}
			| FUNCTION Iconst '(' type_list ')' func_name func_args
				{
					CreateOpClassItem *n = makeNode(CreateOpClassItem);
					n->itemtype = OPCLASS_ITEM_FUNCTION;
					n->name = $6;
					n->args = extractArgTypes($7);
					n->number = $2;
					n->class_args = $4;
					$$ = (Node *) n;
				}
			| STORAGE Typename
				{
					CreateOpClassItem *n = makeNode(CreateOpClassItem);
					n->itemtype = OPCLASS_ITEM_STORAGETYPE;
					n->storedtype = $2;
					$$ = (Node *) n;
				}
		;

opt_default:	DEFAULT						{ $$ = TRUE; }
			| /*EMPTY*/						{ $$ = FALSE; }
		;

opt_opfamily:	FAMILY any_name				{ $$ = $2; }
			| /*EMPTY*/						{ $$ = NIL; }
		;

opt_recheck:	RECHECK
				{
					ereport(ERROR,
							(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
							 errmsg("RECHECK is no longer supported"),
							 errhint("Update your data type."),
							 scanner_errposition(@1)));
					$$ = TRUE;
				}
			| /*EMPTY*/						{ $$ = FALSE; }
		;


CreateOpFamilyStmt:
			CREATE OPERATOR FAMILY any_name USING access_method
				{
					CreateOpFamilyStmt *n = makeNode(CreateOpFamilyStmt);
					n->opfamilyname = $4;
					n->amname = $6;
					$$ = (Node *) n;
				}
		;

AlterOpFamilyStmt:
			ALTER OPERATOR FAMILY any_name USING access_method ADD_P opclass_item_list
				{
					AlterOpFamilyStmt *n = makeNode(AlterOpFamilyStmt);
					n->opfamilyname = $4;
					n->amname = $6;
					n->isDrop = false;
					n->items = $8;
					$$ = (Node *) n;
				}
			| ALTER OPERATOR FAMILY any_name USING access_method DROP opclass_drop_list
				{
					AlterOpFamilyStmt *n = makeNode(AlterOpFamilyStmt);
					n->opfamilyname = $4;
					n->amname = $6;
					n->isDrop = true;
					n->items = $8;
					$$ = (Node *) n;
				}
		;

opclass_drop_list:
			opclass_drop							{ $$ = list_make1($1); }
			| opclass_drop_list ',' opclass_drop	{ $$ = lappend($1, $3); }
		;

opclass_drop:
			OPERATOR Iconst '(' type_list ')'
				{
					CreateOpClassItem *n = makeNode(CreateOpClassItem);
					n->itemtype = OPCLASS_ITEM_OPERATOR;
					n->number = $2;
					n->args = $4;
					$$ = (Node *) n;
				}
			| FUNCTION Iconst '(' type_list ')'
				{
					CreateOpClassItem *n = makeNode(CreateOpClassItem);
					n->itemtype = OPCLASS_ITEM_FUNCTION;
					n->number = $2;
					n->args = $4;
					$$ = (Node *) n;
				}
		;


DropOpClassStmt:
			DROP OPERATOR CLASS any_name USING access_method opt_drop_behavior
				{
					RemoveOpClassStmt *n = makeNode(RemoveOpClassStmt);
					n->opclassname = $4;
					n->amname = $6;
					n->behavior = $7;
					n->missing_ok = false;
					$$ = (Node *) n;
				}
			| DROP OPERATOR CLASS IF_P EXISTS any_name USING access_method opt_drop_behavior
				{
					RemoveOpClassStmt *n = makeNode(RemoveOpClassStmt);
					n->opclassname = $6;
					n->amname = $8;
					n->behavior = $9;
					n->missing_ok = true;
					$$ = (Node *) n;
				}
		;

DropOpFamilyStmt:
			DROP OPERATOR FAMILY any_name USING access_method opt_drop_behavior
				{
					RemoveOpFamilyStmt *n = makeNode(RemoveOpFamilyStmt);
					n->opfamilyname = $4;
					n->amname = $6;
					n->behavior = $7;
					n->missing_ok = false;
					$$ = (Node *) n;
				}
			| DROP OPERATOR FAMILY IF_P EXISTS any_name USING access_method opt_drop_behavior
				{
					RemoveOpFamilyStmt *n = makeNode(RemoveOpFamilyStmt);
					n->opfamilyname = $6;
					n->amname = $8;
					n->behavior = $9;
					n->missing_ok = true;
					$$ = (Node *) n;
				}
		;


/*****************************************************************************
 *
 *		QUERY:
 *
 *		DROP OWNED BY username [, username ...] [ RESTRICT | CASCADE ]
 *		REASSIGN OWNED BY username [, username ...] TO username
 *
 *****************************************************************************/
DropOwnedStmt:
			DROP OWNED BY name_list opt_drop_behavior
			 	{
					DropOwnedStmt *n = makeNode(DropOwnedStmt);
					n->roles = $4;
					n->behavior = $5;
					$$ = (Node *)n;
				}
		;

ReassignOwnedStmt:
			REASSIGN OWNED BY name_list TO name
				{
					ReassignOwnedStmt *n = makeNode(ReassignOwnedStmt);
					n->roles = $4;
					n->newrole = $6;
					$$ = (Node *)n;
				}
		;

/*****************************************************************************
 *
 *		QUERY:
 *
 *		DROP itemtype [ IF EXISTS ] itemname [, itemname ...]
 *           [ RESTRICT | CASCADE ]
 *
 *****************************************************************************/

DropStmt:	DROP drop_type IF_P EXISTS any_name_list opt_drop_behavior
				{
					DropStmt *n = makeNode(DropStmt);
					n->removeType = $2;
					n->missing_ok = TRUE;
					n->objects = $5;
					n->behavior = $6;
					$$ = (Node *)n;
				}
			| DROP drop_type any_name_list opt_drop_behavior
				{
					DropStmt *n = makeNode(DropStmt);
					n->removeType = $2;
					n->missing_ok = FALSE;
					n->objects = $3;
					n->behavior = $4;
					$$ = (Node *)n;
				}
		;


drop_type:	TABLE									{ $$ = OBJECT_TABLE; }
			| SEQUENCE								{ $$ = OBJECT_SEQUENCE; }
			| VIEW									{ $$ = OBJECT_VIEW; }
			| INDEX									{ $$ = OBJECT_INDEX; }
			| TYPE_P								{ $$ = OBJECT_TYPE; }
			| DOMAIN_P								{ $$ = OBJECT_DOMAIN; }
			| CONVERSION_P							{ $$ = OBJECT_CONVERSION; }
			| SCHEMA								{ $$ = OBJECT_SCHEMA; }
			| TEXT_P SEARCH PARSER					{ $$ = OBJECT_TSPARSER; }
			| TEXT_P SEARCH DICTIONARY				{ $$ = OBJECT_TSDICTIONARY; }
			| TEXT_P SEARCH TEMPLATE				{ $$ = OBJECT_TSTEMPLATE; }
			| TEXT_P SEARCH CONFIGURATION			{ $$ = OBJECT_TSCONFIGURATION; }
		;

any_name_list:
			any_name								{ $$ = list_make1($1); }
			| any_name_list ',' any_name			{ $$ = lappend($1, $3); }
		;

any_name:	ColId						{ $$ = list_make1(makeString($1)); }
			| ColId attrs				{ $$ = lcons(makeString($1), $2); }
		;

attrs:		'.' attr_name
					{ $$ = list_make1(makeString($2)); }
			| attrs '.' attr_name
					{ $$ = lappend($1, makeString($3)); }
		;


/*****************************************************************************
 *
 *		QUERY:
 *				truncate table relname1, relname2, ...
 *
 *****************************************************************************/

TruncateStmt:
			TRUNCATE opt_table relation_expr_list opt_restart_seqs opt_drop_behavior
				{
					TruncateStmt *n = makeNode(TruncateStmt);
					n->relations = $3;
					n->restart_seqs = $4;
					n->behavior = $5;
					$$ = (Node *)n;
				}
		;

opt_restart_seqs:
			CONTINUE_P IDENTITY_P		{ $$ = false; }
			| RESTART IDENTITY_P		{ $$ = true; }
			| /* EMPTY */				{ $$ = false; }
		;

/*****************************************************************************
 *
 *	The COMMENT ON statement can take different forms based upon the type of
 *	the object associated with the comment. The form of the statement is:
 *
 *	COMMENT ON [ [ DATABASE | DOMAIN | INDEX | SEQUENCE | TABLE | TYPE | VIEW |
 *				   CONVERSION | LANGUAGE | OPERATOR CLASS | LARGE OBJECT |
 *				   CAST | COLUMN | SCHEMA | TABLESPACE | ROLE |
 *				   TEXT SEARCH PARSER | TEXT SEARCH DICTIONARY |
 *				   TEXT SEARCH TEMPLATE |
 *				   TEXT SEARCH CONFIGURATION ] <objname> |
 *				 AGGREGATE <aggname> (arg1, ...) |
 *				 FUNCTION <funcname> (arg1, arg2, ...) |
 *				 OPERATOR <op> (leftoperand_typ, rightoperand_typ) |
 *				 TRIGGER <triggername> ON <relname> |
 *				 CONSTRAINT <constraintname> ON <relname> |
 *				 RULE <rulename> ON <relname> ]
 *			   IS 'text'
 *
 *****************************************************************************/

CommentStmt:
			COMMENT ON comment_type any_name IS comment_text
				{
					CommentStmt *n = makeNode(CommentStmt);
					n->objtype = $3;
					n->objname = $4;
					n->objargs = NIL;
					n->comment = $6;
					$$ = (Node *) n;
				}
			| COMMENT ON AGGREGATE func_name aggr_args IS comment_text
				{
					CommentStmt *n = makeNode(CommentStmt);
					n->objtype = OBJECT_AGGREGATE;
					n->objname = $4;
					n->objargs = $5;
					n->comment = $7;
					$$ = (Node *) n;
				}
			| COMMENT ON FUNCTION func_name func_args IS comment_text
				{
					CommentStmt *n = makeNode(CommentStmt);
					n->objtype = OBJECT_FUNCTION;
					n->objname = $4;
					n->objargs = extractArgTypes($5);
					n->comment = $7;
					$$ = (Node *) n;
				}
			| COMMENT ON OPERATOR any_operator oper_argtypes IS comment_text
				{
					CommentStmt *n = makeNode(CommentStmt);
					n->objtype = OBJECT_OPERATOR;
					n->objname = $4;
					n->objargs = $5;
					n->comment = $7;
					$$ = (Node *) n;
				}
			| COMMENT ON CONSTRAINT name ON any_name IS comment_text
				{
					CommentStmt *n = makeNode(CommentStmt);
					n->objtype = OBJECT_CONSTRAINT;
					n->objname = lappend($6, makeString($4));
					n->objargs = NIL;
					n->comment = $8;
					$$ = (Node *) n;
				}
			| COMMENT ON RULE name ON any_name IS comment_text
				{
					CommentStmt *n = makeNode(CommentStmt);
					n->objtype = OBJECT_RULE;
					n->objname = lappend($6, makeString($4));
					n->objargs = NIL;
					n->comment = $8;
					$$ = (Node *) n;
				}
			| COMMENT ON RULE name IS comment_text
				{
					/* Obsolete syntax supported for awhile for compatibility */
					CommentStmt *n = makeNode(CommentStmt);
					n->objtype = OBJECT_RULE;
					n->objname = list_make1(makeString($4));
					n->objargs = NIL;
					n->comment = $6;
					$$ = (Node *) n;
				}
			| COMMENT ON TRIGGER name ON any_name IS comment_text
				{
					CommentStmt *n = makeNode(CommentStmt);
					n->objtype = OBJECT_TRIGGER;
					n->objname = lappend($6, makeString($4));
					n->objargs = NIL;
					n->comment = $8;
					$$ = (Node *) n;
				}
			| COMMENT ON OPERATOR CLASS any_name USING access_method IS comment_text
				{
					CommentStmt *n = makeNode(CommentStmt);
					n->objtype = OBJECT_OPCLASS;
					n->objname = $5;
					n->objargs = list_make1(makeString($7));
					n->comment = $9;
					$$ = (Node *) n;
				}
			| COMMENT ON OPERATOR FAMILY any_name USING access_method IS comment_text
				{
					CommentStmt *n = makeNode(CommentStmt);
					n->objtype = OBJECT_OPFAMILY;
					n->objname = $5;
					n->objargs = list_make1(makeString($7));
					n->comment = $9;
					$$ = (Node *) n;
				}
			| COMMENT ON LARGE_P OBJECT_P NumericOnly IS comment_text
				{
					CommentStmt *n = makeNode(CommentStmt);
					n->objtype = OBJECT_LARGEOBJECT;
					n->objname = list_make1($5);
					n->objargs = NIL;
					n->comment = $7;
					$$ = (Node *) n;
				}
			| COMMENT ON CAST '(' Typename AS Typename ')' IS comment_text
				{
					CommentStmt *n = makeNode(CommentStmt);
					n->objtype = OBJECT_CAST;
					n->objname = list_make1($5);
					n->objargs = list_make1($7);
					n->comment = $10;
					$$ = (Node *) n;
				}
			| COMMENT ON opt_procedural LANGUAGE any_name IS comment_text
				{
					CommentStmt *n = makeNode(CommentStmt);
					n->objtype = OBJECT_LANGUAGE;
					n->objname = $5;
					n->objargs = NIL;
					n->comment = $7;
					$$ = (Node *) n;
				}
			| COMMENT ON TEXT_P SEARCH PARSER any_name IS comment_text
				{
					CommentStmt *n = makeNode(CommentStmt);
					n->objtype = OBJECT_TSPARSER;
					n->objname = $6;
					n->comment = $8;
					$$ = (Node *) n;
				}
			| COMMENT ON TEXT_P SEARCH DICTIONARY any_name IS comment_text
				{
					CommentStmt *n = makeNode(CommentStmt);
					n->objtype = OBJECT_TSDICTIONARY;
					n->objname = $6;
					n->comment = $8;
					$$ = (Node *) n;
				}
			| COMMENT ON TEXT_P SEARCH TEMPLATE any_name IS comment_text
				{
					CommentStmt *n = makeNode(CommentStmt);
					n->objtype = OBJECT_TSTEMPLATE;
					n->objname = $6;
					n->comment = $8;
					$$ = (Node *) n;
				}
			| COMMENT ON TEXT_P SEARCH CONFIGURATION any_name IS comment_text
				{
					CommentStmt *n = makeNode(CommentStmt);
					n->objtype = OBJECT_TSCONFIGURATION;
					n->objname = $6;
					n->comment = $8;
					$$ = (Node *) n;
				}
		;

comment_type:
			COLUMN								{ $$ = OBJECT_COLUMN; }
			| DATABASE							{ $$ = OBJECT_DATABASE; }
			| SCHEMA							{ $$ = OBJECT_SCHEMA; }
			| INDEX								{ $$ = OBJECT_INDEX; }
			| SEQUENCE							{ $$ = OBJECT_SEQUENCE; }
			| TABLE								{ $$ = OBJECT_TABLE; }
			| DOMAIN_P							{ $$ = OBJECT_TYPE; }
			| TYPE_P							{ $$ = OBJECT_TYPE; }
			| VIEW								{ $$ = OBJECT_VIEW; }
			| CONVERSION_P						{ $$ = OBJECT_CONVERSION; }
			| TABLESPACE						{ $$ = OBJECT_TABLESPACE; }
			| ROLE								{ $$ = OBJECT_ROLE; }
		;

comment_text:
			Sconst								{ $$ = $1; }
			| NULL_P							{ $$ = NULL; }
		;

/*****************************************************************************
 *
 *		QUERY:
 *			fetch/move
 *
 *****************************************************************************/

FetchStmt:	FETCH fetch_direction from_in name
				{
					FetchStmt *n = (FetchStmt *) $2;
					n->portalname = $4;
					n->ismove = FALSE;
					$$ = (Node *)n;
				}
			| FETCH name
				{
					FetchStmt *n = makeNode(FetchStmt);
					n->direction = FETCH_FORWARD;
					n->howMany = 1;
					n->portalname = $2;
					n->ismove = FALSE;
					$$ = (Node *)n;
				}
			| MOVE fetch_direction from_in name
				{
					FetchStmt *n = (FetchStmt *) $2;
					n->portalname = $4;
					n->ismove = TRUE;
					$$ = (Node *)n;
				}
			| MOVE name
				{
					FetchStmt *n = makeNode(FetchStmt);
					n->direction = FETCH_FORWARD;
					n->howMany = 1;
					n->portalname = $2;
					n->ismove = TRUE;
					$$ = (Node *)n;
				}
		;

fetch_direction:
			/*EMPTY*/
				{
					FetchStmt *n = makeNode(FetchStmt);
					n->direction = FETCH_FORWARD;
					n->howMany = 1;
					$$ = (Node *)n;
				}
			| NEXT
				{
					FetchStmt *n = makeNode(FetchStmt);
					n->direction = FETCH_FORWARD;
					n->howMany = 1;
					$$ = (Node *)n;
				}
			| PRIOR
				{
					FetchStmt *n = makeNode(FetchStmt);
					n->direction = FETCH_BACKWARD;
					n->howMany = 1;
					$$ = (Node *)n;
				}
			| FIRST_P
				{
					FetchStmt *n = makeNode(FetchStmt);
					n->direction = FETCH_ABSOLUTE;
					n->howMany = 1;
					$$ = (Node *)n;
				}
			| LAST_P
				{
					FetchStmt *n = makeNode(FetchStmt);
					n->direction = FETCH_ABSOLUTE;
					n->howMany = -1;
					$$ = (Node *)n;
				}
			| ABSOLUTE_P SignedIconst
				{
					FetchStmt *n = makeNode(FetchStmt);
					n->direction = FETCH_ABSOLUTE;
					n->howMany = $2;
					$$ = (Node *)n;
				}
			| RELATIVE_P SignedIconst
				{
					FetchStmt *n = makeNode(FetchStmt);
					n->direction = FETCH_RELATIVE;
					n->howMany = $2;
					$$ = (Node *)n;
				}
			| SignedIconst
				{
					FetchStmt *n = makeNode(FetchStmt);
					n->direction = FETCH_FORWARD;
					n->howMany = $1;
					$$ = (Node *)n;
				}
			| ALL
				{
					FetchStmt *n = makeNode(FetchStmt);
					n->direction = FETCH_FORWARD;
					n->howMany = FETCH_ALL;
					$$ = (Node *)n;
				}
			| FORWARD
				{
					FetchStmt *n = makeNode(FetchStmt);
					n->direction = FETCH_FORWARD;
					n->howMany = 1;
					$$ = (Node *)n;
				}
			| FORWARD SignedIconst
				{
					FetchStmt *n = makeNode(FetchStmt);
					n->direction = FETCH_FORWARD;
					n->howMany = $2;
					$$ = (Node *)n;
				}
			| FORWARD ALL
				{
					FetchStmt *n = makeNode(FetchStmt);
					n->direction = FETCH_FORWARD;
					n->howMany = FETCH_ALL;
					$$ = (Node *)n;
				}
			| BACKWARD
				{
					FetchStmt *n = makeNode(FetchStmt);
					n->direction = FETCH_BACKWARD;
					n->howMany = 1;
					$$ = (Node *)n;
				}
			| BACKWARD SignedIconst
				{
					FetchStmt *n = makeNode(FetchStmt);
					n->direction = FETCH_BACKWARD;
					n->howMany = $2;
					$$ = (Node *)n;
				}
			| BACKWARD ALL
				{
					FetchStmt *n = makeNode(FetchStmt);
					n->direction = FETCH_BACKWARD;
					n->howMany = FETCH_ALL;
					$$ = (Node *)n;
				}
		;

from_in:	FROM									{}
			| IN_P									{}
		;


/*****************************************************************************
 *
 * GRANT and REVOKE statements
 *
 *****************************************************************************/

GrantStmt:	GRANT privileges ON privilege_target TO grantee_list
			opt_grant_grant_option
				{
					GrantStmt *n = makeNode(GrantStmt);
					n->is_grant = true;
					n->privileges = $2;
					n->objtype = ($4)->objtype;
					n->objects = ($4)->objs;
					n->grantees = $6;
					n->grant_option = $7;
					$$ = (Node*)n;
				}
		;

RevokeStmt:
			REVOKE privileges ON privilege_target
			FROM grantee_list opt_drop_behavior
				{
					GrantStmt *n = makeNode(GrantStmt);
					n->is_grant = false;
					n->grant_option = false;
					n->privileges = $2;
					n->objtype = ($4)->objtype;
					n->objects = ($4)->objs;
					n->grantees = $6;
					n->behavior = $7;
					$$ = (Node *)n;
				}
			| REVOKE GRANT OPTION FOR privileges ON privilege_target
			FROM grantee_list opt_drop_behavior
				{
					GrantStmt *n = makeNode(GrantStmt);
					n->is_grant = false;
					n->grant_option = true;
					n->privileges = $5;
					n->objtype = ($7)->objtype;
					n->objects = ($7)->objs;
					n->grantees = $9;
					n->behavior = $10;
					$$ = (Node *)n;
				}
		;


/*
 * Privilege names are represented as strings; the validity of the privilege
 * names gets checked at execution.  This is a bit annoying but we have little
 * choice because of the syntactic conflict with lists of role names in
 * GRANT/REVOKE.  What's more, we have to call out in the "privilege"
 * production any reserved keywords that need to be usable as privilege names.
 */

/* either ALL [PRIVILEGES] or a list of individual privileges */
privileges: privilege_list
				{ $$ = $1; }
			| ALL
				{ $$ = NIL; }
			| ALL PRIVILEGES
				{ $$ = NIL; }
			| ALL '(' columnList ')'
				{
					AccessPriv *n = makeNode(AccessPriv);
					n->priv_name = NULL;
					n->cols = $3;
					$$ = list_make1(n);
				}
			| ALL PRIVILEGES '(' columnList ')'
				{
					AccessPriv *n = makeNode(AccessPriv);
					n->priv_name = NULL;
					n->cols = $4;
					$$ = list_make1(n);
				}
		;

privilege_list:	privilege							{ $$ = list_make1($1); }
			| privilege_list ',' privilege			{ $$ = lappend($1, $3); }
		;

privilege:	SELECT opt_column_list
			{
				AccessPriv *n = makeNode(AccessPriv);
				n->priv_name = pstrdup($1);
				n->cols = $2;
				$$ = n;
			}
		| REFERENCES opt_column_list
			{
				AccessPriv *n = makeNode(AccessPriv);
				n->priv_name = pstrdup($1);
				n->cols = $2;
				$$ = n;
			}
		| CREATE opt_column_list
			{
				AccessPriv *n = makeNode(AccessPriv);
				n->priv_name = pstrdup($1);
				n->cols = $2;
				$$ = n;
			}
		| ColId opt_column_list
			{
				AccessPriv *n = makeNode(AccessPriv);
				n->priv_name = $1;
				n->cols = $2;
				$$ = n;
			}
		;


/* Don't bother trying to fold the first two rules into one using
 * opt_table.  You're going to get conflicts.
 */
privilege_target:
			qualified_name_list
				{
					PrivTarget *n = (PrivTarget *) palloc(sizeof(PrivTarget));
					n->objtype = ACL_OBJECT_RELATION;
					n->objs = $1;
					$$ = n;
				}
			| TABLE qualified_name_list
				{
					PrivTarget *n = (PrivTarget *) palloc(sizeof(PrivTarget));
					n->objtype = ACL_OBJECT_RELATION;
					n->objs = $2;
					$$ = n;
				}
			| SEQUENCE qualified_name_list
				{
					PrivTarget *n = (PrivTarget *) palloc(sizeof(PrivTarget));
					n->objtype = ACL_OBJECT_SEQUENCE;
					n->objs = $2;
					$$ = n;
				}
			| FOREIGN DATA_P WRAPPER name_list
				{
					PrivTarget *n = (PrivTarget *) palloc(sizeof(PrivTarget));
					n->objtype = ACL_OBJECT_FDW;
					n->objs = $4;
					$$ = n;
				}
			| FOREIGN SERVER name_list
				{
					PrivTarget *n = (PrivTarget *) palloc(sizeof(PrivTarget));
					n->objtype = ACL_OBJECT_FOREIGN_SERVER;
					n->objs = $3;
					$$ = n;
				}
			| FUNCTION function_with_argtypes_list
				{
					PrivTarget *n = (PrivTarget *) palloc(sizeof(PrivTarget));
					n->objtype = ACL_OBJECT_FUNCTION;
					n->objs = $2;
					$$ = n;
				}
			| DATABASE name_list
				{
					PrivTarget *n = (PrivTarget *) palloc(sizeof(PrivTarget));
					n->objtype = ACL_OBJECT_DATABASE;
					n->objs = $2;
					$$ = n;
				}
			| LANGUAGE name_list
				{
					PrivTarget *n = (PrivTarget *) palloc(sizeof(PrivTarget));
					n->objtype = ACL_OBJECT_LANGUAGE;
					n->objs = $2;
					$$ = n;
				}
			| SCHEMA name_list
				{
					PrivTarget *n = (PrivTarget *) palloc(sizeof(PrivTarget));
					n->objtype = ACL_OBJECT_NAMESPACE;
					n->objs = $2;
					$$ = n;
				}
			| TABLESPACE name_list
				{
					PrivTarget *n = (PrivTarget *) palloc(sizeof(PrivTarget));
					n->objtype = ACL_OBJECT_TABLESPACE;
					n->objs = $2;
					$$ = n;
				}
		;


grantee_list:
			grantee									{ $$ = list_make1($1); }
			| grantee_list ',' grantee				{ $$ = lappend($1, $3); }
		;

grantee:	RoleId
				{
					PrivGrantee *n = makeNode(PrivGrantee);
					/* This hack lets us avoid reserving PUBLIC as a keyword*/
					if (strcmp($1, "public") == 0)
						n->rolname = NULL;
					else
						n->rolname = $1;
					$$ = (Node *)n;
				}
			| GROUP_P RoleId
				{
					PrivGrantee *n = makeNode(PrivGrantee);
					/* Treat GROUP PUBLIC as a synonym for PUBLIC */
					if (strcmp($2, "public") == 0)
						n->rolname = NULL;
					else
						n->rolname = $2;
					$$ = (Node *)n;
				}
		;


opt_grant_grant_option:
			WITH GRANT OPTION { $$ = TRUE; }
			| /*EMPTY*/ { $$ = FALSE; }
		;

function_with_argtypes_list:
			function_with_argtypes					{ $$ = list_make1($1); }
			| function_with_argtypes_list ',' function_with_argtypes
													{ $$ = lappend($1, $3); }
		;

function_with_argtypes:
			func_name func_args
				{
					FuncWithArgs *n = makeNode(FuncWithArgs);
					n->funcname = $1;
					n->funcargs = extractArgTypes($2);
					$$ = n;
				}
		;

/*****************************************************************************
 *
 * GRANT and REVOKE ROLE statements
 *
 *****************************************************************************/

GrantRoleStmt:
			GRANT privilege_list TO name_list opt_grant_admin_option opt_granted_by
				{
					GrantRoleStmt *n = makeNode(GrantRoleStmt);
					n->is_grant = true;
					n->granted_roles = $2;
					n->grantee_roles = $4;
					n->admin_opt = $5;
					n->grantor = $6;
					$$ = (Node*)n;
				}
		;

RevokeRoleStmt:
			REVOKE privilege_list FROM name_list opt_granted_by opt_drop_behavior
				{
					GrantRoleStmt *n = makeNode(GrantRoleStmt);
					n->is_grant = false;
					n->admin_opt = false;
					n->granted_roles = $2;
					n->grantee_roles = $4;
					n->behavior = $6;
					$$ = (Node*)n;
				}
			| REVOKE ADMIN OPTION FOR privilege_list FROM name_list opt_granted_by opt_drop_behavior
				{
					GrantRoleStmt *n = makeNode(GrantRoleStmt);
					n->is_grant = false;
					n->admin_opt = true;
					n->granted_roles = $5;
					n->grantee_roles = $7;
					n->behavior = $9;
					$$ = (Node*)n;
				}
		;

opt_grant_admin_option: WITH ADMIN OPTION				{ $$ = TRUE; }
			| /*EMPTY*/									{ $$ = FALSE; }
		;

opt_granted_by: GRANTED BY RoleId						{ $$ = $3; }
			| /*EMPTY*/									{ $$ = NULL; }
		;


/*****************************************************************************
 *
 *		QUERY: CREATE INDEX
 *
 * Note: we can't factor CONCURRENTLY into a separate production without
 * making it a reserved word.
 *
 * Note: we cannot put TABLESPACE clause after WHERE clause unless we are
 * willing to make TABLESPACE a fully reserved word.
 *****************************************************************************/

IndexStmt:	CREATE index_opt_unique INDEX index_name
			ON qualified_name access_method_clause '(' index_params ')'
			opt_reloptions OptTableSpace where_clause
				{
					IndexStmt *n = makeNode(IndexStmt);
					n->unique = $2;
					n->concurrent = false;
					n->idxname = $4;
					n->relation = $6;
					n->accessMethod = $7;
					n->indexParams = $9;
					n->options = $11;
					n->tableSpace = $12;
					n->whereClause = $13;
					$$ = (Node *)n;
				}
			| CREATE index_opt_unique INDEX CONCURRENTLY index_name
			ON qualified_name access_method_clause '(' index_params ')'
			opt_reloptions OptTableSpace where_clause
				{
					IndexStmt *n = makeNode(IndexStmt);
					n->unique = $2;
					n->concurrent = true;
					n->idxname = $5;
					n->relation = $7;
					n->accessMethod = $8;
					n->indexParams = $10;
					n->options = $12;
					n->tableSpace = $13;
					n->whereClause = $14;
					$$ = (Node *)n;
				}
		;

index_opt_unique:
			UNIQUE									{ $$ = TRUE; }
			| /*EMPTY*/								{ $$ = FALSE; }
		;

access_method_clause:
			USING access_method						{ $$ = $2; }
			| /*EMPTY*/								{ $$ = DEFAULT_INDEX_TYPE; }
		;

index_params:	index_elem							{ $$ = list_make1($1); }
			| index_params ',' index_elem			{ $$ = lappend($1, $3); }
		;

/*
 * Index attributes can be either simple column references, or arbitrary
 * expressions in parens.  For backwards-compatibility reasons, we allow
 * an expression that's just a function call to be written without parens.
 */
index_elem:	ColId opt_class opt_asc_desc opt_nulls_order
				{
					$$ = makeNode(IndexElem);
					$$->name = $1;
					$$->expr = NULL;
					$$->opclass = $2;
					$$->ordering = $3;
					$$->nulls_ordering = $4;
				}
			| func_expr opt_class opt_asc_desc opt_nulls_order
				{
					$$ = makeNode(IndexElem);
					$$->name = NULL;
					$$->expr = $1;
					$$->opclass = $2;
					$$->ordering = $3;
					$$->nulls_ordering = $4;
				}
			| '(' a_expr ')' opt_class opt_asc_desc opt_nulls_order
				{
					$$ = makeNode(IndexElem);
					$$->name = NULL;
					$$->expr = $2;
					$$->opclass = $4;
					$$->ordering = $5;
					$$->nulls_ordering = $6;
				}
		;

opt_class:	any_name								{ $$ = $1; }
			| USING any_name						{ $$ = $2; }
			| /*EMPTY*/								{ $$ = NIL; }
		;

opt_asc_desc: ASC							{ $$ = SORTBY_ASC; }
			| DESC							{ $$ = SORTBY_DESC; }
			| /*EMPTY*/						{ $$ = SORTBY_DEFAULT; }
		;

opt_nulls_order: NULLS_FIRST				{ $$ = SORTBY_NULLS_FIRST; }
			| NULLS_LAST					{ $$ = SORTBY_NULLS_LAST; }
			| /*EMPTY*/						{ $$ = SORTBY_NULLS_DEFAULT; }
		;


/*****************************************************************************
 *
 *		QUERY:
 *				create [or replace] function <fname>
 *						[(<type-1> { , <type-n>})]
 *						returns <type-r>
 *						as <filename or code in language as appropriate>
 *						language <lang> [with parameters]
 *
 *****************************************************************************/

CreateFunctionStmt:
			CREATE opt_or_replace FUNCTION func_name func_args_with_defaults
			RETURNS func_return createfunc_opt_list opt_definition
				{
					CreateFunctionStmt *n = makeNode(CreateFunctionStmt);
					n->replace = $2;
					n->funcname = $4;
					n->parameters = $5;
					n->returnType = $7;
					n->options = $8;
					n->withClause = $9;
					$$ = (Node *)n;
				}
			| CREATE opt_or_replace FUNCTION func_name func_args_with_defaults
			  RETURNS TABLE '(' table_func_column_list ')' createfunc_opt_list opt_definition
				{
					CreateFunctionStmt *n = makeNode(CreateFunctionStmt);
					n->replace = $2;
					n->funcname = $4;
					n->parameters = mergeTableFuncParameters($5, $9);
					n->returnType = TableFuncTypeName($9);
					n->returnType->location = @7;
					n->options = $11;
					n->withClause = $12;
					$$ = (Node *)n;
				}
			| CREATE opt_or_replace FUNCTION func_name func_args_with_defaults
			  createfunc_opt_list opt_definition
				{
					CreateFunctionStmt *n = makeNode(CreateFunctionStmt);
					n->replace = $2;
					n->funcname = $4;
					n->parameters = $5;
					n->returnType = NULL;
					n->options = $6;
					n->withClause = $7;
					$$ = (Node *)n;
				}
		;

opt_or_replace:
			OR REPLACE								{ $$ = TRUE; }
			| /*EMPTY*/								{ $$ = FALSE; }
		;

func_args:	'(' func_args_list ')'					{ $$ = $2; }
			| '(' ')'								{ $$ = NIL; }
		;

func_args_list:
			func_arg								{ $$ = list_make1($1); }
			| func_args_list ',' func_arg			{ $$ = lappend($1, $3); }
		;

/*
 * func_args_with_defaults is separate because we only want to accept
 * defaults in CREATE FUNCTION, not in ALTER etc.
 */
func_args_with_defaults:
		'(' func_args_with_defaults_list ')'		{ $$ = $2; }
		| '(' ')'									{ $$ = NIL; }
		;

func_args_with_defaults_list:
		func_arg_with_default						{ $$ = list_make1($1); }
		| func_args_with_defaults_list ',' func_arg_with_default
													{ $$ = lappend($1, $3); }
		;

/*
 * The style with arg_class first is SQL99 standard, but Oracle puts
 * param_name first; accept both since it's likely people will try both
 * anyway.  Don't bother trying to save productions by letting arg_class
 * have an empty alternative ... you'll get shift/reduce conflicts.
 *
 * We can catch over-specified arguments here if we want to,
 * but for now better to silently swallow typmod, etc.
 * - thomas 2000-03-22
 */
func_arg:
			arg_class param_name func_type
				{
					FunctionParameter *n = makeNode(FunctionParameter);
					n->name = $2;
					n->argType = $3;
					n->mode = $1;
					n->defexpr = NULL;
					$$ = n;
				}
			| param_name arg_class func_type
				{
					FunctionParameter *n = makeNode(FunctionParameter);
					n->name = $1;
					n->argType = $3;
					n->mode = $2;
					n->defexpr = NULL;
					$$ = n;
				}
			| param_name func_type
				{
					FunctionParameter *n = makeNode(FunctionParameter);
					n->name = $1;
					n->argType = $2;
					n->mode = FUNC_PARAM_IN;
					n->defexpr = NULL;
					$$ = n;
				}
			| arg_class func_type
				{
					FunctionParameter *n = makeNode(FunctionParameter);
					n->name = NULL;
					n->argType = $2;
					n->mode = $1;
					n->defexpr = NULL;
					$$ = n;
				}
			| func_type
				{
					FunctionParameter *n = makeNode(FunctionParameter);
					n->name = NULL;
					n->argType = $1;
					n->mode = FUNC_PARAM_IN;
					n->defexpr = NULL;
					$$ = n;
				}
		;

/* INOUT is SQL99 standard, IN OUT is for Oracle compatibility */
arg_class:	IN_P								{ $$ = FUNC_PARAM_IN; }
			| OUT_P								{ $$ = FUNC_PARAM_OUT; }
			| INOUT								{ $$ = FUNC_PARAM_INOUT; }
			| IN_P OUT_P						{ $$ = FUNC_PARAM_INOUT; }
			| VARIADIC							{ $$ = FUNC_PARAM_VARIADIC; }
		;

/*
 * Ideally param_name should be ColId, but that causes too many conflicts.
 */
param_name:	type_function_name
		;

func_return:
			func_type
				{
					/* We can catch over-specified results here if we want to,
					 * but for now better to silently swallow typmod, etc.
					 * - thomas 2000-03-22
					 */
					$$ = $1;
				}
		;

/*
 * We would like to make the %TYPE productions here be ColId attrs etc,
 * but that causes reduce/reduce conflicts.  type_function_name
 * is next best choice.
 */
func_type:	Typename								{ $$ = $1; }
			| type_function_name attrs '%' TYPE_P
				{
					$$ = makeTypeNameFromNameList(lcons(makeString($1), $2));
					$$->pct_type = true;
					$$->location = @1;
				}
			| SETOF type_function_name attrs '%' TYPE_P
				{
					$$ = makeTypeNameFromNameList(lcons(makeString($2), $3));
					$$->pct_type = true;
					$$->setof = TRUE;
					$$->location = @2;
				}
		;

func_arg_with_default:
		func_arg
			    {
				    $$ = $1;
			    }
		| func_arg DEFAULT a_expr
			    {
				    $$ = $1;
				    $$->defexpr = $3;
			    }
		| func_arg '=' a_expr
			    {
				    $$ = $1;
				    $$->defexpr = $3;
			    }
		;


createfunc_opt_list:
			/* Must be at least one to prevent conflict */
			createfunc_opt_item                     { $$ = list_make1($1); }
			| createfunc_opt_list createfunc_opt_item { $$ = lappend($1, $2); }
	;

/*
 * Options common to both CREATE FUNCTION and ALTER FUNCTION
 */
common_func_opt_item:
			CALLED ON NULL_P INPUT_P
				{
					$$ = makeDefElem("strict", (Node *)makeInteger(FALSE));
				}
			| RETURNS NULL_P ON NULL_P INPUT_P
				{
					$$ = makeDefElem("strict", (Node *)makeInteger(TRUE));
				}
			| STRICT_P
				{
					$$ = makeDefElem("strict", (Node *)makeInteger(TRUE));
				}
			| IMMUTABLE
				{
					$$ = makeDefElem("volatility", (Node *)makeString("immutable"));
				}
			| STABLE
				{
					$$ = makeDefElem("volatility", (Node *)makeString("stable"));
				}
			| VOLATILE
				{
					$$ = makeDefElem("volatility", (Node *)makeString("volatile"));
				}
			| EXTERNAL SECURITY DEFINER
				{
					$$ = makeDefElem("security", (Node *)makeInteger(TRUE));
				}
			| EXTERNAL SECURITY INVOKER
				{
					$$ = makeDefElem("security", (Node *)makeInteger(FALSE));
				}
			| SECURITY DEFINER
				{
					$$ = makeDefElem("security", (Node *)makeInteger(TRUE));
				}
			| SECURITY INVOKER
				{
					$$ = makeDefElem("security", (Node *)makeInteger(FALSE));
				}
			| COST NumericOnly
				{
					$$ = makeDefElem("cost", (Node *)$2);
				}
			| ROWS NumericOnly
				{
					$$ = makeDefElem("rows", (Node *)$2);
				}
			| SetResetClause
				{
					/* we abuse the normal content of a DefElem here */
					$$ = makeDefElem("set", (Node *)$1);
				}
			| SecurityItem
				{
					$$ = $1;
				}
		;

createfunc_opt_item:
			AS func_as
				{
					$$ = makeDefElem("as", (Node *)$2);
				}
			| LANGUAGE ColId_or_Sconst
				{
					$$ = makeDefElem("language", (Node *)makeString($2));
				}
			| WINDOW
				{
					$$ = makeDefElem("window", (Node *)makeInteger(TRUE));
				}
			| common_func_opt_item
				{
					$$ = $1;
				}
		;

func_as:	Sconst						{ $$ = list_make1(makeString($1)); }
			| Sconst ',' Sconst
				{
					$$ = list_make2(makeString($1), makeString($3));
				}
		;

opt_definition:
			WITH definition							{ $$ = $2; }
			| /*EMPTY*/								{ $$ = NIL; }
		;

table_func_column:	param_name func_type
				{
					FunctionParameter *n = makeNode(FunctionParameter);
					n->name = $1;
					n->argType = $2;
					n->mode = FUNC_PARAM_TABLE;
					n->defexpr = NULL;
					$$ = n;
				}
		;

table_func_column_list:
			table_func_column
				{
					$$ = list_make1($1);
				}
			| table_func_column_list ',' table_func_column
				{
					$$ = lappend($1, $3);
				}
		;

/*****************************************************************************
 * ALTER FUNCTION
 *
 * RENAME and OWNER subcommands are already provided by the generic
 * ALTER infrastructure, here we just specify alterations that can
 * only be applied to functions.
 *
 *****************************************************************************/
AlterFunctionStmt:
			ALTER FUNCTION function_with_argtypes alterfunc_opt_list opt_restrict
				{
					AlterFunctionStmt *n = makeNode(AlterFunctionStmt);
					n->func = $3;
					n->actions = $4;
					$$ = (Node *) n;
				}
		;

alterfunc_opt_list:
			/* At least one option must be specified */
			common_func_opt_item					{ $$ = list_make1($1); }
			| alterfunc_opt_list common_func_opt_item { $$ = lappend($1, $2); }
		;

/* Ignored, merely for SQL compliance */
opt_restrict:
			RESTRICT
			| /* EMPTY */
		;


/*****************************************************************************
 *
 *		QUERY:
 *
 *		DROP FUNCTION funcname (arg1, arg2, ...) [ RESTRICT | CASCADE ]
 *		DROP AGGREGATE aggname (arg1, ...) [ RESTRICT | CASCADE ]
 *		DROP OPERATOR opname (leftoperand_typ, rightoperand_typ) [ RESTRICT | CASCADE ]
 *
 *****************************************************************************/

RemoveFuncStmt:
			DROP FUNCTION func_name func_args opt_drop_behavior
				{
					RemoveFuncStmt *n = makeNode(RemoveFuncStmt);
					n->kind = OBJECT_FUNCTION;
					n->name = $3;
					n->args = extractArgTypes($4);
					n->behavior = $5;
					n->missing_ok = false;
					$$ = (Node *)n;
				}
			| DROP FUNCTION IF_P EXISTS func_name func_args opt_drop_behavior
				{
					RemoveFuncStmt *n = makeNode(RemoveFuncStmt);
					n->kind = OBJECT_FUNCTION;
					n->name = $5;
					n->args = extractArgTypes($6);
					n->behavior = $7;
					n->missing_ok = true;
					$$ = (Node *)n;
				}
		;

RemoveAggrStmt:
			DROP AGGREGATE func_name aggr_args opt_drop_behavior
				{
					RemoveFuncStmt *n = makeNode(RemoveFuncStmt);
					n->kind = OBJECT_AGGREGATE;
					n->name = $3;
					n->args = $4;
					n->behavior = $5;
					n->missing_ok = false;
					$$ = (Node *)n;
				}
			| DROP AGGREGATE IF_P EXISTS func_name aggr_args opt_drop_behavior
				{
					RemoveFuncStmt *n = makeNode(RemoveFuncStmt);
					n->kind = OBJECT_AGGREGATE;
					n->name = $5;
					n->args = $6;
					n->behavior = $7;
					n->missing_ok = true;
					$$ = (Node *)n;
				}
		;

RemoveOperStmt:
			DROP OPERATOR any_operator oper_argtypes opt_drop_behavior
				{
					RemoveFuncStmt *n = makeNode(RemoveFuncStmt);
					n->kind = OBJECT_OPERATOR;
					n->name = $3;
					n->args = $4;
					n->behavior = $5;
					n->missing_ok = false;
					$$ = (Node *)n;
				}
			| DROP OPERATOR IF_P EXISTS any_operator oper_argtypes opt_drop_behavior
				{
					RemoveFuncStmt *n = makeNode(RemoveFuncStmt);
					n->kind = OBJECT_OPERATOR;
					n->name = $5;
					n->args = $6;
					n->behavior = $7;
					n->missing_ok = true;
					$$ = (Node *)n;
				}
		;

oper_argtypes:
			'(' Typename ')'
				{
				   ereport(ERROR,
						   (errcode(ERRCODE_SYNTAX_ERROR),
							errmsg("missing argument"),
							errhint("Use NONE to denote the missing argument of a unary operator."),
							scanner_errposition(@3)));
				}
			| '(' Typename ',' Typename ')'
					{ $$ = list_make2($2, $4); }
			| '(' NONE ',' Typename ')'					/* left unary */
					{ $$ = list_make2(NULL, $4); }
			| '(' Typename ',' NONE ')'					/* right unary */
					{ $$ = list_make2($2, NULL); }
		;

any_operator:
			all_Op
					{ $$ = list_make1(makeString($1)); }
			| ColId '.' any_operator
					{ $$ = lcons(makeString($1), $3); }
		;


/*****************************************************************************
 *
 *		CREATE CAST / DROP CAST
 *
 *****************************************************************************/

CreateCastStmt: CREATE CAST '(' Typename AS Typename ')'
					WITH FUNCTION function_with_argtypes cast_context
				{
					CreateCastStmt *n = makeNode(CreateCastStmt);
					n->sourcetype = $4;
					n->targettype = $6;
					n->func = $10;
					n->context = (CoercionContext) $11;
					n->inout = false;
					$$ = (Node *)n;
				}
			| CREATE CAST '(' Typename AS Typename ')'
					WITHOUT FUNCTION cast_context
				{
					CreateCastStmt *n = makeNode(CreateCastStmt);
					n->sourcetype = $4;
					n->targettype = $6;
					n->func = NULL;
					n->context = (CoercionContext) $10;
					n->inout = false;
					$$ = (Node *)n;
				}
			| CREATE CAST '(' Typename AS Typename ')'
					WITH INOUT cast_context
				{
					CreateCastStmt *n = makeNode(CreateCastStmt);
					n->sourcetype = $4;
					n->targettype = $6;
					n->func = NULL;
					n->context = (CoercionContext) $10;
					n->inout = true;
					$$ = (Node *)n;
				}
		;

cast_context:  AS IMPLICIT_P					{ $$ = COERCION_IMPLICIT; }
		| AS ASSIGNMENT							{ $$ = COERCION_ASSIGNMENT; }
		| /*EMPTY*/								{ $$ = COERCION_EXPLICIT; }
		;


DropCastStmt: DROP CAST opt_if_exists '(' Typename AS Typename ')' opt_drop_behavior
				{
					DropCastStmt *n = makeNode(DropCastStmt);
					n->sourcetype = $5;
					n->targettype = $7;
					n->behavior = $9;
					n->missing_ok = $3;
					$$ = (Node *)n;
				}
		;

opt_if_exists: IF_P EXISTS						{ $$ = TRUE; }
		| /*EMPTY*/								{ $$ = FALSE; }
		;


/*****************************************************************************
 *
 *		QUERY:
 *
 *		REINDEX type <name> [FORCE]
 *
 * FORCE no longer does anything, but we accept it for backwards compatibility
 *****************************************************************************/

ReindexStmt:
			REINDEX reindex_type qualified_name opt_force
				{
					ReindexStmt *n = makeNode(ReindexStmt);
					n->kind = $2;
					n->relation = $3;
					n->name = NULL;
					$$ = (Node *)n;
				}
			| REINDEX SYSTEM_P name opt_force
				{
					ReindexStmt *n = makeNode(ReindexStmt);
					n->kind = OBJECT_DATABASE;
					n->name = $3;
					n->relation = NULL;
					n->do_system = true;
					n->do_user = false;
					$$ = (Node *)n;
				}
			| REINDEX DATABASE name opt_force
				{
					ReindexStmt *n = makeNode(ReindexStmt);
					n->kind = OBJECT_DATABASE;
					n->name = $3;
					n->relation = NULL;
					n->do_system = true;
					n->do_user = true;
					$$ = (Node *)n;
				}
		;

reindex_type:
			INDEX									{ $$ = OBJECT_INDEX; }
			| TABLE									{ $$ = OBJECT_TABLE; }
		;

opt_force:	FORCE									{  $$ = TRUE; }
			| /* EMPTY */							{  $$ = FALSE; }
		;


/*****************************************************************************
 *
 * ALTER THING name RENAME TO newname
 *
 *****************************************************************************/

RenameStmt: ALTER AGGREGATE func_name aggr_args RENAME TO name
				{
					RenameStmt *n = makeNode(RenameStmt);
					n->renameType = OBJECT_AGGREGATE;
					n->object = $3;
					n->objarg = $4;
					n->newname = $7;
					$$ = (Node *)n;
				}
			| ALTER CONVERSION_P any_name RENAME TO name
				{
					RenameStmt *n = makeNode(RenameStmt);
					n->renameType = OBJECT_CONVERSION;
					n->object = $3;
					n->newname = $6;
					$$ = (Node *)n;
				}
			| ALTER DATABASE database_name RENAME TO database_name
				{
					RenameStmt *n = makeNode(RenameStmt);
					n->renameType = OBJECT_DATABASE;
					n->subname = $3;
					n->newname = $6;
					$$ = (Node *)n;
				}
			| ALTER FUNCTION function_with_argtypes RENAME TO name
				{
					RenameStmt *n = makeNode(RenameStmt);
					n->renameType = OBJECT_FUNCTION;
					n->object = $3->funcname;
					n->objarg = $3->funcargs;
					n->newname = $6;
					$$ = (Node *)n;
				}
			| ALTER GROUP_P RoleId RENAME TO RoleId
				{
					RenameStmt *n = makeNode(RenameStmt);
					n->renameType = OBJECT_ROLE;
					n->subname = $3;
					n->newname = $6;
					$$ = (Node *)n;
				}
			| ALTER opt_procedural LANGUAGE name RENAME TO name
				{
					RenameStmt *n = makeNode(RenameStmt);
					n->renameType = OBJECT_LANGUAGE;
					n->subname = $4;
					n->newname = $7;
					$$ = (Node *)n;
				}
			| ALTER OPERATOR CLASS any_name USING access_method RENAME TO name
				{
					RenameStmt *n = makeNode(RenameStmt);
					n->renameType = OBJECT_OPCLASS;
					n->object = $4;
					n->subname = $6;
					n->newname = $9;
					$$ = (Node *)n;
				}
			| ALTER OPERATOR FAMILY any_name USING access_method RENAME TO name
				{
					RenameStmt *n = makeNode(RenameStmt);
					n->renameType = OBJECT_OPFAMILY;
					n->object = $4;
					n->subname = $6;
					n->newname = $9;
					$$ = (Node *)n;
				}
			| ALTER SCHEMA name RENAME TO name
				{
					RenameStmt *n = makeNode(RenameStmt);
					n->renameType = OBJECT_SCHEMA;
					n->subname = $3;
					n->newname = $6;
					$$ = (Node *)n;
				}
			| ALTER TABLE relation_expr RENAME TO name
				{
					RenameStmt *n = makeNode(RenameStmt);
					n->renameType = OBJECT_TABLE;
					n->relation = $3;
					n->subname = NULL;
					n->newname = $6;
					$$ = (Node *)n;
				}
			| ALTER SEQUENCE qualified_name RENAME TO name
				{
					RenameStmt *n = makeNode(RenameStmt);
					n->renameType = OBJECT_SEQUENCE;
					n->relation = $3;
					n->subname = NULL;
					n->newname = $6;
					$$ = (Node *)n;
				}
			| ALTER VIEW qualified_name RENAME TO name
				{
					RenameStmt *n = makeNode(RenameStmt);
					n->renameType = OBJECT_VIEW;
					n->relation = $3;
					n->subname = NULL;
					n->newname = $6;
					$$ = (Node *)n;
				}
			| ALTER INDEX qualified_name RENAME TO name
				{
					RenameStmt *n = makeNode(RenameStmt);
					n->renameType = OBJECT_INDEX;
					n->relation = $3;
					n->subname = NULL;
					n->newname = $6;
					$$ = (Node *)n;
				}
			| ALTER TABLE relation_expr RENAME opt_column name TO name
				{
					RenameStmt *n = makeNode(RenameStmt);
					n->renameType = OBJECT_COLUMN;
					n->relation = $3;
					n->subname = $6;
					n->newname = $8;
					$$ = (Node *)n;
				}
			| ALTER TRIGGER name ON qualified_name RENAME TO name
				{
					RenameStmt *n = makeNode(RenameStmt);
					n->renameType = OBJECT_TRIGGER;
					n->relation = $5;
					n->subname = $3;
					n->newname = $8;
					$$ = (Node *)n;
				}
			| ALTER ROLE RoleId RENAME TO RoleId
				{
					RenameStmt *n = makeNode(RenameStmt);
					n->renameType = OBJECT_ROLE;
					n->subname = $3;
					n->newname = $6;
					$$ = (Node *)n;
				}
			| ALTER USER RoleId RENAME TO RoleId
				{
					RenameStmt *n = makeNode(RenameStmt);
					n->renameType = OBJECT_ROLE;
					n->subname = $3;
					n->newname = $6;
					$$ = (Node *)n;
				}
			| ALTER TABLESPACE name RENAME TO name
				{
					RenameStmt *n = makeNode(RenameStmt);
					n->renameType = OBJECT_TABLESPACE;
					n->subname = $3;
					n->newname = $6;
					$$ = (Node *)n;
				}
			| ALTER TEXT_P SEARCH PARSER any_name RENAME TO name
				{
					RenameStmt *n = makeNode(RenameStmt);
					n->renameType = OBJECT_TSPARSER;
					n->object = $5;
					n->newname = $8;
					$$ = (Node *)n;
				}
			| ALTER TEXT_P SEARCH DICTIONARY any_name RENAME TO name
				{
					RenameStmt *n = makeNode(RenameStmt);
					n->renameType = OBJECT_TSDICTIONARY;
					n->object = $5;
					n->newname = $8;
					$$ = (Node *)n;
				}
			| ALTER TEXT_P SEARCH TEMPLATE any_name RENAME TO name
				{
					RenameStmt *n = makeNode(RenameStmt);
					n->renameType = OBJECT_TSTEMPLATE;
					n->object = $5;
					n->newname = $8;
					$$ = (Node *)n;
				}
			| ALTER TEXT_P SEARCH CONFIGURATION any_name RENAME TO name
				{
					RenameStmt *n = makeNode(RenameStmt);
					n->renameType = OBJECT_TSCONFIGURATION;
					n->object = $5;
					n->newname = $8;
					$$ = (Node *)n;
				}
			| ALTER TYPE_P any_name RENAME TO name
				{
					RenameStmt *n = makeNode(RenameStmt);
					n->renameType = OBJECT_TYPE;
					n->object = $3;
					n->newname = $6;
					$$ = (Node *)n;
				}
		;

opt_column: COLUMN									{ $$ = COLUMN; }
			| /*EMPTY*/								{ $$ = 0; }
		;

opt_set_data: SET DATA_P									{ $$ = 1; }
			| /*EMPTY*/								{ $$ = 0; }
		;

/*****************************************************************************
 *
 * ALTER THING name SET SCHEMA name
 *
 *****************************************************************************/

AlterObjectSchemaStmt:
			ALTER AGGREGATE func_name aggr_args SET SCHEMA name
				{
					AlterObjectSchemaStmt *n = makeNode(AlterObjectSchemaStmt);
					n->objectType = OBJECT_AGGREGATE;
					n->object = $3;
					n->objarg = $4;
					n->newschema = $7;
					$$ = (Node *)n;
				}
			| ALTER DOMAIN_P any_name SET SCHEMA name
				{
					AlterObjectSchemaStmt *n = makeNode(AlterObjectSchemaStmt);
					n->objectType = OBJECT_DOMAIN;
					n->object = $3;
					n->newschema = $6;
					$$ = (Node *)n;
				}
			| ALTER FUNCTION function_with_argtypes SET SCHEMA name
				{
					AlterObjectSchemaStmt *n = makeNode(AlterObjectSchemaStmt);
					n->objectType = OBJECT_FUNCTION;
					n->object = $3->funcname;
					n->objarg = $3->funcargs;
					n->newschema = $6;
					$$ = (Node *)n;
				}
			| ALTER TABLE relation_expr SET SCHEMA name
				{
					AlterObjectSchemaStmt *n = makeNode(AlterObjectSchemaStmt);
					n->objectType = OBJECT_TABLE;
					n->relation = $3;
					n->newschema = $6;
					$$ = (Node *)n;
				}
			| ALTER SEQUENCE qualified_name SET SCHEMA name
				{
					AlterObjectSchemaStmt *n = makeNode(AlterObjectSchemaStmt);
					n->objectType = OBJECT_SEQUENCE;
					n->relation = $3;
					n->newschema = $6;
					$$ = (Node *)n;
				}
			| ALTER VIEW qualified_name SET SCHEMA name
				{
					AlterObjectSchemaStmt *n = makeNode(AlterObjectSchemaStmt);
					n->objectType = OBJECT_VIEW;
					n->relation = $3;
					n->newschema = $6;
					$$ = (Node *)n;
				}
			| ALTER TYPE_P any_name SET SCHEMA name
				{
					AlterObjectSchemaStmt *n = makeNode(AlterObjectSchemaStmt);
					n->objectType = OBJECT_TYPE;
					n->object = $3;
					n->newschema = $6;
					$$ = (Node *)n;
				}
		;

/*****************************************************************************
 *
 * ALTER THING name OWNER TO newname
 *
 *****************************************************************************/

AlterOwnerStmt: ALTER AGGREGATE func_name aggr_args OWNER TO RoleId
				{
					AlterOwnerStmt *n = makeNode(AlterOwnerStmt);
					n->objectType = OBJECT_AGGREGATE;
					n->object = $3;
					n->objarg = $4;
					n->newowner = $7;
					$$ = (Node *)n;
				}
			| ALTER CONVERSION_P any_name OWNER TO RoleId
				{
					AlterOwnerStmt *n = makeNode(AlterOwnerStmt);
					n->objectType = OBJECT_CONVERSION;
					n->object = $3;
					n->newowner = $6;
					$$ = (Node *)n;
				}
			| ALTER DATABASE database_name OWNER TO RoleId
				{
					AlterOwnerStmt *n = makeNode(AlterOwnerStmt);
					n->objectType = OBJECT_DATABASE;
					n->object = list_make1(makeString($3));
					n->newowner = $6;
					$$ = (Node *)n;
				}
			| ALTER DOMAIN_P any_name OWNER TO RoleId
				{
					AlterOwnerStmt *n = makeNode(AlterOwnerStmt);
					n->objectType = OBJECT_DOMAIN;
					n->object = $3;
					n->newowner = $6;
					$$ = (Node *)n;
				}
			| ALTER FUNCTION function_with_argtypes OWNER TO RoleId
				{
					AlterOwnerStmt *n = makeNode(AlterOwnerStmt);
					n->objectType = OBJECT_FUNCTION;
					n->object = $3->funcname;
					n->objarg = $3->funcargs;
					n->newowner = $6;
					$$ = (Node *)n;
				}
			| ALTER opt_procedural LANGUAGE name OWNER TO RoleId
				{
					AlterOwnerStmt *n = makeNode(AlterOwnerStmt);
					n->objectType = OBJECT_LANGUAGE;
					n->object = list_make1(makeString($4));
					n->newowner = $7;
					$$ = (Node *)n;
				}
			| ALTER OPERATOR any_operator oper_argtypes OWNER TO RoleId
				{
					AlterOwnerStmt *n = makeNode(AlterOwnerStmt);
					n->objectType = OBJECT_OPERATOR;
					n->object = $3;
					n->objarg = $4;
					n->newowner = $7;
					$$ = (Node *)n;
				}
			| ALTER OPERATOR CLASS any_name USING access_method OWNER TO RoleId
				{
					AlterOwnerStmt *n = makeNode(AlterOwnerStmt);
					n->objectType = OBJECT_OPCLASS;
					n->object = $4;
					n->addname = $6;
					n->newowner = $9;
					$$ = (Node *)n;
				}
			| ALTER OPERATOR FAMILY any_name USING access_method OWNER TO RoleId
				{
					AlterOwnerStmt *n = makeNode(AlterOwnerStmt);
					n->objectType = OBJECT_OPFAMILY;
					n->object = $4;
					n->addname = $6;
					n->newowner = $9;
					$$ = (Node *)n;
				}
			| ALTER SCHEMA name OWNER TO RoleId
				{
					AlterOwnerStmt *n = makeNode(AlterOwnerStmt);
					n->objectType = OBJECT_SCHEMA;
					n->object = list_make1(makeString($3));
					n->newowner = $6;
					$$ = (Node *)n;
				}
			| ALTER TYPE_P any_name OWNER TO RoleId
				{
					AlterOwnerStmt *n = makeNode(AlterOwnerStmt);
					n->objectType = OBJECT_TYPE;
					n->object = $3;
					n->newowner = $6;
					$$ = (Node *)n;
				}
			| ALTER TABLESPACE name OWNER TO RoleId
				{
					AlterOwnerStmt *n = makeNode(AlterOwnerStmt);
					n->objectType = OBJECT_TABLESPACE;
					n->object = list_make1(makeString($3));
					n->newowner = $6;
					$$ = (Node *)n;
				}
			| ALTER TEXT_P SEARCH DICTIONARY any_name OWNER TO RoleId
				{
					AlterOwnerStmt *n = makeNode(AlterOwnerStmt);
					n->objectType = OBJECT_TSDICTIONARY;
					n->object = $5;
					n->newowner = $8;
					$$ = (Node *)n;
				}
			| ALTER TEXT_P SEARCH CONFIGURATION any_name OWNER TO RoleId
				{
					AlterOwnerStmt *n = makeNode(AlterOwnerStmt);
					n->objectType = OBJECT_TSCONFIGURATION;
					n->object = $5;
					n->newowner = $8;
					$$ = (Node *)n;
				}
			| ALTER FOREIGN DATA_P WRAPPER name OWNER TO RoleId
				{
					AlterOwnerStmt *n = makeNode(AlterOwnerStmt);
					n->objectType = OBJECT_FDW;
					n->object = list_make1(makeString($5));
					n->newowner = $8;
					$$ = (Node *)n;
				}
			| ALTER SERVER name OWNER TO RoleId
				{
					AlterOwnerStmt *n = makeNode(AlterOwnerStmt);
					n->objectType = OBJECT_FOREIGN_SERVER;
					n->object = list_make1(makeString($3));
					n->newowner = $6;
					$$ = (Node *)n;
				}
		;


/*****************************************************************************
 *
 *		QUERY:	Define Rewrite Rule
 *
 *****************************************************************************/

RuleStmt:	CREATE opt_or_replace RULE name AS
			{ QueryIsRule=TRUE; }
			ON event TO qualified_name where_clause
			DO opt_instead RuleActionList
				{
					RuleStmt *n = makeNode(RuleStmt);
					n->replace = $2;
					n->relation = $10;
					n->rulename = $4;
					n->whereClause = $11;
					n->event = $8;
					n->instead = $13;
					n->actions = $14;
					$$ = (Node *)n;
					QueryIsRule=FALSE;
				}
		;

RuleActionList:
			NOTHING									{ $$ = NIL; }
			| RuleActionStmt						{ $$ = list_make1($1); }
			| '(' RuleActionMulti ')'				{ $$ = $2; }
		;

/* the thrashing around here is to discard "empty" statements... */
RuleActionMulti:
			RuleActionMulti ';' RuleActionStmtOrEmpty
				{ if ($3 != NULL)
					$$ = lappend($1, $3);
				  else
					$$ = $1;
				}
			| RuleActionStmtOrEmpty
				{ if ($1 != NULL)
					$$ = list_make1($1);
				  else
					$$ = NIL;
				}
		;

RuleActionStmt:
			SelectStmt
			| InsertStmt
			| UpdateStmt
			| DeleteStmt
			| NotifyStmt
		;

RuleActionStmtOrEmpty:
			RuleActionStmt							{ $$ = $1; }
			|	/*EMPTY*/							{ $$ = NULL; }
		;

event:		SELECT									{ $$ = CMD_SELECT; }
			| UPDATE								{ $$ = CMD_UPDATE; }
			| DELETE_P								{ $$ = CMD_DELETE; }
			| INSERT								{ $$ = CMD_INSERT; }
		 ;

opt_instead:
			INSTEAD									{ $$ = TRUE; }
			| ALSO									{ $$ = FALSE; }
			| /*EMPTY*/								{ $$ = FALSE; }
		;


DropRuleStmt:
			DROP RULE name ON qualified_name opt_drop_behavior
				{
					DropPropertyStmt *n = makeNode(DropPropertyStmt);
					n->relation = $5;
					n->property = $3;
					n->behavior = $6;
					n->removeType = OBJECT_RULE;
					n->missing_ok = false;
					$$ = (Node *) n;
				}
			| DROP RULE IF_P EXISTS name ON qualified_name opt_drop_behavior
				{
					DropPropertyStmt *n = makeNode(DropPropertyStmt);
					n->relation = $7;
					n->property = $5;
					n->behavior = $8;
					n->removeType = OBJECT_RULE;
					n->missing_ok = true;
					$$ = (Node *) n;
				}
		;


/*****************************************************************************
 *
 *		QUERY:
 *				NOTIFY <identifier> can appear both in rule bodies and
 *				as a query-level command
 *
 *****************************************************************************/

NotifyStmt: NOTIFY ColId
				{
					NotifyStmt *n = makeNode(NotifyStmt);
					n->conditionname = $2;
					$$ = (Node *)n;
				}
		;

ListenStmt: LISTEN ColId
				{
					ListenStmt *n = makeNode(ListenStmt);
					n->conditionname = $2;
					$$ = (Node *)n;
				}
		;

UnlistenStmt:
			UNLISTEN ColId
				{
					UnlistenStmt *n = makeNode(UnlistenStmt);
					n->conditionname = $2;
					$$ = (Node *)n;
				}
			| UNLISTEN '*'
				{
					UnlistenStmt *n = makeNode(UnlistenStmt);
					n->conditionname = NULL;
					$$ = (Node *)n;
				}
		;


/*****************************************************************************
 *
 *		Transactions:
 *
 *		BEGIN / COMMIT / ROLLBACK
 *		(also older versions END / ABORT)
 *
 *****************************************************************************/

TransactionStmt:
			ABORT_P opt_transaction
				{
					TransactionStmt *n = makeNode(TransactionStmt);
					n->kind = TRANS_STMT_ROLLBACK;
					n->options = NIL;
					$$ = (Node *)n;
				}
			| BEGIN_P opt_transaction transaction_mode_list_or_empty
				{
					TransactionStmt *n = makeNode(TransactionStmt);
					n->kind = TRANS_STMT_BEGIN;
					n->options = $3;
					$$ = (Node *)n;
				}
			| START TRANSACTION transaction_mode_list_or_empty
				{
					TransactionStmt *n = makeNode(TransactionStmt);
					n->kind = TRANS_STMT_START;
					n->options = $3;
					$$ = (Node *)n;
				}
			| COMMIT opt_transaction
				{
					TransactionStmt *n = makeNode(TransactionStmt);
					n->kind = TRANS_STMT_COMMIT;
					n->options = NIL;
					$$ = (Node *)n;
				}
			| END_P opt_transaction
				{
					TransactionStmt *n = makeNode(TransactionStmt);
					n->kind = TRANS_STMT_COMMIT;
					n->options = NIL;
					$$ = (Node *)n;
				}
			| ROLLBACK opt_transaction
				{
					TransactionStmt *n = makeNode(TransactionStmt);
					n->kind = TRANS_STMT_ROLLBACK;
					n->options = NIL;
					$$ = (Node *)n;
				}
			| SAVEPOINT ColId
				{
					TransactionStmt *n = makeNode(TransactionStmt);
					n->kind = TRANS_STMT_SAVEPOINT;
					n->options = list_make1(makeDefElem("savepoint_name",
														(Node *)makeString($2)));
					$$ = (Node *)n;
				}
			| RELEASE SAVEPOINT ColId
				{
					TransactionStmt *n = makeNode(TransactionStmt);
					n->kind = TRANS_STMT_RELEASE;
					n->options = list_make1(makeDefElem("savepoint_name",
														(Node *)makeString($3)));
					$$ = (Node *)n;
				}
			| RELEASE ColId
				{
					TransactionStmt *n = makeNode(TransactionStmt);
					n->kind = TRANS_STMT_RELEASE;
					n->options = list_make1(makeDefElem("savepoint_name",
														(Node *)makeString($2)));
					$$ = (Node *)n;
				}
			| ROLLBACK opt_transaction TO SAVEPOINT ColId
				{
					TransactionStmt *n = makeNode(TransactionStmt);
					n->kind = TRANS_STMT_ROLLBACK_TO;
					n->options = list_make1(makeDefElem("savepoint_name",
														(Node *)makeString($5)));
					$$ = (Node *)n;
				}
			| ROLLBACK opt_transaction TO ColId
				{
					TransactionStmt *n = makeNode(TransactionStmt);
					n->kind = TRANS_STMT_ROLLBACK_TO;
					n->options = list_make1(makeDefElem("savepoint_name",
														(Node *)makeString($4)));
					$$ = (Node *)n;
				}
			| PREPARE TRANSACTION Sconst
				{
					TransactionStmt *n = makeNode(TransactionStmt);
					n->kind = TRANS_STMT_PREPARE;
					n->gid = $3;
					$$ = (Node *)n;
				}
			| COMMIT PREPARED Sconst
				{
					TransactionStmt *n = makeNode(TransactionStmt);
					n->kind = TRANS_STMT_COMMIT_PREPARED;
					n->gid = $3;
					$$ = (Node *)n;
				}
			| ROLLBACK PREPARED Sconst
				{
					TransactionStmt *n = makeNode(TransactionStmt);
					n->kind = TRANS_STMT_ROLLBACK_PREPARED;
					n->gid = $3;
					$$ = (Node *)n;
				}
		;

opt_transaction:	WORK							{}
			| TRANSACTION							{}
			| /*EMPTY*/								{}
		;

transaction_mode_item:
			ISOLATION LEVEL iso_level
					{ $$ = makeDefElem("transaction_isolation",
									   makeStringConst($3, @3)); }
			| READ ONLY
					{ $$ = makeDefElem("transaction_read_only",
									   makeIntConst(TRUE, @1)); }
			| READ WRITE
					{ $$ = makeDefElem("transaction_read_only",
									   makeIntConst(FALSE, @1)); }
		;

/* Syntax with commas is SQL-spec, without commas is Postgres historical */
transaction_mode_list:
			transaction_mode_item
					{ $$ = list_make1($1); }
			| transaction_mode_list ',' transaction_mode_item
					{ $$ = lappend($1, $3); }
			| transaction_mode_list transaction_mode_item
					{ $$ = lappend($1, $2); }
		;

transaction_mode_list_or_empty:
			transaction_mode_list
			| /* EMPTY */
					{ $$ = NIL; }
		;


/*****************************************************************************
 *
 *	QUERY:
 *		CREATE [ OR REPLACE ] [ TEMP ] VIEW <viewname> '('target-list ')'
 *			AS <query> [ WITH [ CASCADED | LOCAL ] CHECK OPTION ]
 *
 *****************************************************************************/

ViewStmt: CREATE OptTemp VIEW qualified_name opt_column_list
				AS SelectStmt opt_check_option
				{
					ViewStmt *n = makeNode(ViewStmt);
					n->view = $4;
					n->view->istemp = $2;
					n->aliases = $5;
					n->query = $7;
					n->replace = false;
					$$ = (Node *) n;
				}
		| CREATE OR REPLACE OptTemp VIEW qualified_name opt_column_list
				AS SelectStmt opt_check_option
				{
					ViewStmt *n = makeNode(ViewStmt);
					n->view = $6;
					n->view->istemp = $4;
					n->aliases = $7;
					n->query = $9;
					n->replace = true;
					$$ = (Node *) n;
				}
		;

opt_check_option:
		WITH CHECK OPTION
				{
					ereport(ERROR,
							(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
							 errmsg("WITH CHECK OPTION is not implemented")));
				}
		| WITH CASCADED CHECK OPTION
				{
					ereport(ERROR,
							(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
							 errmsg("WITH CHECK OPTION is not implemented")));
				}
		| WITH LOCAL CHECK OPTION
				{
					ereport(ERROR,
							(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
							 errmsg("WITH CHECK OPTION is not implemented")));
				}
		| /* EMPTY */							{ $$ = NIL; }
		;

/*****************************************************************************
 *
 *		QUERY:
 *				LOAD "filename"
 *
 *****************************************************************************/

LoadStmt:	LOAD file_name
				{
					LoadStmt *n = makeNode(LoadStmt);
					n->filename = $2;
					$$ = (Node *)n;
				}
		;


/*****************************************************************************
 *
 *		CREATE DATABASE
 *
 *****************************************************************************/

CreatedbStmt:
			CREATE DATABASE database_name opt_with createdb_opt_list
				{
					CreatedbStmt *n = makeNode(CreatedbStmt);
					n->dbname = $3;
					n->options = $5;
					$$ = (Node *)n;
				}
		;

createdb_opt_list:
			createdb_opt_list createdb_opt_item		{ $$ = lappend($1, $2); }
			| /* EMPTY */							{ $$ = NIL; }
		;

createdb_opt_item:
			TABLESPACE opt_equal name
				{
					$$ = makeDefElem("tablespace", (Node *)makeString($3));
				}
			| TABLESPACE opt_equal DEFAULT
				{
					$$ = makeDefElem("tablespace", NULL);
				}
			| LOCATION opt_equal Sconst
				{
					$$ = makeDefElem("location", (Node *)makeString($3));
				}
			| LOCATION opt_equal DEFAULT
				{
					$$ = makeDefElem("location", NULL);
				}
			| TEMPLATE opt_equal name
				{
					$$ = makeDefElem("template", (Node *)makeString($3));
				}
			| TEMPLATE opt_equal DEFAULT
				{
					$$ = makeDefElem("template", NULL);
				}
			| ENCODING opt_equal Sconst
				{
					$$ = makeDefElem("encoding", (Node *)makeString($3));
				}
			| ENCODING opt_equal Iconst
				{
					$$ = makeDefElem("encoding", (Node *)makeInteger($3));
				}
			| ENCODING opt_equal DEFAULT
				{
					$$ = makeDefElem("encoding", NULL);
				}
			| COLLATE opt_equal Sconst
				{
					$$ = makeDefElem("collate", (Node *)makeString($3));
				}
			| COLLATE opt_equal DEFAULT
				{
					$$ = makeDefElem("collate", NULL);
				}
			| CTYPE opt_equal Sconst
				{
					$$ = makeDefElem("ctype", (Node *)makeString($3));
				}
			| CTYPE opt_equal DEFAULT
				{
					$$ = makeDefElem("ctype", NULL);
				}
			| CONNECTION LIMIT opt_equal SignedIconst
				{
					$$ = makeDefElem("connectionlimit", (Node *)makeInteger($4));
				}
			| OWNER opt_equal name
				{
					$$ = makeDefElem("owner", (Node *)makeString($3));
				}
			| OWNER opt_equal DEFAULT
				{
					$$ = makeDefElem("owner", NULL);
				}
			| SecurityItem
				{
					$$ = $1;
				}
		;

/*
 *	Though the equals sign doesn't match other WITH options, pg_dump uses
 *	equals for backward compatibility, and it doesn't seem worth removing it.
 */
opt_equal:	'='										{}
			| /*EMPTY*/								{}
		;


/*****************************************************************************
 *
 *		ALTER DATABASE
 *
 *****************************************************************************/

AlterDatabaseStmt:
			ALTER DATABASE database_name opt_with alterdb_opt_list
				 {
					AlterDatabaseStmt *n = makeNode(AlterDatabaseStmt);
					n->dbname = $3;
					n->options = $5;
					$$ = (Node *)n;
				 }
			| ALTER DATABASE database_name SET TABLESPACE name
				 {
					AlterDatabaseStmt *n = makeNode(AlterDatabaseStmt);
					n->dbname = $3;
					n->options = list_make1(makeDefElem("tablespace",
													(Node *)makeString($6)));
					$$ = (Node *)n;
				 }
		;

AlterDatabaseSetStmt:
			ALTER DATABASE database_name SetResetClause
				{
					AlterDatabaseSetStmt *n = makeNode(AlterDatabaseSetStmt);
					n->dbname = $3;
					n->setstmt = $4;
					$$ = (Node *)n;
				}
		;


alterdb_opt_list:
			alterdb_opt_list alterdb_opt_item		{ $$ = lappend($1, $2); }
			| /* EMPTY */							{ $$ = NIL; }
		;

alterdb_opt_item:
			CONNECTION LIMIT opt_equal SignedIconst
				{
					$$ = makeDefElem("connectionlimit", (Node *)makeInteger($4));
				}
			| SecurityItem
				{
					$$ = $1;
				}
		;


/*****************************************************************************
 *
 *		DROP DATABASE [ IF EXISTS ]
 *
 * This is implicitly CASCADE, no need for drop behavior
 *****************************************************************************/

DropdbStmt: DROP DATABASE database_name
				{
					DropdbStmt *n = makeNode(DropdbStmt);
					n->dbname = $3;
					n->missing_ok = FALSE;
					$$ = (Node *)n;
				}
			| DROP DATABASE IF_P EXISTS database_name
				{
					DropdbStmt *n = makeNode(DropdbStmt);
					n->dbname = $5;
					n->missing_ok = TRUE;
					$$ = (Node *)n;
				}
		;


/*****************************************************************************
 *
 * Manipulate a domain
 *
 *****************************************************************************/

CreateDomainStmt:
			CREATE DOMAIN_P any_name opt_as Typename ColQualList
				{
					CreateDomainStmt *n = makeNode(CreateDomainStmt);
					n->domainname = $3;
					n->typename = $5;
					n->constraints = $6;
					$$ = (Node *)n;
				}
		;

AlterDomainStmt:
			/* ALTER DOMAIN <domain> {SET DEFAULT <expr>|DROP DEFAULT} */
			ALTER DOMAIN_P any_name alter_column_default
				{
					AlterDomainStmt *n = makeNode(AlterDomainStmt);
					n->subtype = 'T';
					n->typename = $3;
					n->def = $4;
					$$ = (Node *)n;
				}
			/* ALTER DOMAIN <domain> DROP NOT NULL */
			| ALTER DOMAIN_P any_name DROP NOT NULL_P
				{
					AlterDomainStmt *n = makeNode(AlterDomainStmt);
					n->subtype = 'N';
					n->typename = $3;
					$$ = (Node *)n;
				}
			/* ALTER DOMAIN <domain> SET NOT NULL */
			| ALTER DOMAIN_P any_name SET NOT NULL_P
				{
					AlterDomainStmt *n = makeNode(AlterDomainStmt);
					n->subtype = 'O';
					n->typename = $3;
					$$ = (Node *)n;
				}
			/* ALTER DOMAIN <domain> ADD CONSTRAINT ... */
			| ALTER DOMAIN_P any_name ADD_P TableConstraint
				{
					AlterDomainStmt *n = makeNode(AlterDomainStmt);
					n->subtype = 'C';
					n->typename = $3;
					n->def = $5;
					$$ = (Node *)n;
				}
			/* ALTER DOMAIN <domain> DROP CONSTRAINT <name> [RESTRICT|CASCADE] */
			| ALTER DOMAIN_P any_name DROP CONSTRAINT name opt_drop_behavior
				{
					AlterDomainStmt *n = makeNode(AlterDomainStmt);
					n->subtype = 'X';
					n->typename = $3;
					n->name = $6;
					n->behavior = $7;
					$$ = (Node *)n;
				}
			;

opt_as:		AS										{}
			| /* EMPTY */							{}
		;


/*****************************************************************************
 *
 * Manipulate a text search dictionary or configuration
 *
 *****************************************************************************/

AlterTSDictionaryStmt:
			ALTER TEXT_P SEARCH DICTIONARY any_name definition
				{
					AlterTSDictionaryStmt *n = makeNode(AlterTSDictionaryStmt);
					n->dictname = $5;
					n->options = $6;
					$$ = (Node *)n;
				}
		;

AlterTSConfigurationStmt:
			ALTER TEXT_P SEARCH CONFIGURATION any_name ADD_P MAPPING FOR name_list WITH any_name_list
				{
					AlterTSConfigurationStmt *n = makeNode(AlterTSConfigurationStmt);
					n->cfgname = $5;
					n->tokentype = $9;
					n->dicts = $11;
					n->override = false;
					n->replace = false;
					$$ = (Node*)n;
				}
			| ALTER TEXT_P SEARCH CONFIGURATION any_name ALTER MAPPING FOR name_list WITH any_name_list
				{
					AlterTSConfigurationStmt *n = makeNode(AlterTSConfigurationStmt);
					n->cfgname = $5;
					n->tokentype = $9;
					n->dicts = $11;
					n->override = true;
					n->replace = false;
					$$ = (Node*)n;
				}
			| ALTER TEXT_P SEARCH CONFIGURATION any_name ALTER MAPPING REPLACE any_name WITH any_name
				{
					AlterTSConfigurationStmt *n = makeNode(AlterTSConfigurationStmt);
					n->cfgname = $5;
					n->tokentype = NIL;
					n->dicts = list_make2($9,$11);
					n->override = false;
					n->replace = true;
					$$ = (Node*)n;
				}
			| ALTER TEXT_P SEARCH CONFIGURATION any_name ALTER MAPPING FOR name_list REPLACE any_name WITH any_name
				{
					AlterTSConfigurationStmt *n = makeNode(AlterTSConfigurationStmt);
					n->cfgname = $5;
					n->tokentype = $9;
					n->dicts = list_make2($11,$13);
					n->override = false;
					n->replace = true;
					$$ = (Node*)n;
				}
			| ALTER TEXT_P SEARCH CONFIGURATION any_name DROP MAPPING FOR name_list
				{
					AlterTSConfigurationStmt *n = makeNode(AlterTSConfigurationStmt);
					n->cfgname = $5;
					n->tokentype = $9;
					n->missing_ok = false;
					$$ = (Node*)n;
				}
			| ALTER TEXT_P SEARCH CONFIGURATION any_name DROP MAPPING IF_P EXISTS FOR name_list
				{
					AlterTSConfigurationStmt *n = makeNode(AlterTSConfigurationStmt);
					n->cfgname = $5;
					n->tokentype = $11;
					n->missing_ok = true;
					$$ = (Node*)n;
				}
		;


/*****************************************************************************
 *
 * Manipulate a conversion
 *
 *		CREATE [DEFAULT] CONVERSION <conversion_name>
 *		FOR <encoding_name> TO <encoding_name> FROM <func_name>
 *
 *****************************************************************************/

CreateConversionStmt:
			CREATE opt_default CONVERSION_P any_name FOR Sconst
			TO Sconst FROM any_name
			{
			  CreateConversionStmt *n = makeNode(CreateConversionStmt);
			  n->conversion_name = $4;
			  n->for_encoding_name = $6;
			  n->to_encoding_name = $8;
			  n->func_name = $10;
			  n->def = $2;
			  $$ = (Node *)n;
			}
		;

/*****************************************************************************
 *
 *		QUERY:
 *				CLUSTER [VERBOSE] <qualified_name> [ USING <index_name> ]
 *				CLUSTER [VERBOSE]
 *				CLUSTER [VERBOSE] <index_name> ON <qualified_name> (for pre-8.3)
 *
 *****************************************************************************/

ClusterStmt:
			CLUSTER opt_verbose qualified_name cluster_index_specification
				{
			       ClusterStmt *n = makeNode(ClusterStmt);
				   n->relation = $3;
				   n->indexname = $4;
				   n->verbose = $2;
				   $$ = (Node*)n;
				}
			| CLUSTER opt_verbose
			    {
				   ClusterStmt *n = makeNode(ClusterStmt);
				   n->relation = NULL;
				   n->indexname = NULL;
				   n->verbose = $2;
				   $$ = (Node*)n;
				}
			/* kept for pre-8.3 compatibility */
			| CLUSTER opt_verbose index_name ON qualified_name
				{
				   ClusterStmt *n = makeNode(ClusterStmt);
				   n->relation = $5;
				   n->indexname = $3;
				   n->verbose = $2;
				   $$ = (Node*)n;
				}
		;

cluster_index_specification:
			USING index_name		{ $$ = $2; }
			| /*EMPTY*/				{ $$ = NULL; }
		;


/*****************************************************************************
 *
 *		QUERY:
 *				VACUUM
 *				ANALYZE
 *
 *****************************************************************************/

VacuumStmt: VACUUM opt_full opt_freeze opt_verbose
				{
					VacuumStmt *n = makeNode(VacuumStmt);
					n->vacuum = true;
					n->analyze = false;
					n->full = $2;
					n->freeze_min_age = $3 ? 0 : -1;
					n->freeze_table_age = $3 ? 0 : -1;
					n->verbose = $4;
					n->relation = NULL;
					n->va_cols = NIL;
					$$ = (Node *)n;
				}
			| VACUUM opt_full opt_freeze opt_verbose qualified_name
				{
					VacuumStmt *n = makeNode(VacuumStmt);
					n->vacuum = true;
					n->analyze = false;
					n->full = $2;
					n->freeze_min_age = $3 ? 0 : -1;
					n->freeze_table_age = $3 ? 0 : -1;
					n->verbose = $4;
					n->relation = $5;
					n->va_cols = NIL;
					$$ = (Node *)n;
				}
			| VACUUM opt_full opt_freeze opt_verbose AnalyzeStmt
				{
					VacuumStmt *n = (VacuumStmt *) $5;
					n->vacuum = true;
					n->full = $2;
					n->freeze_min_age = $3 ? 0 : -1;
					n->freeze_table_age = $3 ? 0 : -1;
					n->verbose |= $4;
					$$ = (Node *)n;
				}
		;

AnalyzeStmt:
			analyze_keyword opt_verbose
				{
					VacuumStmt *n = makeNode(VacuumStmt);
					n->vacuum = false;
					n->analyze = true;
					n->full = false;
					n->freeze_min_age = -1;
					n->freeze_table_age = -1;
					n->verbose = $2;
					n->relation = NULL;
					n->va_cols = NIL;
					$$ = (Node *)n;
				}
			| analyze_keyword opt_verbose qualified_name opt_name_list
				{
					VacuumStmt *n = makeNode(VacuumStmt);
					n->vacuum = false;
					n->analyze = true;
					n->full = false;
					n->freeze_min_age = -1;
					n->freeze_table_age = -1;
					n->verbose = $2;
					n->relation = $3;
					n->va_cols = $4;
					$$ = (Node *)n;
				}
		;

analyze_keyword:
			ANALYZE									{}
			| ANALYSE /* British */					{}
		;

opt_verbose:
			VERBOSE									{ $$ = TRUE; }
			| /*EMPTY*/								{ $$ = FALSE; }
		;

opt_full:	FULL									{ $$ = TRUE; }
			| /*EMPTY*/								{ $$ = FALSE; }
		;

opt_freeze: FREEZE									{ $$ = TRUE; }
			| /*EMPTY*/								{ $$ = FALSE; }
		;

opt_name_list:
			'(' name_list ')'						{ $$ = $2; }
			| /*EMPTY*/								{ $$ = NIL; }
		;


/*****************************************************************************
 *
 *		QUERY:
 *				EXPLAIN [ANALYZE] [VERBOSE] query
 *
 *****************************************************************************/

ExplainStmt: EXPLAIN opt_analyze opt_verbose ExplainableStmt
				{
					ExplainStmt *n = makeNode(ExplainStmt);
					n->analyze = $2;
					n->verbose = $3;
					n->query = $4;
					$$ = (Node *)n;
				}
		;

ExplainableStmt:
			SelectStmt
			| InsertStmt
			| UpdateStmt
			| DeleteStmt
			| DeclareCursorStmt
			| CreateAsStmt
			| ExecuteStmt					/* by default all are $$=$1 */
		;

opt_analyze:
			analyze_keyword			{ $$ = TRUE; }
			| /* EMPTY */			{ $$ = FALSE; }
		;

/*****************************************************************************
 *
 *		QUERY:
 *				PREPARE <plan_name> [(args, ...)] AS <query>
 *
 *****************************************************************************/

PrepareStmt: PREPARE name prep_type_clause AS PreparableStmt
				{
					PrepareStmt *n = makeNode(PrepareStmt);
					n->name = $2;
					n->argtypes = $3;
					n->query = $5;
					$$ = (Node *) n;
				}
		;

prep_type_clause: '(' type_list ')'			{ $$ = $2; }
				| /* EMPTY */				{ $$ = NIL; }
		;

PreparableStmt:
			SelectStmt
			| InsertStmt
			| UpdateStmt
			| DeleteStmt					/* by default all are $$=$1 */
		;

/*****************************************************************************
 *
 * EXECUTE <plan_name> [(params, ...)]
 * CREATE TABLE <name> AS EXECUTE <plan_name> [(params, ...)]
 *
 *****************************************************************************/

ExecuteStmt: EXECUTE name execute_param_clause
				{
					ExecuteStmt *n = makeNode(ExecuteStmt);
					n->name = $2;
					n->params = $3;
					n->into = NULL;
					$$ = (Node *) n;
				}
			| CREATE OptTemp TABLE create_as_target AS
				EXECUTE name execute_param_clause
				{
					ExecuteStmt *n = makeNode(ExecuteStmt);
					n->name = $7;
					n->params = $8;
					$4->rel->istemp = $2;
					n->into = $4;
					if ($4->colNames)
						ereport(ERROR,
								(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
								 errmsg("column name list not allowed in CREATE TABLE / AS EXECUTE")));
					/* ... because it's not implemented, but it could be */
					$$ = (Node *) n;
				}
		;

execute_param_clause: '(' expr_list ')'				{ $$ = $2; }
					| /* EMPTY */					{ $$ = NIL; }
					;

/*****************************************************************************
 *
 *		QUERY:
 *				DEALLOCATE [PREPARE] <plan_name>
 *
 *****************************************************************************/

DeallocateStmt: DEALLOCATE name
					{
						DeallocateStmt *n = makeNode(DeallocateStmt);
						n->name = $2;
						$$ = (Node *) n;
					}
				| DEALLOCATE PREPARE name
					{
						DeallocateStmt *n = makeNode(DeallocateStmt);
						n->name = $3;
						$$ = (Node *) n;
					}
				| DEALLOCATE ALL
					{
						DeallocateStmt *n = makeNode(DeallocateStmt);
						n->name = NULL;
						$$ = (Node *) n;
					}
				| DEALLOCATE PREPARE ALL
					{
						DeallocateStmt *n = makeNode(DeallocateStmt);
						n->name = NULL;
						$$ = (Node *) n;
					}
		;

/*****************************************************************************
 *
 *		QUERY:
 *				INSERT STATEMENTS
 *
 *****************************************************************************/

InsertStmt:
			INSERT INTO qualified_name insert_rest returning_clause
				{
					$4->relation = $3;
					$4->returningList = $5;
					$$ = (Node *) $4;
				}
		;

insert_rest:
			SelectStmt
				{
					$$ = makeNode(InsertStmt);
					$$->cols = NIL;
					$$->selectStmt = $1;
				}
			| '(' insert_column_list ')' SelectStmt
				{
					$$ = makeNode(InsertStmt);
					$$->cols = $2;
					$$->selectStmt = $4;
				}
			| DEFAULT VALUES
				{
					$$ = makeNode(InsertStmt);
					$$->cols = NIL;
					$$->selectStmt = NULL;
				}
		;

insert_column_list:
			insert_column_item
					{ $$ = list_make1($1); }
			| insert_column_list ',' insert_column_item
					{ $$ = lappend($1, $3); }
		;

insert_column_item:
			ColId opt_indirection
				{
					$$ = makeNode(ResTarget);
					$$->name = $1;
					$$->indirection = check_indirection($2);
					$$->val = NULL;
					$$->location = @1;
				}
		;

returning_clause:
			RETURNING target_list		{ $$ = $2; }
			| /* EMPTY */				{ $$ = NIL; }
		;


/*****************************************************************************
 *
 *		QUERY:
 *				DELETE STATEMENTS
 *
 *****************************************************************************/

DeleteStmt: DELETE_P FROM relation_expr_opt_alias
			using_clause where_or_current_clause returning_clause
				{
					DeleteStmt *n = makeNode(DeleteStmt);
					n->relation = $3;
					n->usingClause = $4;
					n->whereClause = $5;
					n->returningList = $6;
					$$ = (Node *)n;
				}
		;

using_clause:
	    		USING from_list						{ $$ = $2; }
			| /*EMPTY*/								{ $$ = NIL; }
		;


/*****************************************************************************
 *
 *		QUERY:
 *				LOCK TABLE
 *
 *****************************************************************************/

LockStmt:	LOCK_P opt_table relation_expr_list opt_lock opt_nowait
				{
					LockStmt *n = makeNode(LockStmt);

					n->relations = $3;
					n->mode = $4;
					n->nowait = $5;
					$$ = (Node *)n;
				}
		;

opt_lock:	IN_P lock_type MODE 			{ $$ = $2; }
			| /*EMPTY*/						{ $$ = AccessExclusiveLock; }
		;

lock_type:	ACCESS SHARE					{ $$ = AccessShareLock; }
			| ROW SHARE						{ $$ = RowShareLock; }
			| ROW EXCLUSIVE					{ $$ = RowExclusiveLock; }
			| SHARE UPDATE EXCLUSIVE		{ $$ = ShareUpdateExclusiveLock; }
			| SHARE							{ $$ = ShareLock; }
			| SHARE ROW EXCLUSIVE			{ $$ = ShareRowExclusiveLock; }
			| EXCLUSIVE						{ $$ = ExclusiveLock; }
			| ACCESS EXCLUSIVE				{ $$ = AccessExclusiveLock; }
		;

opt_nowait:	NOWAIT							{ $$ = TRUE; }
			| /*EMPTY*/						{ $$ = FALSE; }
		;


/*****************************************************************************
 *
 *		QUERY:
 *				UpdateStmt (UPDATE)
 *
 *****************************************************************************/

UpdateStmt: UPDATE relation_expr_opt_alias
			SET set_clause_list
			from_clause
			where_or_current_clause
			returning_clause
				{
					UpdateStmt *n = makeNode(UpdateStmt);
					n->relation = $2;
					n->targetList = $4;
					n->fromClause = $5;
					n->whereClause = $6;
					n->returningList = $7;
					$$ = (Node *)n;
				}
		;

set_clause_list:
			set_clause							{ $$ = $1; }
			| set_clause_list ',' set_clause	{ $$ = list_concat($1,$3); }
		;

set_clause:
			single_set_clause						{ $$ = list_make1($1); }
			| multiple_set_clause					{ $$ = $1; }
		;

single_set_clause:
			set_target '=' ctext_expr
				{
					$$ = $1;
					$$->val = (Node *) $3;
				}
		;

multiple_set_clause:
			'(' set_target_list ')' '=' ctext_row
				{
					ListCell *col_cell;
					ListCell *val_cell;

					/*
					 * Break the ctext_row apart, merge individual expressions
					 * into the destination ResTargets.  XXX this approach
					 * cannot work for general row expressions as sources.
					 */
					if (list_length($2) != list_length($5))
						ereport(ERROR,
								(errcode(ERRCODE_SYNTAX_ERROR),
								 errmsg("number of columns does not match number of values"),
								 scanner_errposition(@1)));
					forboth(col_cell, $2, val_cell, $5)
					{
						ResTarget *res_col = (ResTarget *) lfirst(col_cell);
						Node *res_val = (Node *) lfirst(val_cell);

						res_col->val = res_val;
					}

					$$ = $2;
				}
		;

set_target:
			ColId opt_indirection
				{
					$$ = makeNode(ResTarget);
					$$->name = $1;
					$$->indirection = check_indirection($2);
					$$->val = NULL;	/* upper production sets this */
					$$->location = @1;
				}
		;

set_target_list:
			set_target								{ $$ = list_make1($1); }
			| set_target_list ',' set_target		{ $$ = lappend($1,$3); }
		;


/*****************************************************************************
 *
 *		QUERY:
 *				CURSOR STATEMENTS
 *
 *****************************************************************************/
DeclareCursorStmt: DECLARE name cursor_options CURSOR opt_hold FOR SelectStmt
				{
					DeclareCursorStmt *n = makeNode(DeclareCursorStmt);
					n->portalname = $2;
					/* currently we always set FAST_PLAN option */
					n->options = $3 | $5 | CURSOR_OPT_FAST_PLAN;
					n->query = $7;
					$$ = (Node *)n;
				}
		;

cursor_options: /*EMPTY*/					{ $$ = 0; }
			| cursor_options NO SCROLL		{ $$ = $1 | CURSOR_OPT_NO_SCROLL; }
			| cursor_options SCROLL			{ $$ = $1 | CURSOR_OPT_SCROLL; }
			| cursor_options BINARY			{ $$ = $1 | CURSOR_OPT_BINARY; }
			| cursor_options INSENSITIVE	{ $$ = $1 | CURSOR_OPT_INSENSITIVE; }
		;

opt_hold: /* EMPTY */						{ $$ = 0; }
			| WITH HOLD						{ $$ = CURSOR_OPT_HOLD; }
			| WITHOUT HOLD					{ $$ = 0; }
		;

/*****************************************************************************
 *
 *		QUERY:
 *				SELECT STATEMENTS
 *
 *****************************************************************************/

/* A complete SELECT statement looks like this.
 *
 * The rule returns either a single SelectStmt node or a tree of them,
 * representing a set-operation tree.
 *
 * There is an ambiguity when a sub-SELECT is within an a_expr and there
 * are excess parentheses: do the parentheses belong to the sub-SELECT or
 * to the surrounding a_expr?  We don't really care, but yacc wants to know.
 * To resolve the ambiguity, we are careful to define the grammar so that
 * the decision is staved off as long as possible: as long as we can keep
 * absorbing parentheses into the sub-SELECT, we will do so, and only when
 * it's no longer possible to do that will we decide that parens belong to
 * the expression.	For example, in "SELECT (((SELECT 2)) + 3)" the extra
 * parentheses are treated as part of the sub-select.  The necessity of doing
 * it that way is shown by "SELECT (((SELECT 2)) UNION SELECT 2)".	Had we
 * parsed "((SELECT 2))" as an a_expr, it'd be too late to go back to the
 * SELECT viewpoint when we see the UNION.
 *
 * This approach is implemented by defining a nonterminal select_with_parens,
 * which represents a SELECT with at least one outer layer of parentheses,
 * and being careful to use select_with_parens, never '(' SelectStmt ')',
 * in the expression grammar.  We will then have shift-reduce conflicts
 * which we can resolve in favor of always treating '(' <select> ')' as
 * a select_with_parens.  To resolve the conflicts, the productions that
 * conflict with the select_with_parens productions are manually given
 * precedences lower than the precedence of ')', thereby ensuring that we
 * shift ')' (and then reduce to select_with_parens) rather than trying to
 * reduce the inner <select> nonterminal to something else.  We use UMINUS
 * precedence for this, which is a fairly arbitrary choice.
 *
 * To be able to define select_with_parens itself without ambiguity, we need
 * a nonterminal select_no_parens that represents a SELECT structure with no
 * outermost parentheses.  This is a little bit tedious, but it works.
 *
 * In non-expression contexts, we use SelectStmt which can represent a SELECT
 * with or without outer parentheses.
 */

SelectStmt: select_no_parens			%prec UMINUS
			| select_with_parens		%prec UMINUS
		;

select_with_parens:
			'(' select_no_parens ')'				{ $$ = $2; }
			| '(' select_with_parens ')'			{ $$ = $2; }
		;

/*
 * This rule parses the equivalent of the standard's <query expression>.
 * The duplicative productions are annoying, but hard to get rid of without
 * creating shift/reduce conflicts.
 *
 *	FOR UPDATE/SHARE may be before or after LIMIT/OFFSET.
 *	In <=7.2.X, LIMIT/OFFSET had to be after FOR UPDATE
 *	We now support both orderings, but prefer LIMIT/OFFSET before FOR UPDATE/SHARE
 *	2002-08-28 bjm
 */
select_no_parens:
			simple_select						{ $$ = $1; }
			| select_clause sort_clause
				{
					insertSelectOptions((SelectStmt *) $1, $2, NIL,
										NULL, NULL, NULL);
					$$ = $1;
				}
			| select_clause opt_sort_clause for_locking_clause opt_select_limit
				{
					insertSelectOptions((SelectStmt *) $1, $2, $3,
										list_nth($4, 0), list_nth($4, 1),
										NULL);
					$$ = $1;
				}
			| select_clause opt_sort_clause select_limit opt_for_locking_clause
				{
					insertSelectOptions((SelectStmt *) $1, $2, $4,
										list_nth($3, 0), list_nth($3, 1),
										NULL);
					$$ = $1;
				}
			| with_clause simple_select
				{
					insertSelectOptions((SelectStmt *) $2, NULL, NIL,
										NULL, NULL,
										$1);
					$$ = $2;
				}
			| with_clause select_clause sort_clause
				{
					insertSelectOptions((SelectStmt *) $2, $3, NIL,
										NULL, NULL,
										$1);
					$$ = $2;
				}
			| with_clause select_clause opt_sort_clause for_locking_clause opt_select_limit
				{
					insertSelectOptions((SelectStmt *) $2, $3, $4,
										list_nth($5, 0), list_nth($5, 1),
										$1);
					$$ = $2;
				}
			| with_clause select_clause opt_sort_clause select_limit opt_for_locking_clause
				{
					insertSelectOptions((SelectStmt *) $2, $3, $5,
										list_nth($4, 0), list_nth($4, 1),
										$1);
					$$ = $2;
				}
		;

select_clause:
			simple_select							{ $$ = $1; }
			| select_with_parens					{ $$ = $1; }
		;

/*
 * This rule parses SELECT statements that can appear within set operations,
 * including UNION, INTERSECT and EXCEPT.  '(' and ')' can be used to specify
 * the ordering of the set operations.	Without '(' and ')' we want the
 * operations to be ordered per the precedence specs at the head of this file.
 *
 * As with select_no_parens, simple_select cannot have outer parentheses,
 * but can have parenthesized subclauses.
 *
 * Note that sort clauses cannot be included at this level --- SQL92 requires
 *		SELECT foo UNION SELECT bar ORDER BY baz
 * to be parsed as
 *		(SELECT foo UNION SELECT bar) ORDER BY baz
 * not
 *		SELECT foo UNION (SELECT bar ORDER BY baz)
 * Likewise for WITH, FOR UPDATE and LIMIT.  Therefore, those clauses are
 * described as part of the select_no_parens production, not simple_select.
 * This does not limit functionality, because you can reintroduce these
 * clauses inside parentheses.
 *
 * NOTE: only the leftmost component SelectStmt should have INTO.
 * However, this is not checked by the grammar; parse analysis must check it.
 */
simple_select:
			SELECT opt_distinct target_list
			into_clause from_clause where_clause
			group_clause having_clause window_clause
				{
					SelectStmt *n = makeNode(SelectStmt);
					n->distinctClause = $2;
					n->targetList = $3;
					n->intoClause = $4;
					n->fromClause = $5;
					n->whereClause = $6;
					n->groupClause = $7;
					n->havingClause = $8;
					n->windowClause = $9;
					$$ = (Node *)n;
				}
			| values_clause							{ $$ = $1; }
			| TABLE relation_expr
				{
					/* same as SELECT * FROM relation_expr */
					ColumnRef *cr = makeNode(ColumnRef);
					ResTarget *rt = makeNode(ResTarget);
					SelectStmt *n = makeNode(SelectStmt);

					cr->fields = list_make1(makeNode(A_Star));
					cr->location = -1;

					rt->name = NULL;
					rt->indirection = NIL;
					rt->val = (Node *)cr;
					rt->location = -1;

					n->targetList = list_make1(rt);
					n->fromClause = list_make1($2);
					$$ = (Node *)n;
				}
			| select_clause UNION opt_all select_clause
				{
					$$ = makeSetOp(SETOP_UNION, $3, $1, $4);
				}
			| select_clause INTERSECT opt_all select_clause
				{
					$$ = makeSetOp(SETOP_INTERSECT, $3, $1, $4);
				}
			| select_clause EXCEPT opt_all select_clause
				{
					$$ = makeSetOp(SETOP_EXCEPT, $3, $1, $4);
				}
		;

/*
 * SQL standard WITH clause looks like:
 *
 * WITH [ RECURSIVE ] <query name> [ (<column>,...) ]
 *		AS (query) [ SEARCH or CYCLE clause ]
 *
 * We don't currently support the SEARCH or CYCLE clause.
 */
with_clause:
		WITH cte_list
			{
				$$ = makeNode(WithClause);
				$$->ctes = $2;
				$$->recursive = false;
				$$->location = @1;
			}
		| WITH RECURSIVE cte_list
			{
				$$ = makeNode(WithClause);
				$$->ctes = $3;
				$$->recursive = true;
				$$->location = @1;
			}
		;

cte_list:
		common_table_expr						{ $$ = list_make1($1); }
		| cte_list ',' common_table_expr		{ $$ = lappend($1, $3); }
		;

common_table_expr:  name opt_name_list AS select_with_parens
			{
				CommonTableExpr *n = makeNode(CommonTableExpr);
				n->ctename = $1;
				n->aliascolnames = $2;
				n->ctequery = $4;
				n->location = @1;
				$$ = (Node *) n;
			}
		;

into_clause:
			INTO OptTempTableName
				{
					$$ = makeNode(IntoClause);
					$$->rel = $2;
					$$->colNames = NIL;
					$$->options = NIL;
					$$->onCommit = ONCOMMIT_NOOP;
					$$->tableSpaceName = NULL;
				}
			| /*EMPTY*/
				{ $$ = NULL; }
		;

/*
 * Redundancy here is needed to avoid shift/reduce conflicts,
 * since TEMP is not a reserved word.  See also OptTemp.
 */
OptTempTableName:
			TEMPORARY opt_table qualified_name
				{
					$$ = $3;
					$$->istemp = true;
				}
			| TEMP opt_table qualified_name
				{
					$$ = $3;
					$$->istemp = true;
				}
			| LOCAL TEMPORARY opt_table qualified_name
				{
					$$ = $4;
					$$->istemp = true;
				}
			| LOCAL TEMP opt_table qualified_name
				{
					$$ = $4;
					$$->istemp = true;
				}
			| GLOBAL TEMPORARY opt_table qualified_name
				{
					$$ = $4;
					$$->istemp = true;
				}
			| GLOBAL TEMP opt_table qualified_name
				{
					$$ = $4;
					$$->istemp = true;
				}
			| TABLE qualified_name
				{
					$$ = $2;
					$$->istemp = false;
				}
			| qualified_name
				{
					$$ = $1;
					$$->istemp = false;
				}
		;

opt_table:	TABLE									{}
			| /*EMPTY*/								{}
		;

opt_all:	ALL										{ $$ = TRUE; }
			| DISTINCT								{ $$ = FALSE; }
			| /*EMPTY*/								{ $$ = FALSE; }
		;

/* We use (NIL) as a placeholder to indicate that all target expressions
 * should be placed in the DISTINCT list during parsetree analysis.
 */
opt_distinct:
			DISTINCT								{ $$ = list_make1(NIL); }
			| DISTINCT ON '(' expr_list ')'			{ $$ = $4; }
			| ALL									{ $$ = NIL; }
			| /*EMPTY*/								{ $$ = NIL; }
		;

opt_sort_clause:
			sort_clause								{ $$ = $1;}
			| /*EMPTY*/								{ $$ = NIL; }
		;

sort_clause:
			ORDER BY sortby_list					{ $$ = $3; }
		;

sortby_list:
			sortby									{ $$ = list_make1($1); }
			| sortby_list ',' sortby				{ $$ = lappend($1, $3); }
		;

sortby:		a_expr USING qual_all_Op opt_nulls_order
				{
					$$ = makeNode(SortBy);
					$$->node = $1;
					$$->sortby_dir = SORTBY_USING;
					$$->sortby_nulls = $4;
					$$->useOp = $3;
					$$->location = @3;
				}
			| a_expr opt_asc_desc opt_nulls_order
				{
					$$ = makeNode(SortBy);
					$$->node = $1;
					$$->sortby_dir = $2;
					$$->sortby_nulls = $3;
					$$->useOp = NIL;
					$$->location = -1;		/* no operator */
				}
		;


select_limit:
			LIMIT select_limit_value OFFSET select_offset_value
				{ $$ = list_make2($4, $2); }
			| OFFSET select_offset_value LIMIT select_limit_value
				{ $$ = list_make2($2, $4); }
			| LIMIT select_limit_value
				{ $$ = list_make2(NULL, $2); }
			| OFFSET select_offset_value
				{ $$ = list_make2($2, NULL); }
			| LIMIT select_limit_value ',' select_offset_value
				{
					/* Disabled because it was too confusing, bjm 2002-02-18 */
					ereport(ERROR,
							(errcode(ERRCODE_SYNTAX_ERROR),
							 errmsg("LIMIT #,# syntax is not supported"),
							 errhint("Use separate LIMIT and OFFSET clauses."),
							 scanner_errposition(@1)));
				}
			/* SQL:2008 syntax variants */
			| OFFSET select_offset_value2 row_or_rows
				{ $$ = list_make2($2, NULL); }
			| FETCH first_or_next opt_select_fetch_first_value row_or_rows ONLY
				{ $$ = list_make2(NULL, $3); }
			| OFFSET select_offset_value2 row_or_rows FETCH first_or_next opt_select_fetch_first_value row_or_rows ONLY
				{ $$ = list_make2($2, $6); }
		;

opt_select_limit:
			select_limit							{ $$ = $1; }
			| /* EMPTY */
					{ $$ = list_make2(NULL,NULL); }
		;

select_limit_value:
			a_expr									{ $$ = $1; }
			| ALL
				{
					/* LIMIT ALL is represented as a NULL constant */
					$$ = makeNullAConst(@1);
				}
		;

/*
 * Allowing full expressions without parentheses causes various parsing
 * problems with the trailing ROW/ROWS key words.  SQL only calls for
 * constants, so we allow the rest only with parentheses.
 */
opt_select_fetch_first_value:
			SignedIconst		{ $$ = makeIntConst($1, @1); }
			| '(' a_expr ')'	{ $$ = $2; }
			| /*EMPTY*/		{ $$ = makeIntConst(1, -1); }
		;

select_offset_value:
			a_expr									{ $$ = $1; }
		;

/*
 * Again, the trailing ROW/ROWS in this case prevent the full expression
 * syntax.  c_expr is the best we can do.
 */
select_offset_value2:
			c_expr									{ $$ = $1; }
		;

/* noise words */
row_or_rows:
			ROW		{ $$ = 0; }
			| ROWS		{ $$ = 0; }
			;

/* noise words */
first_or_next:
			FIRST_P		{ $$ = 0; }
			| NEXT		{ $$ = 0; }
			;

group_clause:
			GROUP_P BY expr_list					{ $$ = $3; }
			| /*EMPTY*/								{ $$ = NIL; }
		;

having_clause:
			HAVING a_expr							{ $$ = $2; }
			| /*EMPTY*/								{ $$ = NULL; }
		;

for_locking_clause:
			for_locking_items						{ $$ = $1; }
			| FOR READ ONLY							{ $$ = NIL; }
		;

opt_for_locking_clause:
			for_locking_clause						{ $$ = $1; }
			| /* EMPTY */							{ $$ = NIL; }
		;

for_locking_items:
			for_locking_item						{ $$ = list_make1($1); }
			| for_locking_items for_locking_item	{ $$ = lappend($1, $2); }
		;

for_locking_item:
			FOR UPDATE locked_rels_list opt_nowait
				{
					LockingClause *n = makeNode(LockingClause);
					n->lockedRels = $3;
					n->forUpdate = TRUE;
					n->noWait = $4;
					$$ = (Node *) n;
				}
			| FOR SHARE locked_rels_list opt_nowait
				{
					LockingClause *n = makeNode(LockingClause);
					n->lockedRels = $3;
					n->forUpdate = FALSE;
					n->noWait = $4;
					$$ = (Node *) n;
				}
		;

locked_rels_list:
			OF qualified_name_list					{ $$ = $2; }
			| /* EMPTY */							{ $$ = NIL; }
		;


values_clause:
			VALUES ctext_row
				{
					SelectStmt *n = makeNode(SelectStmt);
					n->valuesLists = list_make1($2);
					$$ = (Node *) n;
				}
			| values_clause ',' ctext_row
				{
					SelectStmt *n = (SelectStmt *) $1;
					n->valuesLists = lappend(n->valuesLists, $3);
					$$ = (Node *) n;
				}
		;


/*****************************************************************************
 *
 *	clauses common to all Optimizable Stmts:
 *		from_clause		- allow list of both JOIN expressions and table names
 *		where_clause	- qualifications for joins or restrictions
 *
 *****************************************************************************/

from_clause:
			FROM from_list							{ $$ = $2; }
			| /*EMPTY*/								{ $$ = NIL; }
		;

from_list:
			table_ref								{ $$ = list_make1($1); }
			| from_list ',' table_ref				{ $$ = lappend($1, $3); }
		;

/*
 * table_ref is where an alias clause can be attached.	Note we cannot make
 * alias_clause have an empty production because that causes parse conflicts
 * between table_ref := '(' joined_table ')' alias_clause
 * and joined_table := '(' joined_table ')'.  So, we must have the
 * redundant-looking productions here instead.
 */
table_ref:	relation_expr
				{
					$$ = (Node *) $1;
				}
			| relation_expr alias_clause
				{
					$1->alias = $2;
					$$ = (Node *) $1;
				}
			| func_table
				{
					RangeFunction *n = makeNode(RangeFunction);
					n->funccallnode = $1;
					n->coldeflist = NIL;
					$$ = (Node *) n;
				}
			| func_table alias_clause
				{
					RangeFunction *n = makeNode(RangeFunction);
					n->funccallnode = $1;
					n->alias = $2;
					n->coldeflist = NIL;
					$$ = (Node *) n;
				}
			| func_table AS '(' TableFuncElementList ')'
				{
					RangeFunction *n = makeNode(RangeFunction);
					n->funccallnode = $1;
					n->coldeflist = $4;
					$$ = (Node *) n;
				}
			| func_table AS ColId '(' TableFuncElementList ')'
				{
					RangeFunction *n = makeNode(RangeFunction);
					Alias *a = makeNode(Alias);
					n->funccallnode = $1;
					a->aliasname = $3;
					n->alias = a;
					n->coldeflist = $5;
					$$ = (Node *) n;
				}
			| func_table ColId '(' TableFuncElementList ')'
				{
					RangeFunction *n = makeNode(RangeFunction);
					Alias *a = makeNode(Alias);
					n->funccallnode = $1;
					a->aliasname = $2;
					n->alias = a;
					n->coldeflist = $4;
					$$ = (Node *) n;
				}
			| select_with_parens
				{
					/*
					 * The SQL spec does not permit a subselect
					 * (<derived_table>) without an alias clause,
					 * so we don't either.  This avoids the problem
					 * of needing to invent a unique refname for it.
					 * That could be surmounted if there's sufficient
					 * popular demand, but for now let's just implement
					 * the spec and see if anyone complains.
					 * However, it does seem like a good idea to emit
					 * an error message that's better than "syntax error".
					 */
					if (IsA($1, SelectStmt) &&
						((SelectStmt *) $1)->valuesLists)
						ereport(ERROR,
								(errcode(ERRCODE_SYNTAX_ERROR),
								 errmsg("VALUES in FROM must have an alias"),
								 errhint("For example, FROM (VALUES ...) [AS] foo."),
								 scanner_errposition(@1)));
					else
						ereport(ERROR,
								(errcode(ERRCODE_SYNTAX_ERROR),
								 errmsg("subquery in FROM must have an alias"),
								 errhint("For example, FROM (SELECT ...) [AS] foo."),
								 scanner_errposition(@1)));
					$$ = NULL;
				}
			| select_with_parens alias_clause
				{
					RangeSubselect *n = makeNode(RangeSubselect);
					n->subquery = $1;
					n->alias = $2;
					$$ = (Node *) n;
				}
			| joined_table
				{
					$$ = (Node *) $1;
				}
			| '(' joined_table ')' alias_clause
				{
					$2->alias = $4;
					$$ = (Node *) $2;
				}
		;


/*
 * It may seem silly to separate joined_table from table_ref, but there is
 * method in SQL92's madness: if you don't do it this way you get reduce-
 * reduce conflicts, because it's not clear to the parser generator whether
 * to expect alias_clause after ')' or not.  For the same reason we must
 * treat 'JOIN' and 'join_type JOIN' separately, rather than allowing
 * join_type to expand to empty; if we try it, the parser generator can't
 * figure out when to reduce an empty join_type right after table_ref.
 *
 * Note that a CROSS JOIN is the same as an unqualified
 * INNER JOIN, and an INNER JOIN/ON has the same shape
 * but a qualification expression to limit membership.
 * A NATURAL JOIN implicitly matches column names between
 * tables and the shape is determined by which columns are
 * in common. We'll collect columns during the later transformations.
 */

joined_table:
			'(' joined_table ')'
				{
					$$ = $2;
				}
			| table_ref CROSS JOIN table_ref
				{
					/* CROSS JOIN is same as unqualified inner join */
					JoinExpr *n = makeNode(JoinExpr);
					n->jointype = JOIN_INNER;
					n->isNatural = FALSE;
					n->larg = $1;
					n->rarg = $4;
					n->using = NIL;
					n->quals = NULL;
					$$ = n;
				}
			| table_ref join_type JOIN table_ref join_qual
				{
					JoinExpr *n = makeNode(JoinExpr);
					n->jointype = $2;
					n->isNatural = FALSE;
					n->larg = $1;
					n->rarg = $4;
					if ($5 != NULL && IsA($5, List))
						n->using = (List *) $5; /* USING clause */
					else
						n->quals = $5; /* ON clause */
					$$ = n;
				}
			| table_ref JOIN table_ref join_qual
				{
					/* letting join_type reduce to empty doesn't work */
					JoinExpr *n = makeNode(JoinExpr);
					n->jointype = JOIN_INNER;
					n->isNatural = FALSE;
					n->larg = $1;
					n->rarg = $3;
					if ($4 != NULL && IsA($4, List))
						n->using = (List *) $4; /* USING clause */
					else
						n->quals = $4; /* ON clause */
					$$ = n;
				}
			| table_ref NATURAL join_type JOIN table_ref
				{
					JoinExpr *n = makeNode(JoinExpr);
					n->jointype = $3;
					n->isNatural = TRUE;
					n->larg = $1;
					n->rarg = $5;
					n->using = NIL; /* figure out which columns later... */
					n->quals = NULL; /* fill later */
					$$ = n;
				}
			| table_ref NATURAL JOIN table_ref
				{
					/* letting join_type reduce to empty doesn't work */
					JoinExpr *n = makeNode(JoinExpr);
					n->jointype = JOIN_INNER;
					n->isNatural = TRUE;
					n->larg = $1;
					n->rarg = $4;
					n->using = NIL; /* figure out which columns later... */
					n->quals = NULL; /* fill later */
					$$ = n;
				}
		;

alias_clause:
			AS ColId '(' name_list ')'
				{
					$$ = makeNode(Alias);
					$$->aliasname = $2;
					$$->colnames = $4;
				}
			| AS ColId
				{
					$$ = makeNode(Alias);
					$$->aliasname = $2;
				}
			| ColId '(' name_list ')'
				{
					$$ = makeNode(Alias);
					$$->aliasname = $1;
					$$->colnames = $3;
				}
			| ColId
				{
					$$ = makeNode(Alias);
					$$->aliasname = $1;
				}
		;

join_type:	FULL join_outer							{ $$ = JOIN_FULL; }
			| LEFT join_outer						{ $$ = JOIN_LEFT; }
			| RIGHT join_outer						{ $$ = JOIN_RIGHT; }
			| INNER_P								{ $$ = JOIN_INNER; }
		;

/* OUTER is just noise... */
join_outer: OUTER_P									{ $$ = NULL; }
			| /*EMPTY*/								{ $$ = NULL; }
		;

/* JOIN qualification clauses
 * Possibilities are:
 *	USING ( column list ) allows only unqualified column names,
 *						  which must match between tables.
 *	ON expr allows more general qualifications.
 *
 * We return USING as a List node, while an ON-expr will not be a List.
 */

join_qual:	USING '(' name_list ')'					{ $$ = (Node *) $3; }
			| ON a_expr								{ $$ = $2; }
		;


relation_expr:
			qualified_name
				{
					/* default inheritance */
					$$ = $1;
					$$->inhOpt = INH_DEFAULT;
					$$->alias = NULL;
				}
			| qualified_name '*'
				{
					/* inheritance query */
					$$ = $1;
					$$->inhOpt = INH_YES;
					$$->alias = NULL;
				}
			| ONLY qualified_name
				{
					/* no inheritance */
					$$ = $2;
					$$->inhOpt = INH_NO;
					$$->alias = NULL;
				}
			| ONLY '(' qualified_name ')'
				{
					/* no inheritance, SQL99-style syntax */
					$$ = $3;
					$$->inhOpt = INH_NO;
					$$->alias = NULL;
				}
		;


relation_expr_list:
			relation_expr							{ $$ = list_make1($1); }
			| relation_expr_list ',' relation_expr	{ $$ = lappend($1, $3); }
		;


/*
 * Given "UPDATE foo set set ...", we have to decide without looking any
 * further ahead whether the first "set" is an alias or the UPDATE's SET
 * keyword.  Since "set" is allowed as a column name both interpretations
 * are feasible.  We resolve the shift/reduce conflict by giving the first
 * relation_expr_opt_alias production a higher precedence than the SET token
 * has, causing the parser to prefer to reduce, in effect assuming that the
 * SET is not an alias.
 */
relation_expr_opt_alias: relation_expr					%prec UMINUS
				{
					$$ = $1;
				}
			| relation_expr ColId
				{
					Alias *alias = makeNode(Alias);
					alias->aliasname = $2;
					$1->alias = alias;
					$$ = $1;
				}
			| relation_expr AS ColId
				{
					Alias *alias = makeNode(Alias);
					alias->aliasname = $3;
					$1->alias = alias;
					$$ = $1;
				}
		;


func_table: func_expr								{ $$ = $1; }
		;


where_clause:
			WHERE a_expr							{ $$ = $2; }
			| /*EMPTY*/								{ $$ = NULL; }
		;

/* variant for UPDATE and DELETE */
where_or_current_clause:
			WHERE a_expr							{ $$ = $2; }
			| WHERE CURRENT_P OF name
				{
					CurrentOfExpr *n = makeNode(CurrentOfExpr);
					/* cvarno is filled in by parse analysis */
					n->cursor_name = $4;
					n->cursor_param = 0;
					$$ = (Node *) n;
				}
			| WHERE CURRENT_P OF PARAM
				{
					CurrentOfExpr *n = makeNode(CurrentOfExpr);
					/* cvarno is filled in by parse analysis */
					n->cursor_name = NULL;
					n->cursor_param = $4;
					$$ = (Node *) n;
				}
			| /*EMPTY*/								{ $$ = NULL; }
		;


TableFuncElementList:
			TableFuncElement
				{
					$$ = list_make1($1);
				}
			| TableFuncElementList ',' TableFuncElement
				{
					$$ = lappend($1, $3);
				}
		;

TableFuncElement:	ColId Typename
				{
					ColumnDef *n = makeNode(ColumnDef);
					n->colname = $1;
					n->typename = $2;
					n->constraints = NIL;
					n->is_local = true;
					$$ = (Node *)n;
				}
		;

/*****************************************************************************
 *
 *	Type syntax
 *		SQL92 introduces a large amount of type-specific syntax.
 *		Define individual clauses to handle these cases, and use
 *		 the generic case to handle regular type-extensible Postgres syntax.
 *		- thomas 1997-10-10
 *
 *****************************************************************************/

Typename:	SimpleTypename opt_array_bounds
				{
					$$ = $1;
					$$->arrayBounds = $2;
				}
			| SETOF SimpleTypename opt_array_bounds
				{
					$$ = $2;
					$$->arrayBounds = $3;
					$$->setof = TRUE;
				}
			/* SQL standard syntax, currently only one-dimensional */
			| SimpleTypename ARRAY '[' Iconst ']'
				{
					$$ = $1;
					$$->arrayBounds = list_make1(makeInteger($4));
				}
			| SETOF SimpleTypename ARRAY '[' Iconst ']'
				{
					$$ = $2;
					$$->arrayBounds = list_make1(makeInteger($5));
					$$->setof = TRUE;
				}
			| SimpleTypename ARRAY
				{
					$$ = $1;
					$$->arrayBounds = list_make1(makeInteger(-1));
				}
			| SETOF SimpleTypename ARRAY
				{
					$$ = $2;
					$$->arrayBounds = list_make1(makeInteger(-1));
					$$->setof = TRUE;
				}
		;

opt_array_bounds:
			opt_array_bounds '[' ']'
					{  $$ = lappend($1, makeInteger(-1)); }
			| opt_array_bounds '[' Iconst ']'
					{  $$ = lappend($1, makeInteger($3)); }
			| /*EMPTY*/
					{  $$ = NIL; }
		;

SimpleTypename:
			GenericType								{ $$ = $1; }
			| Numeric								{ $$ = $1; }
			| Bit									{ $$ = $1; }
			| Character								{ $$ = $1; }
			| ConstDatetime							{ $$ = $1; }
			| ConstInterval opt_interval
				{
					$$ = $1;
					$$->typmods = $2;
				}
			| ConstInterval '(' Iconst ')' opt_interval
				{
					$$ = $1;
					if ($5 != NIL)
					{
						if (list_length($5) != 1)
							ereport(ERROR,
									(errcode(ERRCODE_SYNTAX_ERROR),
									 errmsg("interval precision specified twice"),
									 scanner_errposition(@1)));
						$$->typmods = lappend($5, makeIntConst($3, @3));
					}
					else
						$$->typmods = list_make2(makeIntConst(INTERVAL_FULL_RANGE, -1),
												 makeIntConst($3, @3));
				}
		;

/* We have a separate ConstTypename to allow defaulting fixed-length
 * types such as CHAR() and BIT() to an unspecified length.
 * SQL9x requires that these default to a length of one, but this
 * makes no sense for constructs like CHAR 'hi' and BIT '0101',
 * where there is an obvious better choice to make.
 * Note that ConstInterval is not included here since it must
 * be pushed up higher in the rules to accomodate the postfix
 * options (e.g. INTERVAL '1' YEAR). Likewise, we have to handle
 * the generic-type-name case in AExprConst to avoid premature
 * reduce/reduce conflicts against function names.
 */
ConstTypename:
			Numeric									{ $$ = $1; }
			| ConstBit								{ $$ = $1; }
			| ConstCharacter						{ $$ = $1; }
			| ConstDatetime							{ $$ = $1; }
		;

/*
 * GenericType covers all type names that don't have special syntax mandated
 * by the standard, including qualified names.  We also allow type modifiers.
 * To avoid parsing conflicts against function invocations, the modifiers
 * have to be shown as expr_list here, but parse analysis will only accept
 * constants for them.
 */
GenericType:
			type_function_name opt_type_modifiers
				{
					$$ = makeTypeName($1);
					$$->typmods = $2;
					$$->location = @1;
				}
			| type_function_name attrs opt_type_modifiers
				{
					$$ = makeTypeNameFromNameList(lcons(makeString($1), $2));
					$$->typmods = $3;
					$$->location = @1;
				}
		;

opt_type_modifiers: '(' expr_list ')'				{ $$ = $2; }
					| /* EMPTY */					{ $$ = NIL; }
		;

/*
 * SQL92 numeric data types
 */
Numeric:	INT_P
				{
					$$ = SystemTypeName("int4");
					$$->location = @1;
				}
			| INTEGER
				{
					$$ = SystemTypeName("int4");
					$$->location = @1;
				}
			| SMALLINT
				{
					$$ = SystemTypeName("int2");
					$$->location = @1;
				}
			| BIGINT
				{
					$$ = SystemTypeName("int8");
					$$->location = @1;
				}
			| REAL
				{
					$$ = SystemTypeName("float4");
					$$->location = @1;
				}
			| FLOAT_P opt_float
				{
					$$ = $2;
					$$->location = @1;
				}
			| DOUBLE_P PRECISION
				{
					$$ = SystemTypeName("float8");
					$$->location = @1;
				}
			| DECIMAL_P opt_type_modifiers
				{
					$$ = SystemTypeName("numeric");
					$$->typmods = $2;
					$$->location = @1;
				}
			| DEC opt_type_modifiers
				{
					$$ = SystemTypeName("numeric");
					$$->typmods = $2;
					$$->location = @1;
				}
			| NUMERIC opt_type_modifiers
				{
					$$ = SystemTypeName("numeric");
					$$->typmods = $2;
					$$->location = @1;
				}
			| BOOLEAN_P
				{
					$$ = SystemTypeName("bool");
					$$->location = @1;
				}
		;

opt_float:	'(' Iconst ')'
				{
					/*
					 * Check FLOAT() precision limits assuming IEEE floating
					 * types - thomas 1997-09-18
					 */
					if ($2 < 1)
						ereport(ERROR,
								(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
								 errmsg("precision for type float must be at least 1 bit"),
								 scanner_errposition(@2)));
					else if ($2 <= 24)
						$$ = SystemTypeName("float4");
					else if ($2 <= 53)
						$$ = SystemTypeName("float8");
					else
						ereport(ERROR,
								(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
								 errmsg("precision for type float must be less than 54 bits"),
								 scanner_errposition(@2)));
				}
			| /*EMPTY*/
				{
					$$ = SystemTypeName("float8");
				}
		;

/*
 * SQL92 bit-field data types
 * The following implements BIT() and BIT VARYING().
 */
Bit:		BitWithLength
				{
					$$ = $1;
				}
			| BitWithoutLength
				{
					$$ = $1;
				}
		;

/* ConstBit is like Bit except "BIT" defaults to unspecified length */
/* See notes for ConstCharacter, which addresses same issue for "CHAR" */
ConstBit:	BitWithLength
				{
					$$ = $1;
				}
			| BitWithoutLength
				{
					$$ = $1;
					$$->typmods = NIL;
				}
		;

BitWithLength:
			BIT opt_varying '(' expr_list ')'
				{
					char *typname;

					typname = $2 ? "varbit" : "bit";
					$$ = SystemTypeName(typname);
					$$->typmods = $4;
					$$->location = @1;
				}
		;

BitWithoutLength:
			BIT opt_varying
				{
					/* bit defaults to bit(1), varbit to no limit */
					if ($2)
					{
						$$ = SystemTypeName("varbit");
					}
					else
					{
						$$ = SystemTypeName("bit");
						$$->typmods = list_make1(makeIntConst(1, -1));
					}
					$$->location = @1;
				}
		;


/*
 * SQL92 character data types
 * The following implements CHAR() and VARCHAR().
 */
Character:  CharacterWithLength
				{
					$$ = $1;
				}
			| CharacterWithoutLength
				{
					$$ = $1;
				}
		;

ConstCharacter:  CharacterWithLength
				{
					$$ = $1;
				}
			| CharacterWithoutLength
				{
					/* Length was not specified so allow to be unrestricted.
					 * This handles problems with fixed-length (bpchar) strings
					 * which in column definitions must default to a length
					 * of one, but should not be constrained if the length
					 * was not specified.
					 */
					$$ = $1;
					$$->typmods = NIL;
				}
		;

CharacterWithLength:  character '(' Iconst ')' opt_charset
				{
					if (($5 != NULL) && (strcmp($5, "sql_text") != 0))
					{
						char *type;

						type = palloc(strlen($1) + 1 + strlen($5) + 1);
						strcpy(type, $1);
						strcat(type, "_");
						strcat(type, $5);
						$1 = type;
					}

					$$ = SystemTypeName($1);
					$$->typmods = list_make1(makeIntConst($3, @3));
					$$->location = @1;
				}
		;

CharacterWithoutLength:	 character opt_charset
				{
					if (($2 != NULL) && (strcmp($2, "sql_text") != 0))
					{
						char *type;

						type = palloc(strlen($1) + 1 + strlen($2) + 1);
						strcpy(type, $1);
						strcat(type, "_");
						strcat(type, $2);
						$1 = type;
					}

					$$ = SystemTypeName($1);

					/* char defaults to char(1), varchar to no limit */
					if (strcmp($1, "bpchar") == 0)
						$$->typmods = list_make1(makeIntConst(1, -1));

					$$->location = @1;
				}
		;

character:	CHARACTER opt_varying
										{ $$ = $2 ? "varchar": "bpchar"; }
			| CHAR_P opt_varying
										{ $$ = $2 ? "varchar": "bpchar"; }
			| VARCHAR
										{ $$ = "varchar"; }
			| NATIONAL CHARACTER opt_varying
										{ $$ = $3 ? "varchar": "bpchar"; }
			| NATIONAL CHAR_P opt_varying
										{ $$ = $3 ? "varchar": "bpchar"; }
			| NCHAR opt_varying
										{ $$ = $2 ? "varchar": "bpchar"; }
		;

opt_varying:
			VARYING									{ $$ = TRUE; }
			| /*EMPTY*/								{ $$ = FALSE; }
		;

opt_charset:
			CHARACTER SET ColId						{ $$ = $3; }
			| /*EMPTY*/								{ $$ = NULL; }
		;

/*
 * SQL92 date/time types
 */
ConstDatetime:
			TIMESTAMP '(' Iconst ')' opt_timezone
				{
					if ($5)
						$$ = SystemTypeName("timestamptz");
					else
						$$ = SystemTypeName("timestamp");
					$$->typmods = list_make1(makeIntConst($3, @3));
					$$->location = @1;
				}
			| TIMESTAMP opt_timezone
				{
					if ($2)
						$$ = SystemTypeName("timestamptz");
					else
						$$ = SystemTypeName("timestamp");
					$$->location = @1;
				}
			| TIME '(' Iconst ')' opt_timezone
				{
					if ($5)
						$$ = SystemTypeName("timetz");
					else
						$$ = SystemTypeName("time");
					$$->typmods = list_make1(makeIntConst($3, @3));
					$$->location = @1;
				}
			| TIME opt_timezone
				{
					if ($2)
						$$ = SystemTypeName("timetz");
					else
						$$ = SystemTypeName("time");
					$$->location = @1;
				}
		;

ConstInterval:
			INTERVAL
				{
					$$ = SystemTypeName("interval");
					$$->location = @1;
				}
		;

opt_timezone:
			WITH_TIME ZONE							{ $$ = TRUE; }
			| WITHOUT TIME ZONE						{ $$ = FALSE; }
			| /*EMPTY*/								{ $$ = FALSE; }
		;

opt_interval:
			YEAR_P
				{ $$ = list_make1(makeIntConst(INTERVAL_MASK(YEAR), @1)); }
			| MONTH_P
				{ $$ = list_make1(makeIntConst(INTERVAL_MASK(MONTH), @1)); }
			| DAY_P
				{ $$ = list_make1(makeIntConst(INTERVAL_MASK(DAY), @1)); }
			| HOUR_P
				{ $$ = list_make1(makeIntConst(INTERVAL_MASK(HOUR), @1)); }
			| MINUTE_P
				{ $$ = list_make1(makeIntConst(INTERVAL_MASK(MINUTE), @1)); }
			| interval_second
				{ $$ = $1; }
			| YEAR_P TO MONTH_P
				{
					$$ = list_make1(makeIntConst(INTERVAL_MASK(YEAR) |
												 INTERVAL_MASK(MONTH), @1));
				}
			| DAY_P TO HOUR_P
				{
					$$ = list_make1(makeIntConst(INTERVAL_MASK(DAY) |
												 INTERVAL_MASK(HOUR), @1));
				}
			| DAY_P TO MINUTE_P
				{
					$$ = list_make1(makeIntConst(INTERVAL_MASK(DAY) |
												 INTERVAL_MASK(HOUR) |
												 INTERVAL_MASK(MINUTE), @1));
				}
			| DAY_P TO interval_second
				{
					$$ = $3;
					linitial($$) = makeIntConst(INTERVAL_MASK(DAY) |
												INTERVAL_MASK(HOUR) |
												INTERVAL_MASK(MINUTE) |
												INTERVAL_MASK(SECOND), @1);
				}
			| HOUR_P TO MINUTE_P
				{
					$$ = list_make1(makeIntConst(INTERVAL_MASK(HOUR) |
												 INTERVAL_MASK(MINUTE), @1));
				}
			| HOUR_P TO interval_second
				{
					$$ = $3;
					linitial($$) = makeIntConst(INTERVAL_MASK(HOUR) |
												INTERVAL_MASK(MINUTE) |
												INTERVAL_MASK(SECOND), @1);
				}
			| MINUTE_P TO interval_second
				{
					$$ = $3;
					linitial($$) = makeIntConst(INTERVAL_MASK(MINUTE) |
												INTERVAL_MASK(SECOND), @1);
				}
			| /*EMPTY*/
				{ $$ = NIL; }
		;

interval_second:
			SECOND_P
				{
					$$ = list_make1(makeIntConst(INTERVAL_MASK(SECOND), @1));
				}
			| SECOND_P '(' Iconst ')'
				{
					$$ = list_make2(makeIntConst(INTERVAL_MASK(SECOND), @1),
									makeIntConst($3, @3));
				}
		;


/*****************************************************************************
 *
 *	expression grammar
 *
 *****************************************************************************/

/*
 * General expressions
 * This is the heart of the expression syntax.
 *
 * We have two expression types: a_expr is the unrestricted kind, and
 * b_expr is a subset that must be used in some places to avoid shift/reduce
 * conflicts.  For example, we can't do BETWEEN as "BETWEEN a_expr AND a_expr"
 * because that use of AND conflicts with AND as a boolean operator.  So,
 * b_expr is used in BETWEEN and we remove boolean keywords from b_expr.
 *
 * Note that '(' a_expr ')' is a b_expr, so an unrestricted expression can
 * always be used by surrounding it with parens.
 *
 * c_expr is all the productions that are common to a_expr and b_expr;
 * it's factored out just to eliminate redundant coding.
 */
a_expr:		c_expr									{ $$ = $1; }
			| a_expr TYPECAST Typename
					{ $$ = makeTypeCast($1, $3, @2); }
			| a_expr AT TIME ZONE a_expr
				{
					FuncCall *n = makeNode(FuncCall);
					n->funcname = SystemFuncName("timezone");
					n->args = list_make2($5, $1);
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = NULL;
					n->location = @2;
					$$ = (Node *) n;
				}
		/*
		 * These operators must be called out explicitly in order to make use
		 * of yacc/bison's automatic operator-precedence handling.  All other
		 * operator names are handled by the generic productions using "Op",
		 * below; and all those operators will have the same precedence.
		 *
		 * If you add more explicitly-known operators, be sure to add them
		 * also to b_expr and to the MathOp list above.
		 */
			| '+' a_expr					%prec UMINUS
				{ $$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "+", NULL, $2, @1); }
			| '-' a_expr					%prec UMINUS
				{ $$ = doNegate($2, @1); }
			| a_expr '+' a_expr
				{ $$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "+", $1, $3, @2); }
			| a_expr '-' a_expr
				{ $$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "-", $1, $3, @2); }
			| a_expr '*' a_expr
				{ $$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "*", $1, $3, @2); }
			| a_expr '/' a_expr
				{ $$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "/", $1, $3, @2); }
			| a_expr '%' a_expr
				{ $$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "%", $1, $3, @2); }
			| a_expr '^' a_expr
				{ $$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "^", $1, $3, @2); }
			| a_expr '<' a_expr
				{ $$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "<", $1, $3, @2); }
			| a_expr '>' a_expr
				{ $$ = (Node *) makeSimpleA_Expr(AEXPR_OP, ">", $1, $3, @2); }
			| a_expr '=' a_expr
				{ $$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "=", $1, $3, @2); }

			| a_expr qual_Op a_expr				%prec Op
				{ $$ = (Node *) makeA_Expr(AEXPR_OP, $2, $1, $3, @2); }
			| qual_Op a_expr					%prec Op
				{ $$ = (Node *) makeA_Expr(AEXPR_OP, $1, NULL, $2, @1); }
			| a_expr qual_Op					%prec POSTFIXOP
				{ $$ = (Node *) makeA_Expr(AEXPR_OP, $2, $1, NULL, @2); }

			| a_expr AND a_expr
				{ $$ = (Node *) makeA_Expr(AEXPR_AND, NIL, $1, $3, @2); }
			| a_expr OR a_expr
				{ $$ = (Node *) makeA_Expr(AEXPR_OR, NIL, $1, $3, @2); }
			| NOT a_expr
				{ $$ = (Node *) makeA_Expr(AEXPR_NOT, NIL, NULL, $2, @1); }

			| a_expr LIKE a_expr
				{ $$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "~~", $1, $3, @2); }
			| a_expr LIKE a_expr ESCAPE a_expr
				{
					FuncCall *n = makeNode(FuncCall);
					n->funcname = SystemFuncName("like_escape");
					n->args = list_make2($3, $5);
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = NULL;
					n->location = @4;
					$$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "~~", $1, (Node *) n, @2);
				}
			| a_expr NOT LIKE a_expr
				{ $$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "!~~", $1, $4, @2); }
			| a_expr NOT LIKE a_expr ESCAPE a_expr
				{
					FuncCall *n = makeNode(FuncCall);
					n->funcname = SystemFuncName("like_escape");
					n->args = list_make2($4, $6);
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = NULL;
					n->location = @5;
					$$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "!~~", $1, (Node *) n, @2);
				}
			| a_expr ILIKE a_expr
				{ $$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "~~*", $1, $3, @2); }
			| a_expr ILIKE a_expr ESCAPE a_expr
				{
					FuncCall *n = makeNode(FuncCall);
					n->funcname = SystemFuncName("like_escape");
					n->args = list_make2($3, $5);
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = NULL;
					n->location = @4;
					$$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "~~*", $1, (Node *) n, @2);
				}
			| a_expr NOT ILIKE a_expr
				{ $$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "!~~*", $1, $4, @2); }
			| a_expr NOT ILIKE a_expr ESCAPE a_expr
				{
					FuncCall *n = makeNode(FuncCall);
					n->funcname = SystemFuncName("like_escape");
					n->args = list_make2($4, $6);
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = NULL;
					n->location = @5;
					$$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "!~~*", $1, (Node *) n, @2);
				}

			| a_expr SIMILAR TO a_expr				%prec SIMILAR
				{
					FuncCall *n = makeNode(FuncCall);
					n->funcname = SystemFuncName("similar_escape");
					n->args = list_make2($4, makeNullAConst(-1));
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = NULL;
					n->location = @2;
					$$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "~", $1, (Node *) n, @2);
				}
			| a_expr SIMILAR TO a_expr ESCAPE a_expr
				{
					FuncCall *n = makeNode(FuncCall);
					n->funcname = SystemFuncName("similar_escape");
					n->args = list_make2($4, $6);
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = NULL;
					n->location = @5;
					$$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "~", $1, (Node *) n, @2);
				}
			| a_expr NOT SIMILAR TO a_expr			%prec SIMILAR
				{
					FuncCall *n = makeNode(FuncCall);
					n->funcname = SystemFuncName("similar_escape");
					n->args = list_make2($5, makeNullAConst(-1));
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = NULL;
					n->location = @5;
					$$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "!~", $1, (Node *) n, @2);
				}
			| a_expr NOT SIMILAR TO a_expr ESCAPE a_expr
				{
					FuncCall *n = makeNode(FuncCall);
					n->funcname = SystemFuncName("similar_escape");
					n->args = list_make2($5, $7);
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = NULL;
					n->location = @6;
					$$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "!~", $1, (Node *) n, @2);
				}

			/* NullTest clause
			 * Define SQL92-style Null test clause.
			 * Allow two forms described in the standard:
			 *	a IS NULL
			 *	a IS NOT NULL
			 * Allow two SQL extensions
			 *	a ISNULL
			 *	a NOTNULL
			 */
			| a_expr IS NULL_P
				{
					NullTest *n = makeNode(NullTest);
					n->arg = (Expr *) $1;
					n->nulltesttype = IS_NULL;
					$$ = (Node *)n;
				}
			| a_expr ISNULL
				{
					NullTest *n = makeNode(NullTest);
					n->arg = (Expr *) $1;
					n->nulltesttype = IS_NULL;
					$$ = (Node *)n;
				}
			| a_expr IS NOT NULL_P
				{
					NullTest *n = makeNode(NullTest);
					n->arg = (Expr *) $1;
					n->nulltesttype = IS_NOT_NULL;
					$$ = (Node *)n;
				}
			| a_expr NOTNULL
				{
					NullTest *n = makeNode(NullTest);
					n->arg = (Expr *) $1;
					n->nulltesttype = IS_NOT_NULL;
					$$ = (Node *)n;
				}
			| row OVERLAPS row
				{
					$$ = (Node *)makeOverlaps($1, $3, @2);
				}
			| a_expr IS TRUE_P
				{
					BooleanTest *b = makeNode(BooleanTest);
					b->arg = (Expr *) $1;
					b->booltesttype = IS_TRUE;
					$$ = (Node *)b;
				}
			| a_expr IS NOT TRUE_P
				{
					BooleanTest *b = makeNode(BooleanTest);
					b->arg = (Expr *) $1;
					b->booltesttype = IS_NOT_TRUE;
					$$ = (Node *)b;
				}
			| a_expr IS FALSE_P
				{
					BooleanTest *b = makeNode(BooleanTest);
					b->arg = (Expr *) $1;
					b->booltesttype = IS_FALSE;
					$$ = (Node *)b;
				}
			| a_expr IS NOT FALSE_P
				{
					BooleanTest *b = makeNode(BooleanTest);
					b->arg = (Expr *) $1;
					b->booltesttype = IS_NOT_FALSE;
					$$ = (Node *)b;
				}
			| a_expr IS UNKNOWN
				{
					BooleanTest *b = makeNode(BooleanTest);
					b->arg = (Expr *) $1;
					b->booltesttype = IS_UNKNOWN;
					$$ = (Node *)b;
				}
			| a_expr IS NOT UNKNOWN
				{
					BooleanTest *b = makeNode(BooleanTest);
					b->arg = (Expr *) $1;
					b->booltesttype = IS_NOT_UNKNOWN;
					$$ = (Node *)b;
				}
			| a_expr IS DISTINCT FROM a_expr			%prec IS
				{
					$$ = (Node *) makeSimpleA_Expr(AEXPR_DISTINCT, "=", $1, $5, @2);
				}
			| a_expr IS NOT DISTINCT FROM a_expr		%prec IS
				{
					$$ = (Node *) makeA_Expr(AEXPR_NOT, NIL, NULL,
									(Node *) makeSimpleA_Expr(AEXPR_DISTINCT,
															  "=", $1, $6, @2),
											 @2);

				}
			| a_expr IS OF '(' type_list ')'			%prec IS
				{
					$$ = (Node *) makeSimpleA_Expr(AEXPR_OF, "=", $1, (Node *) $5, @2);
				}
			| a_expr IS NOT OF '(' type_list ')'		%prec IS
				{
					$$ = (Node *) makeSimpleA_Expr(AEXPR_OF, "<>", $1, (Node *) $6, @2);
				}
			/*
			 *	Ideally we would not use hard-wired operators below but instead use
			 *	opclasses.  However, mixed data types and other issues make this
			 *	difficult:  http://archives.postgresql.org/pgsql-hackers/2008-08/msg01142.php
			 */			
			| a_expr BETWEEN opt_asymmetric b_expr AND b_expr		%prec BETWEEN
				{
					$$ = (Node *) makeA_Expr(AEXPR_AND, NIL,
						(Node *) makeSimpleA_Expr(AEXPR_OP, ">=", $1, $4, @2),
						(Node *) makeSimpleA_Expr(AEXPR_OP, "<=", $1, $6, @2),
											 @2);
				}
			| a_expr NOT BETWEEN opt_asymmetric b_expr AND b_expr	%prec BETWEEN
				{
					$$ = (Node *) makeA_Expr(AEXPR_OR, NIL,
						(Node *) makeSimpleA_Expr(AEXPR_OP, "<", $1, $5, @2),
						(Node *) makeSimpleA_Expr(AEXPR_OP, ">", $1, $7, @2),
											 @2);
				}
			| a_expr BETWEEN SYMMETRIC b_expr AND b_expr			%prec BETWEEN
				{
					$$ = (Node *) makeA_Expr(AEXPR_OR, NIL,
						(Node *) makeA_Expr(AEXPR_AND, NIL,
						    (Node *) makeSimpleA_Expr(AEXPR_OP, ">=", $1, $4, @2),
						    (Node *) makeSimpleA_Expr(AEXPR_OP, "<=", $1, $6, @2),
											@2),
						(Node *) makeA_Expr(AEXPR_AND, NIL,
						    (Node *) makeSimpleA_Expr(AEXPR_OP, ">=", $1, $6, @2),
						    (Node *) makeSimpleA_Expr(AEXPR_OP, "<=", $1, $4, @2),
											@2),
											 @2);
				}
			| a_expr NOT BETWEEN SYMMETRIC b_expr AND b_expr		%prec BETWEEN
				{
					$$ = (Node *) makeA_Expr(AEXPR_AND, NIL,
						(Node *) makeA_Expr(AEXPR_OR, NIL,
						    (Node *) makeSimpleA_Expr(AEXPR_OP, "<", $1, $5, @2),
						    (Node *) makeSimpleA_Expr(AEXPR_OP, ">", $1, $7, @2),
											@2),
						(Node *) makeA_Expr(AEXPR_OR, NIL,
						    (Node *) makeSimpleA_Expr(AEXPR_OP, "<", $1, $7, @2),
						    (Node *) makeSimpleA_Expr(AEXPR_OP, ">", $1, $5, @2),
											@2),
											 @2);
				}
			| a_expr IN_P in_expr
				{
					/* in_expr returns a SubLink or a list of a_exprs */
					if (IsA($3, SubLink))
					{
						/* generate foo = ANY (subquery) */
						SubLink *n = (SubLink *) $3;
						n->subLinkType = ANY_SUBLINK;
						n->testexpr = $1;
						n->operName = list_make1(makeString("="));
						n->location = @2;
						$$ = (Node *)n;
					}
					else
					{
						/* generate scalar IN expression */
						$$ = (Node *) makeSimpleA_Expr(AEXPR_IN, "=", $1, $3, @2);
					}
				}
			| a_expr NOT IN_P in_expr
				{
					/* in_expr returns a SubLink or a list of a_exprs */
					if (IsA($4, SubLink))
					{
						/* generate NOT (foo = ANY (subquery)) */
						/* Make an = ANY node */
						SubLink *n = (SubLink *) $4;
						n->subLinkType = ANY_SUBLINK;
						n->testexpr = $1;
						n->operName = list_make1(makeString("="));
						n->location = @3;
						/* Stick a NOT on top */
						$$ = (Node *) makeA_Expr(AEXPR_NOT, NIL, NULL, (Node *) n, @2);
					}
					else
					{
						/* generate scalar NOT IN expression */
						$$ = (Node *) makeSimpleA_Expr(AEXPR_IN, "<>", $1, $4, @2);
					}
				}
			| a_expr subquery_Op sub_type select_with_parens	%prec Op
				{
					SubLink *n = makeNode(SubLink);
					n->subLinkType = $3;
					n->testexpr = $1;
					n->operName = $2;
					n->subselect = $4;
					n->location = @2;
					$$ = (Node *)n;
				}
			| a_expr subquery_Op sub_type '(' a_expr ')'		%prec Op
				{
					if ($3 == ANY_SUBLINK)
						$$ = (Node *) makeA_Expr(AEXPR_OP_ANY, $2, $1, $5, @2);
					else
						$$ = (Node *) makeA_Expr(AEXPR_OP_ALL, $2, $1, $5, @2);
				}
			| UNIQUE select_with_parens
				{
					/* Not sure how to get rid of the parentheses
					 * but there are lots of shift/reduce errors without them.
					 *
					 * Should be able to implement this by plopping the entire
					 * select into a node, then transforming the target expressions
					 * from whatever they are into count(*), and testing the
					 * entire result equal to one.
					 * But, will probably implement a separate node in the executor.
					 */
					ereport(ERROR,
							(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
							 errmsg("UNIQUE predicate is not yet implemented"),
							 scanner_errposition(@1)));
				}
			| a_expr IS DOCUMENT_P					%prec IS
				{
					$$ = makeXmlExpr(IS_DOCUMENT, NULL, NIL,
									 list_make1($1), @2);
				}
			| a_expr IS NOT DOCUMENT_P				%prec IS
				{
					$$ = (Node *) makeA_Expr(AEXPR_NOT, NIL, NULL,
											 makeXmlExpr(IS_DOCUMENT, NULL, NIL,
														 list_make1($1), @2),
											 @2);
				}
		;

/*
 * Restricted expressions
 *
 * b_expr is a subset of the complete expression syntax defined by a_expr.
 *
 * Presently, AND, NOT, IS, and IN are the a_expr keywords that would
 * cause trouble in the places where b_expr is used.  For simplicity, we
 * just eliminate all the boolean-keyword-operator productions from b_expr.
 */
b_expr:		c_expr
				{ $$ = $1; }
			| b_expr TYPECAST Typename
				{ $$ = makeTypeCast($1, $3, @2); }
			| '+' b_expr					%prec UMINUS
				{ $$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "+", NULL, $2, @1); }
			| '-' b_expr					%prec UMINUS
				{ $$ = doNegate($2, @1); }
			| b_expr '+' b_expr
				{ $$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "+", $1, $3, @2); }
			| b_expr '-' b_expr
				{ $$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "-", $1, $3, @2); }
			| b_expr '*' b_expr
				{ $$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "*", $1, $3, @2); }
			| b_expr '/' b_expr
				{ $$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "/", $1, $3, @2); }
			| b_expr '%' b_expr
				{ $$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "%", $1, $3, @2); }
			| b_expr '^' b_expr
				{ $$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "^", $1, $3, @2); }
			| b_expr '<' b_expr
				{ $$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "<", $1, $3, @2); }
			| b_expr '>' b_expr
				{ $$ = (Node *) makeSimpleA_Expr(AEXPR_OP, ">", $1, $3, @2); }
			| b_expr '=' b_expr
				{ $$ = (Node *) makeSimpleA_Expr(AEXPR_OP, "=", $1, $3, @2); }
			| b_expr qual_Op b_expr				%prec Op
				{ $$ = (Node *) makeA_Expr(AEXPR_OP, $2, $1, $3, @2); }
			| qual_Op b_expr					%prec Op
				{ $$ = (Node *) makeA_Expr(AEXPR_OP, $1, NULL, $2, @1); }
			| b_expr qual_Op					%prec POSTFIXOP
				{ $$ = (Node *) makeA_Expr(AEXPR_OP, $2, $1, NULL, @2); }
			| b_expr IS DISTINCT FROM b_expr		%prec IS
				{
					$$ = (Node *) makeSimpleA_Expr(AEXPR_DISTINCT, "=", $1, $5, @2);
				}
			| b_expr IS NOT DISTINCT FROM b_expr	%prec IS
				{
					$$ = (Node *) makeA_Expr(AEXPR_NOT, NIL,
						NULL, (Node *) makeSimpleA_Expr(AEXPR_DISTINCT, "=", $1, $6, @2), @2);
				}
			| b_expr IS OF '(' type_list ')'		%prec IS
				{
					$$ = (Node *) makeSimpleA_Expr(AEXPR_OF, "=", $1, (Node *) $5, @2);
				}
			| b_expr IS NOT OF '(' type_list ')'	%prec IS
				{
					$$ = (Node *) makeSimpleA_Expr(AEXPR_OF, "<>", $1, (Node *) $6, @2);
				}
			| b_expr IS DOCUMENT_P					%prec IS
				{
					$$ = makeXmlExpr(IS_DOCUMENT, NULL, NIL,
									 list_make1($1), @2);
				}
			| b_expr IS NOT DOCUMENT_P				%prec IS
				{
					$$ = (Node *) makeA_Expr(AEXPR_NOT, NIL, NULL,
											 makeXmlExpr(IS_DOCUMENT, NULL, NIL,
														 list_make1($1), @2),
											 @2);
				}
		;

/*
 * Productions that can be used in both a_expr and b_expr.
 *
 * Note: productions that refer recursively to a_expr or b_expr mostly
 * cannot appear here.	However, it's OK to refer to a_exprs that occur
 * inside parentheses, such as function arguments; that cannot introduce
 * ambiguity to the b_expr syntax.
 */
c_expr:		columnref								{ $$ = $1; }
			| AexprConst							{ $$ = $1; }
			| PARAM opt_indirection
				{
					ParamRef *p = makeNode(ParamRef);
					p->number = $1;
					p->location = @1;
					if ($2)
					{
						A_Indirection *n = makeNode(A_Indirection);
						n->arg = (Node *) p;
						n->indirection = check_indirection($2);
						$$ = (Node *) n;
					}
					else
						$$ = (Node *) p;
				}
			| '(' a_expr ')' opt_indirection
				{
					if ($4)
					{
						A_Indirection *n = makeNode(A_Indirection);
						n->arg = $2;
						n->indirection = check_indirection($4);
						$$ = (Node *)n;
					}
					else
						$$ = $2;
				}
			| case_expr
				{ $$ = $1; }
			| func_expr
				{ $$ = $1; }
			| select_with_parens			%prec UMINUS
				{
					SubLink *n = makeNode(SubLink);
					n->subLinkType = EXPR_SUBLINK;
					n->testexpr = NULL;
					n->operName = NIL;
					n->subselect = $1;
					n->location = @1;
					$$ = (Node *)n;
				}
			| EXISTS select_with_parens
				{
					SubLink *n = makeNode(SubLink);
					n->subLinkType = EXISTS_SUBLINK;
					n->testexpr = NULL;
					n->operName = NIL;
					n->subselect = $2;
					n->location = @1;
					$$ = (Node *)n;
				}
			| ARRAY select_with_parens
				{
					SubLink *n = makeNode(SubLink);
					n->subLinkType = ARRAY_SUBLINK;
					n->testexpr = NULL;
					n->operName = NIL;
					n->subselect = $2;
					n->location = @1;
					$$ = (Node *)n;
				}
			| ARRAY array_expr
				{
					A_ArrayExpr *n = (A_ArrayExpr *) $2;
					Assert(IsA(n, A_ArrayExpr));
					/* point outermost A_ArrayExpr to the ARRAY keyword */
					n->location = @1;
					$$ = (Node *)n;
				}
			| row
				{
					RowExpr *r = makeNode(RowExpr);
					r->args = $1;
					r->row_typeid = InvalidOid;	/* not analyzed yet */
					r->location = @1;
					$$ = (Node *)r;
				}
		;

/*
 * func_expr is split out from c_expr just so that we have a classification
 * for "everything that is a function call or looks like one".  This isn't
 * very important, but it saves us having to document which variants are
 * legal in the backwards-compatible functional-index syntax for CREATE INDEX.
 * (Note that many of the special SQL functions wouldn't actually make any
 * sense as functional index entries, but we ignore that consideration here.)
 */
func_expr:	func_name '(' ')' over_clause
				{
					FuncCall *n = makeNode(FuncCall);
					n->funcname = $1;
					n->args = NIL;
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = $4;
					n->location = @1;
					$$ = (Node *)n;
				}
			| func_name '(' expr_list ')' over_clause
				{
					FuncCall *n = makeNode(FuncCall);
					n->funcname = $1;
					n->args = $3;
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = $5;
					n->location = @1;
					$$ = (Node *)n;
				}
			| func_name '(' VARIADIC a_expr ')' over_clause
				{
					FuncCall *n = makeNode(FuncCall);
					n->funcname = $1;
					n->args = list_make1($4);
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = TRUE;
					n->over = $6;
					n->location = @1;
					$$ = (Node *)n;
				}
			| func_name '(' expr_list ',' VARIADIC a_expr ')' over_clause
				{
					FuncCall *n = makeNode(FuncCall);
					n->funcname = $1;
					n->args = lappend($3, $6);
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = TRUE;
					n->over = $8;
					n->location = @1;
					$$ = (Node *)n;
				}
			| func_name '(' ALL expr_list ')' over_clause
				{
					FuncCall *n = makeNode(FuncCall);
					n->funcname = $1;
					n->args = $4;
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					/* Ideally we'd mark the FuncCall node to indicate
					 * "must be an aggregate", but there's no provision
					 * for that in FuncCall at the moment.
					 */
					n->func_variadic = FALSE;
					n->over = $6;
					n->location = @1;
					$$ = (Node *)n;
				}
			| func_name '(' DISTINCT expr_list ')' over_clause
				{
					FuncCall *n = makeNode(FuncCall);
					n->funcname = $1;
					n->args = $4;
					n->agg_star = FALSE;
					n->agg_distinct = TRUE;
					n->func_variadic = FALSE;
					n->over = $6;
					n->location = @1;
					$$ = (Node *)n;
				}
			| func_name '(' '*' ')' over_clause
				{
					/*
					 * We consider AGGREGATE(*) to invoke a parameterless
					 * aggregate.  This does the right thing for COUNT(*),
					 * and there are no other aggregates in SQL92 that accept
					 * '*' as parameter.
					 *
					 * The FuncCall node is also marked agg_star = true,
					 * so that later processing can detect what the argument
					 * really was.
					 */
					FuncCall *n = makeNode(FuncCall);
					n->funcname = $1;
					n->args = NIL;
					n->agg_star = TRUE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = $5;
					n->location = @1;
					$$ = (Node *)n;
				}
			| CURRENT_DATE
				{
					/*
					 * Translate as "'now'::text::date".
					 *
					 * We cannot use "'now'::date" because coerce_type() will
					 * immediately reduce that to a constant representing
					 * today's date.  We need to delay the conversion until
					 * runtime, else the wrong things will happen when
					 * CURRENT_DATE is used in a column default value or rule.
					 *
					 * This could be simplified if we had a way to generate
					 * an expression tree representing runtime application
					 * of type-input conversion functions.  (As of PG 7.3
					 * that is actually possible, but not clear that we want
					 * to rely on it.)
					 */
					Node *n;
					n = makeStringConstCast("now", @1, SystemTypeName("text"));
					$$ = makeTypeCast(n, SystemTypeName("date"), -1);
				}
			| CURRENT_TIME
				{
					/*
					 * Translate as "'now'::text::timetz".
					 * See comments for CURRENT_DATE.
					 */
					Node *n;
					n = makeStringConstCast("now", @1, SystemTypeName("text"));
					$$ = makeTypeCast(n, SystemTypeName("timetz"), -1);
				}
			| CURRENT_TIME '(' Iconst ')'
				{
					/*
					 * Translate as "'now'::text::timetz(n)".
					 * See comments for CURRENT_DATE.
					 */
					Node *n;
					TypeName *d;
					n = makeStringConstCast("now", @1, SystemTypeName("text"));
					d = SystemTypeName("timetz");
					d->typmods = list_make1(makeIntConst($3, @3));
					$$ = makeTypeCast(n, d, -1);
				}
			| CURRENT_TIMESTAMP
				{
					/*
					 * Translate as "now()", since we have a function that
					 * does exactly what is needed.
					 */
					FuncCall *n = makeNode(FuncCall);
					n->funcname = SystemFuncName("now");
					n->args = NIL;
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = NULL;
					n->location = @1;
					$$ = (Node *)n;
				}
			| CURRENT_TIMESTAMP '(' Iconst ')'
				{
					/*
					 * Translate as "'now'::text::timestamptz(n)".
					 * See comments for CURRENT_DATE.
					 */
					Node *n;
					TypeName *d;
					n = makeStringConstCast("now", @1, SystemTypeName("text"));
					d = SystemTypeName("timestamptz");
					d->typmods = list_make1(makeIntConst($3, @3));
					$$ = makeTypeCast(n, d, -1);
				}
			| LOCALTIME
				{
					/*
					 * Translate as "'now'::text::time".
					 * See comments for CURRENT_DATE.
					 */
					Node *n;
					n = makeStringConstCast("now", @1, SystemTypeName("text"));
					$$ = makeTypeCast((Node *)n, SystemTypeName("time"), -1);
				}
			| LOCALTIME '(' Iconst ')'
				{
					/*
					 * Translate as "'now'::text::time(n)".
					 * See comments for CURRENT_DATE.
					 */
					Node *n;
					TypeName *d;
					n = makeStringConstCast("now", @1, SystemTypeName("text"));
					d = SystemTypeName("time");
					d->typmods = list_make1(makeIntConst($3, @3));
					$$ = makeTypeCast((Node *)n, d, -1);
				}
			| LOCALTIMESTAMP
				{
					/*
					 * Translate as "'now'::text::timestamp".
					 * See comments for CURRENT_DATE.
					 */
					Node *n;
					n = makeStringConstCast("now", @1, SystemTypeName("text"));
					$$ = makeTypeCast(n, SystemTypeName("timestamp"), -1);
				}
			| LOCALTIMESTAMP '(' Iconst ')'
				{
					/*
					 * Translate as "'now'::text::timestamp(n)".
					 * See comments for CURRENT_DATE.
					 */
					Node *n;
					TypeName *d;
					n = makeStringConstCast("now", @1, SystemTypeName("text"));
					d = SystemTypeName("timestamp");
					d->typmods = list_make1(makeIntConst($3, @3));
					$$ = makeTypeCast(n, d, -1);
				}
			| CURRENT_ROLE
				{
					FuncCall *n = makeNode(FuncCall);
					n->funcname = SystemFuncName("current_user");
					n->args = NIL;
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = NULL;
					n->location = @1;
					$$ = (Node *)n;
				}
			| CURRENT_USER
				{
					FuncCall *n = makeNode(FuncCall);
					n->funcname = SystemFuncName("current_user");
					n->args = NIL;
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = NULL;
					n->location = @1;
					$$ = (Node *)n;
				}
			| SESSION_USER
				{
					FuncCall *n = makeNode(FuncCall);
					n->funcname = SystemFuncName("session_user");
					n->args = NIL;
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = NULL;
					n->location = @1;
					$$ = (Node *)n;
				}
			| USER
				{
					FuncCall *n = makeNode(FuncCall);
					n->funcname = SystemFuncName("current_user");
					n->args = NIL;
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = NULL;
					n->location = @1;
					$$ = (Node *)n;
				}
			| CURRENT_CATALOG
				{
					FuncCall *n = makeNode(FuncCall);
					n->funcname = SystemFuncName("current_database");
					n->args = NIL;
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = NULL;
					n->location = @1;
					$$ = (Node *)n;
				}
			| CURRENT_SCHEMA
				{
					FuncCall *n = makeNode(FuncCall);
					n->funcname = SystemFuncName("current_schema");
					n->args = NIL;
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = NULL;
					n->location = @1;
					$$ = (Node *)n;
				}
			| CAST '(' a_expr AS Typename ')'
				{ $$ = makeTypeCast($3, $5, @1); }
			| EXTRACT '(' extract_list ')'
				{
					FuncCall *n = makeNode(FuncCall);
					n->funcname = SystemFuncName("date_part");
					n->args = $3;
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = NULL;
					n->location = @1;
					$$ = (Node *)n;
				}
			| OVERLAY '(' overlay_list ')'
				{
					/* overlay(A PLACING B FROM C FOR D) is converted to
					 * substring(A, 1, C-1) || B || substring(A, C+1, C+D)
					 * overlay(A PLACING B FROM C) is converted to
					 * substring(A, 1, C-1) || B || substring(A, C+1, C+char_length(B))
					 */
					FuncCall *n = makeNode(FuncCall);
					n->funcname = SystemFuncName("overlay");
					n->args = $3;
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = NULL;
					n->location = @1;
					$$ = (Node *)n;
				}
			| POSITION '(' position_list ')'
				{
					/* position(A in B) is converted to position(B, A) */
					FuncCall *n = makeNode(FuncCall);
					n->funcname = SystemFuncName("position");
					n->args = $3;
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = NULL;
					n->location = @1;
					$$ = (Node *)n;
				}
			| SUBSTRING '(' substr_list ')'
				{
					/* substring(A from B for C) is converted to
					 * substring(A, B, C) - thomas 2000-11-28
					 */
					FuncCall *n = makeNode(FuncCall);
					n->funcname = SystemFuncName("substring");
					n->args = $3;
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = NULL;
					n->location = @1;
					$$ = (Node *)n;
				}
			| TREAT '(' a_expr AS Typename ')'
				{
					/* TREAT(expr AS target) converts expr of a particular type to target,
					 * which is defined to be a subtype of the original expression.
					 * In SQL99, this is intended for use with structured UDTs,
					 * but let's make this a generally useful form allowing stronger
					 * coercions than are handled by implicit casting.
					 */
					FuncCall *n = makeNode(FuncCall);
					/* Convert SystemTypeName() to SystemFuncName() even though
					 * at the moment they result in the same thing.
					 */
					n->funcname = SystemFuncName(((Value *)llast($5->names))->val.str);
					n->args = list_make1($3);
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = NULL;
					n->location = @1;
					$$ = (Node *)n;
				}
			| TRIM '(' BOTH trim_list ')'
				{
					/* various trim expressions are defined in SQL92
					 * - thomas 1997-07-19
					 */
					FuncCall *n = makeNode(FuncCall);
					n->funcname = SystemFuncName("btrim");
					n->args = $4;
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = NULL;
					n->location = @1;
					$$ = (Node *)n;
				}
			| TRIM '(' LEADING trim_list ')'
				{
					FuncCall *n = makeNode(FuncCall);
					n->funcname = SystemFuncName("ltrim");
					n->args = $4;
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = NULL;
					n->location = @1;
					$$ = (Node *)n;
				}
			| TRIM '(' TRAILING trim_list ')'
				{
					FuncCall *n = makeNode(FuncCall);
					n->funcname = SystemFuncName("rtrim");
					n->args = $4;
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = NULL;
					n->location = @1;
					$$ = (Node *)n;
				}
			| TRIM '(' trim_list ')'
				{
					FuncCall *n = makeNode(FuncCall);
					n->funcname = SystemFuncName("btrim");
					n->args = $3;
					n->agg_star = FALSE;
					n->agg_distinct = FALSE;
					n->func_variadic = FALSE;
					n->over = NULL;
					n->location = @1;
					$$ = (Node *)n;
				}
			| NULLIF '(' a_expr ',' a_expr ')'
				{
					$$ = (Node *) makeSimpleA_Expr(AEXPR_NULLIF, "=", $3, $5, @1);
				}
			| COALESCE '(' expr_list ')'
				{
					CoalesceExpr *c = makeNode(CoalesceExpr);
					c->args = $3;
					c->location = @1;
					$$ = (Node *)c;
				}
			| GREATEST '(' expr_list ')'
				{
					MinMaxExpr *v = makeNode(MinMaxExpr);
					v->args = $3;
					v->op = IS_GREATEST;
					v->location = @1;
					$$ = (Node *)v;
				}
			| LEAST '(' expr_list ')'
				{
					MinMaxExpr *v = makeNode(MinMaxExpr);
					v->args = $3;
					v->op = IS_LEAST;
					v->location = @1;
					$$ = (Node *)v;
				}
			| XMLCONCAT '(' expr_list ')'
				{
					$$ = makeXmlExpr(IS_XMLCONCAT, NULL, NIL, $3, @1);
				}
			| XMLELEMENT '(' NAME_P ColLabel ')'
				{
					$$ = makeXmlExpr(IS_XMLELEMENT, $4, NIL, NIL, @1);
				}
			| XMLELEMENT '(' NAME_P ColLabel ',' xml_attributes ')'
				{
					$$ = makeXmlExpr(IS_XMLELEMENT, $4, $6, NIL, @1);
				}
			| XMLELEMENT '(' NAME_P ColLabel ',' expr_list ')'
				{
					$$ = makeXmlExpr(IS_XMLELEMENT, $4, NIL, $6, @1);
				}
			| XMLELEMENT '(' NAME_P ColLabel ',' xml_attributes ',' expr_list ')'
				{
					$$ = makeXmlExpr(IS_XMLELEMENT, $4, $6, $8, @1);
				}
			| XMLFOREST '(' xml_attribute_list ')'
				{
					$$ = makeXmlExpr(IS_XMLFOREST, NULL, $3, NIL, @1);
				}
			| XMLPARSE '(' document_or_content a_expr xml_whitespace_option ')'
				{
					XmlExpr *x = (XmlExpr *)
						makeXmlExpr(IS_XMLPARSE, NULL, NIL,
									list_make2($4, makeBoolAConst($5, -1)),
									@1);
					x->xmloption = $3;
					$$ = (Node *)x;
				}
			| XMLPI '(' NAME_P ColLabel ')'
				{
					$$ = makeXmlExpr(IS_XMLPI, $4, NULL, NIL, @1);
				}
			| XMLPI '(' NAME_P ColLabel ',' a_expr ')'
				{
					$$ = makeXmlExpr(IS_XMLPI, $4, NULL, list_make1($6), @1);
				}
			| XMLROOT '(' a_expr ',' xml_root_version opt_xml_root_standalone ')'
				{
					$$ = makeXmlExpr(IS_XMLROOT, NULL, NIL,
									 list_make3($3, $5, $6), @1);
				}
			| XMLSERIALIZE '(' document_or_content a_expr AS SimpleTypename ')'
				{
					XmlSerialize *n = makeNode(XmlSerialize);
					n->xmloption = $3;
					n->expr = $4;
					n->typename = $6;
					n->location = @1;
					$$ = (Node *)n;
				}
		;

/*
 * SQL/XML support
 */
xml_root_version: VERSION_P a_expr
				{ $$ = $2; }
			| VERSION_P NO VALUE_P
				{ $$ = makeNullAConst(-1); }
		;

opt_xml_root_standalone: ',' STANDALONE_P YES_P
				{ $$ = makeIntConst(XML_STANDALONE_YES, -1); }
			| ',' STANDALONE_P NO
				{ $$ = makeIntConst(XML_STANDALONE_NO, -1); }
			| ',' STANDALONE_P NO VALUE_P
				{ $$ = makeIntConst(XML_STANDALONE_NO_VALUE, -1); }
			| /*EMPTY*/
				{ $$ = makeIntConst(XML_STANDALONE_OMITTED, -1); }
		;

xml_attributes: XMLATTRIBUTES '(' xml_attribute_list ')'	{ $$ = $3; }
		;

xml_attribute_list:	xml_attribute_el					{ $$ = list_make1($1); }
			| xml_attribute_list ',' xml_attribute_el	{ $$ = lappend($1, $3); }
		;

xml_attribute_el: a_expr AS ColLabel
				{
					$$ = makeNode(ResTarget);
					$$->name = $3;
					$$->indirection = NIL;
					$$->val = (Node *) $1;
					$$->location = @1;
				}
			| a_expr
				{
					$$ = makeNode(ResTarget);
					$$->name = NULL;
					$$->indirection = NIL;
					$$->val = (Node *) $1;
					$$->location = @1;
				}
		;

document_or_content: DOCUMENT_P						{ $$ = XMLOPTION_DOCUMENT; }
			| CONTENT_P								{ $$ = XMLOPTION_CONTENT; }
		;

xml_whitespace_option: PRESERVE WHITESPACE_P		{ $$ = TRUE; }
			| STRIP_P WHITESPACE_P					{ $$ = FALSE; }
			| /*EMPTY*/								{ $$ = FALSE; }
		;

/*
 * Window Definitions
 */
window_clause:
			WINDOW window_definition_list			{ $$ = $2; }
			| /*EMPTY*/								{ $$ = NIL; }
		;

window_definition_list:
			window_definition						{ $$ = list_make1($1); }
			| window_definition_list ',' window_definition
													{ $$ = lappend($1, $3); }
		;

window_definition:
			ColId AS window_specification
				{
					WindowDef *n = $3;
					n->name = $1;
					$$ = n;
				}
		;

over_clause: OVER window_specification
				{ $$ = $2; }
			| OVER ColId
				{
					WindowDef *n = makeNode(WindowDef);
					n->name = $2;
					n->refname = NULL;
					n->partitionClause = NIL;
					n->orderClause = NIL;
					n->frameOptions = FRAMEOPTION_DEFAULTS;
					n->location = @2;
					$$ = n;
				}
			| /*EMPTY*/
				{ $$ = NULL; }
		;

window_specification: '(' opt_existing_window_name opt_partition_clause
						opt_sort_clause opt_frame_clause ')'
				{
					WindowDef *n = makeNode(WindowDef);
					n->name = NULL;
					n->refname = $2;
					n->partitionClause = $3;
					n->orderClause = $4;
					n->frameOptions = $5;
					n->location = @1;
					$$ = n;
				}
		;

/*
 * If we see PARTITION, RANGE, or ROWS as the first token after the '('
 * of a window_specification, we want the assumption to be that there is
 * no existing_window_name; but those keywords are unreserved and so could
 * be ColIds.  We fix this by making them have the same precedence as IDENT
 * and giving the empty production here a slightly higher precedence, so
 * that the shift/reduce conflict is resolved in favor of reducing the rule.
 * These keywords are thus precluded from being an existing_window_name but
 * are not reserved for any other purpose.
 */
opt_existing_window_name: ColId						{ $$ = $1; }
			| /*EMPTY*/				%prec Op		{ $$ = NULL; }
		;

opt_partition_clause: PARTITION BY expr_list		{ $$ = $3; }
			| /*EMPTY*/								{ $$ = NIL; }
		;

/*
 * This is only a subset of the full SQL:2008 frame_clause grammar.
 * We don't support <expression> PRECEDING, <expression> FOLLOWING,
 * nor <window frame exclusion> yet.
 */
opt_frame_clause:
			RANGE frame_extent
				{
					$$ = FRAMEOPTION_NONDEFAULT | FRAMEOPTION_RANGE | $2;
				}
			| ROWS frame_extent
				{
					$$ = FRAMEOPTION_NONDEFAULT | FRAMEOPTION_ROWS | $2;
				}
			| /*EMPTY*/
				{ $$ = FRAMEOPTION_DEFAULTS; }
		;

frame_extent: frame_bound
				{
					/* reject invalid cases */
					if ($1 & FRAMEOPTION_START_UNBOUNDED_FOLLOWING)
						ereport(ERROR,
								(errcode(ERRCODE_WINDOWING_ERROR),
								 errmsg("frame start cannot be UNBOUNDED FOLLOWING"),
								 scanner_errposition(@1)));
					if ($1 & FRAMEOPTION_START_CURRENT_ROW)
						ereport(ERROR,
								(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
								 errmsg("frame start at CURRENT ROW is not implemented"),
								 scanner_errposition(@1)));
					$$ = $1 | FRAMEOPTION_END_CURRENT_ROW;
				}
			| BETWEEN frame_bound AND frame_bound
				{
					/* reject invalid cases */
					if ($2 & FRAMEOPTION_START_UNBOUNDED_FOLLOWING)
						ereport(ERROR,
								(errcode(ERRCODE_WINDOWING_ERROR),
								 errmsg("frame start cannot be UNBOUNDED FOLLOWING"),
								 scanner_errposition(@2)));
					if ($2 & FRAMEOPTION_START_CURRENT_ROW)
						ereport(ERROR,
								(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
								 errmsg("frame start at CURRENT ROW is not implemented"),
								 scanner_errposition(@2)));
					if ($4 & FRAMEOPTION_START_UNBOUNDED_PRECEDING)
						ereport(ERROR,
								(errcode(ERRCODE_WINDOWING_ERROR),
								 errmsg("frame end cannot be UNBOUNDED PRECEDING"),
								 scanner_errposition(@4)));
					/* shift converts START_ options to END_ options */
					$$ = FRAMEOPTION_BETWEEN | $2 | ($4 << 1);
				}
		;

/*
 * This is used for both frame start and frame end, with output set up on
 * the assumption it's frame start; the frame_extent productions must reject
 * invalid cases.
 */
frame_bound:
			UNBOUNDED PRECEDING
				{
					$$ = FRAMEOPTION_START_UNBOUNDED_PRECEDING;
				}
			| UNBOUNDED FOLLOWING
				{
					$$ = FRAMEOPTION_START_UNBOUNDED_FOLLOWING;
				}
			| CURRENT_P ROW
				{
					$$ = FRAMEOPTION_START_CURRENT_ROW;
				}
		;


/*
 * Supporting nonterminals for expressions.
 */

/* Explicit row production.
 *
 * SQL99 allows an optional ROW keyword, so we can now do single-element rows
 * without conflicting with the parenthesized a_expr production.  Without the
 * ROW keyword, there must be more than one a_expr inside the parens.
 */
row:		ROW '(' expr_list ')'					{ $$ = $3; }
			| ROW '(' ')'							{ $$ = NIL; }
			| '(' expr_list ',' a_expr ')'			{ $$ = lappend($2, $4); }
		;

sub_type:	ANY										{ $$ = ANY_SUBLINK; }
			| SOME									{ $$ = ANY_SUBLINK; }
			| ALL									{ $$ = ALL_SUBLINK; }
		;

all_Op:		Op										{ $$ = $1; }
			| MathOp								{ $$ = $1; }
		;

MathOp:		 '+'									{ $$ = "+"; }
			| '-'									{ $$ = "-"; }
			| '*'									{ $$ = "*"; }
			| '/'									{ $$ = "/"; }
			| '%'									{ $$ = "%"; }
			| '^'									{ $$ = "^"; }
			| '<'									{ $$ = "<"; }
			| '>'									{ $$ = ">"; }
			| '='									{ $$ = "="; }
		;

qual_Op:	Op
					{ $$ = list_make1(makeString($1)); }
			| OPERATOR '(' any_operator ')'
					{ $$ = $3; }
		;

qual_all_Op:
			all_Op
					{ $$ = list_make1(makeString($1)); }
			| OPERATOR '(' any_operator ')'
					{ $$ = $3; }
		;

subquery_Op:
			all_Op
					{ $$ = list_make1(makeString($1)); }
			| OPERATOR '(' any_operator ')'
					{ $$ = $3; }
			| LIKE
					{ $$ = list_make1(makeString("~~")); }
			| NOT LIKE
					{ $$ = list_make1(makeString("!~~")); }
			| ILIKE
					{ $$ = list_make1(makeString("~~*")); }
			| NOT ILIKE
					{ $$ = list_make1(makeString("!~~*")); }
/* cannot put SIMILAR TO here, because SIMILAR TO is a hack.
 * the regular expression is preprocessed by a function (similar_escape),
 * and the ~ operator for posix regular expressions is used.
 *        x SIMILAR TO y     ->    x ~ similar_escape(y)
 * this transformation is made on the fly by the parser upwards.
 * however the SubLink structure which handles any/some/all stuff
 * is not ready for such a thing.
 */
			;

expr_list:	a_expr
				{
					$$ = list_make1($1);
				}
			| expr_list ',' a_expr
				{
					$$ = lappend($1, $3);
				}
		;

type_list:	Typename								{ $$ = list_make1($1); }
			| type_list ',' Typename				{ $$ = lappend($1, $3); }
		;

array_expr: '[' expr_list ']'
				{
					$$ = makeAArrayExpr($2, @1);
				}
			| '[' array_expr_list ']'
				{
					$$ = makeAArrayExpr($2, @1);
				}
			| '[' ']'
				{
					$$ = makeAArrayExpr(NIL, @1);
				}
		;

array_expr_list: array_expr							{ $$ = list_make1($1); }
			| array_expr_list ',' array_expr		{ $$ = lappend($1, $3); }
		;


extract_list:
			extract_arg FROM a_expr
				{
					$$ = list_make2(makeStringConst($1, @1), $3);
				}
			| /*EMPTY*/								{ $$ = NIL; }
		;

/* Allow delimited string Sconst in extract_arg as an SQL extension.
 * - thomas 2001-04-12
 */
extract_arg:
			IDENT									{ $$ = $1; }
			| YEAR_P								{ $$ = "year"; }
			| MONTH_P								{ $$ = "month"; }
			| DAY_P									{ $$ = "day"; }
			| HOUR_P								{ $$ = "hour"; }
			| MINUTE_P								{ $$ = "minute"; }
			| SECOND_P								{ $$ = "second"; }
			| Sconst								{ $$ = $1; }
		;

/* OVERLAY() arguments
 * SQL99 defines the OVERLAY() function:
 * o overlay(text placing text from int for int)
 * o overlay(text placing text from int)
 */
overlay_list:
			a_expr overlay_placing substr_from substr_for
				{
					$$ = list_make4($1, $2, $3, $4);
				}
			| a_expr overlay_placing substr_from
				{
					$$ = list_make3($1, $2, $3);
				}
		;

overlay_placing:
			PLACING a_expr
				{ $$ = $2; }
		;

/* position_list uses b_expr not a_expr to avoid conflict with general IN */

position_list:
			b_expr IN_P b_expr						{ $$ = list_make2($3, $1); }
			| /*EMPTY*/								{ $$ = NIL; }
		;

/* SUBSTRING() arguments
 * SQL9x defines a specific syntax for arguments to SUBSTRING():
 * o substring(text from int for int)
 * o substring(text from int) get entire string from starting point "int"
 * o substring(text for int) get first "int" characters of string
 * o substring(text from pattern) get entire string matching pattern
 * o substring(text from pattern for escape) same with specified escape char
 * We also want to support generic substring functions which accept
 * the usual generic list of arguments. So we will accept both styles
 * here, and convert the SQL9x style to the generic list for further
 * processing. - thomas 2000-11-28
 */
substr_list:
			a_expr substr_from substr_for
				{
					$$ = list_make3($1, $2, $3);
				}
			| a_expr substr_for substr_from
				{
					/* not legal per SQL99, but might as well allow it */
					$$ = list_make3($1, $3, $2);
				}
			| a_expr substr_from
				{
					$$ = list_make2($1, $2);
				}
			| a_expr substr_for
				{
					/*
					 * Since there are no cases where this syntax allows
					 * a textual FOR value, we forcibly cast the argument
					 * to int4.  The possible matches in pg_proc are
					 * substring(text,int4) and substring(text,text),
					 * and we don't want the parser to choose the latter,
					 * which it is likely to do if the second argument
					 * is unknown or doesn't have an implicit cast to int4.
					 */
					$$ = list_make3($1, makeIntConst(1, -1),
									makeTypeCast($2,
												 SystemTypeName("int4"), -1));
				}
			| expr_list
				{
					$$ = $1;
				}
			| /*EMPTY*/
				{ $$ = NIL; }
		;

substr_from:
			FROM a_expr								{ $$ = $2; }
		;

substr_for: FOR a_expr								{ $$ = $2; }
		;

trim_list:	a_expr FROM expr_list					{ $$ = lappend($3, $1); }
			| FROM expr_list						{ $$ = $2; }
			| expr_list								{ $$ = $1; }
		;

in_expr:	select_with_parens
				{
					SubLink *n = makeNode(SubLink);
					n->subselect = $1;
					/* other fields will be filled later */
					$$ = (Node *)n;
				}
			| '(' expr_list ')'						{ $$ = (Node *)$2; }
		;

/*
 * Define SQL92-style case clause.
 * - Full specification
 *	CASE WHEN a = b THEN c ... ELSE d END
 * - Implicit argument
 *	CASE a WHEN b THEN c ... ELSE d END
 */
case_expr:	CASE case_arg when_clause_list case_default END_P
				{
					CaseExpr *c = makeNode(CaseExpr);
					c->casetype = InvalidOid; /* not analyzed yet */
					c->arg = (Expr *) $2;
					c->args = $3;
					c->defresult = (Expr *) $4;
					c->location = @1;
					$$ = (Node *)c;
				}
		;

when_clause_list:
			/* There must be at least one */
			when_clause								{ $$ = list_make1($1); }
			| when_clause_list when_clause			{ $$ = lappend($1, $2); }
		;

when_clause:
			WHEN a_expr THEN a_expr
				{
					CaseWhen *w = makeNode(CaseWhen);
					w->expr = (Expr *) $2;
					w->result = (Expr *) $4;
					w->location = @1;
					$$ = (Node *)w;
				}
		;

case_default:
			ELSE a_expr								{ $$ = $2; }
			| /*EMPTY*/								{ $$ = NULL; }
		;

case_arg:	a_expr									{ $$ = $1; }
			| /*EMPTY*/								{ $$ = NULL; }
		;

/*
 * columnref starts with relation_name not ColId, so that OLD and NEW
 * references can be accepted.	Note that when there are more than two
 * dotted names, the first name is not actually a relation name...
 */
columnref:	relation_name
				{
					$$ = makeColumnRef($1, NIL, @1);
				}
			| relation_name indirection
				{
					$$ = makeColumnRef($1, $2, @1);
				}
		;

indirection_el:
			'.' attr_name
				{
					$$ = (Node *) makeString($2);
				}
			| '.' '*'
				{
					$$ = (Node *) makeNode(A_Star);
				}
			| '[' a_expr ']'
				{
					A_Indices *ai = makeNode(A_Indices);
					ai->lidx = NULL;
					ai->uidx = $2;
					$$ = (Node *) ai;
				}
			| '[' a_expr ':' a_expr ']'
				{
					A_Indices *ai = makeNode(A_Indices);
					ai->lidx = $2;
					ai->uidx = $4;
					$$ = (Node *) ai;
				}
		;

indirection:
			indirection_el							{ $$ = list_make1($1); }
			| indirection indirection_el			{ $$ = lappend($1, $2); }
		;

opt_indirection:
			/*EMPTY*/								{ $$ = NIL; }
			| opt_indirection indirection_el		{ $$ = lappend($1, $2); }
		;

opt_asymmetric: ASYMMETRIC
			| /*EMPTY*/
		;

/*
 * The SQL spec defines "contextually typed value expressions" and
 * "contextually typed row value constructors", which for our purposes
 * are the same as "a_expr" and "row" except that DEFAULT can appear at
 * the top level.
 */

ctext_expr:
			a_expr					{ $$ = (Node *) $1; }
			| DEFAULT
				{
					SetToDefault *n = makeNode(SetToDefault);
					n->location = @1;
					$$ = (Node *) n;
				}
		;

ctext_expr_list:
			ctext_expr								{ $$ = list_make1($1); }
			| ctext_expr_list ',' ctext_expr		{ $$ = lappend($1, $3); }
		;

/*
 * We should allow ROW '(' ctext_expr_list ')' too, but that seems to require
 * making VALUES a fully reserved word, which will probably break more apps
 * than allowing the noise-word is worth.
 */
ctext_row: '(' ctext_expr_list ')'					{ $$ = $2; }
		;


/*****************************************************************************
 *
 *	target list for SELECT
 *
 *****************************************************************************/

target_list:
			target_el								{ $$ = list_make1($1); }
			| target_list ',' target_el				{ $$ = lappend($1, $3); }
		;

target_el:	a_expr AS ColLabel
				{
					$$ = makeNode(ResTarget);
					$$->name = $3;
					$$->indirection = NIL;
					$$->val = (Node *)$1;
					$$->location = @1;
				}
			/*
			 * We support omitting AS only for column labels that aren't
			 * any known keyword.  There is an ambiguity against postfix
			 * operators: is "a ! b" an infix expression, or a postfix
			 * expression and a column label?  We prefer to resolve this
			 * as an infix expression, which we accomplish by assigning
			 * IDENT a precedence higher than POSTFIXOP.
			 */
			| a_expr IDENT
				{
					$$ = makeNode(ResTarget);
					$$->name = $2;
					$$->indirection = NIL;
					$$->val = (Node *)$1;
					$$->location = @1;
				}
			| a_expr
				{
					$$ = makeNode(ResTarget);
					$$->name = NULL;
					$$->indirection = NIL;
					$$->val = (Node *)$1;
					$$->location = @1;
				}
			| '*'
				{
					ColumnRef *n = makeNode(ColumnRef);
					n->fields = list_make1(makeNode(A_Star));
					n->location = @1;

					$$ = makeNode(ResTarget);
					$$->name = NULL;
					$$->indirection = NIL;
					$$->val = (Node *)n;
					$$->location = @1;
				}
		;

/*****************************************************************************
 *
 * SE-PostgreSQL security items
 *
 *****************************************************************************/

OptSecurityItem:
			SecurityItem				{ $$ = $1; }
			| /* EMPTY */				{ $$ = NULL; }
			;

SecurityItem:
			IDENT opt_equal Sconst
				{
					if (!sepgsqlIsEnabled() ||
						strcmp("security_label", $1) != 0)
						yyerror("syntax error");

					$$ = makeDefElem($1, (Node *) makeString($3));
				}
			;

/*****************************************************************************
 *
 *	Names and constants
 *
 *****************************************************************************/

relation_name:
			SpecialRuleRelation						{ $$ = $1; }
			| ColId									{ $$ = $1; }
		;

qualified_name_list:
			qualified_name							{ $$ = list_make1($1); }
			| qualified_name_list ',' qualified_name { $$ = lappend($1, $3); }
		;

/*
 * The production for a qualified relation name has to exactly match the
 * production for a qualified func_name, because in a FROM clause we cannot
 * tell which we are parsing until we see what comes after it ('(' for a
 * func_name, something else for a relation). Therefore we allow 'indirection'
 * which may contain subscripts, and reject that case in the C code.
 */
qualified_name:
			relation_name
				{
					$$ = makeNode(RangeVar);
					$$->catalogname = NULL;
					$$->schemaname = NULL;
					$$->relname = $1;
					$$->location = @1;
				}
			| relation_name indirection
				{
					check_qualified_name($2);
					$$ = makeNode(RangeVar);
					switch (list_length($2))
					{
						case 1:
							$$->catalogname = NULL;
							$$->schemaname = $1;
							$$->relname = strVal(linitial($2));
							break;
						case 2:
							$$->catalogname = $1;
							$$->schemaname = strVal(linitial($2));
							$$->relname = strVal(lsecond($2));
							break;
						default:
							ereport(ERROR,
									(errcode(ERRCODE_SYNTAX_ERROR),
									 errmsg("improper qualified name (too many dotted names): %s",
											NameListToString(lcons(makeString($1), $2))),
									 scanner_errposition(@1)));
							break;
					}
					$$->location = @1;
				}
		;

name_list:	name
					{ $$ = list_make1(makeString($1)); }
			| name_list ',' name
					{ $$ = lappend($1, makeString($3)); }
		;


name:		ColId									{ $$ = $1; };

database_name:
			ColId									{ $$ = $1; };

access_method:
			ColId									{ $$ = $1; };

attr_name:	ColLabel								{ $$ = $1; };

index_name: ColId									{ $$ = $1; };

file_name:	Sconst									{ $$ = $1; };

/*
 * The production for a qualified func_name has to exactly match the
 * production for a qualified columnref, because we cannot tell which we
 * are parsing until we see what comes after it ('(' or Sconst for a func_name,
 * anything else for a columnref).  Therefore we allow 'indirection' which
 * may contain subscripts, and reject that case in the C code.  (If we
 * ever implement SQL99-like methods, such syntax may actually become legal!)
 */
func_name:	type_function_name
					{ $$ = list_make1(makeString($1)); }
			| relation_name indirection
					{ $$ = check_func_name(lcons(makeString($1), $2)); }
		;


/*
 * Constants
 */
AexprConst: Iconst
				{
					$$ = makeIntConst($1, @1);
				}
			| FCONST
				{
					$$ = makeFloatConst($1, @1);
				}
			| Sconst
				{
					$$ = makeStringConst($1, @1);
				}
			| BCONST
				{
					$$ = makeBitStringConst($1, @1);
				}
			| XCONST
				{
					/* This is a bit constant per SQL99:
					 * Without Feature F511, "BIT data type",
					 * a <general literal> shall not be a
					 * <bit string literal> or a <hex string literal>.
					 */
					$$ = makeBitStringConst($1, @1);
				}
			| func_name Sconst
				{
					/* generic type 'literal' syntax */
					TypeName *t = makeTypeNameFromNameList($1);
					t->location = @1;
					$$ = makeStringConstCast($2, @2, t);
				}
			| func_name '(' expr_list ')' Sconst
				{
					/* generic syntax with a type modifier */
					TypeName *t = makeTypeNameFromNameList($1);
					t->typmods = $3;
					t->location = @1;
					$$ = makeStringConstCast($5, @5, t);
				}
			| ConstTypename Sconst
				{
					$$ = makeStringConstCast($2, @2, $1);
				}
			| ConstInterval Sconst opt_interval
				{
					TypeName *t = $1;
					t->typmods = $3;
					$$ = makeStringConstCast($2, @2, t);
				}
			| ConstInterval '(' Iconst ')' Sconst opt_interval
				{
					TypeName *t = $1;
					if ($6 != NIL)
					{
						if (list_length($6) != 1)
							ereport(ERROR,
									(errcode(ERRCODE_SYNTAX_ERROR),
									 errmsg("interval precision specified twice"),
									 scanner_errposition(@1)));
						t->typmods = lappend($6, makeIntConst($3, @3));
					}
					else
						t->typmods = list_make2(makeIntConst(INTERVAL_FULL_RANGE, -1),
												makeIntConst($3, @3));
					$$ = makeStringConstCast($5, @5, t);
				}
			| TRUE_P
				{
					$$ = makeBoolAConst(TRUE, @1);
				}
			| FALSE_P
				{
					$$ = makeBoolAConst(FALSE, @1);
				}
			| NULL_P
				{
					$$ = makeNullAConst(@1);
				}
		;

Iconst:		ICONST									{ $$ = $1; };
Sconst:		SCONST									{ $$ = $1; };
RoleId:		ColId									{ $$ = $1; };

SignedIconst: Iconst								{ $$ = $1; }
			| '+' Iconst							{ $$ = + $2; }
			| '-' Iconst							{ $$ = - $2; }
		;

/*
 * Name classification hierarchy.
 *
 * IDENT is the lexeme returned by the lexer for identifiers that match
 * no known keyword.  In most cases, we can accept certain keywords as
 * names, not only IDENTs.	We prefer to accept as many such keywords
 * as possible to minimize the impact of "reserved words" on programmers.
 * So, we divide names into several possible classes.  The classification
 * is chosen in part to make keywords acceptable as names wherever possible.
 */

/* Column identifier --- names that can be column, table, etc names.
 */
ColId:		IDENT									{ $$ = $1; }
			| unreserved_keyword					{ $$ = pstrdup($1); }
			| col_name_keyword						{ $$ = pstrdup($1); }
		;

/* Type/function identifier --- names that can be type or function names.
 */
type_function_name:	IDENT							{ $$ = $1; }
			| unreserved_keyword					{ $$ = pstrdup($1); }
			| type_func_name_keyword				{ $$ = pstrdup($1); }
		;

/* Column label --- allowed labels in "AS" clauses.
 * This presently includes *all* Postgres keywords.
 */
ColLabel:	IDENT									{ $$ = $1; }
			| unreserved_keyword					{ $$ = pstrdup($1); }
			| col_name_keyword						{ $$ = pstrdup($1); }
			| type_func_name_keyword				{ $$ = pstrdup($1); }
			| reserved_keyword						{ $$ = pstrdup($1); }
		;


/*
 * Keyword category lists.  Generally, every keyword present in
 * the Postgres grammar should appear in exactly one of these lists.
 *
 * Put a new keyword into the first list that it can go into without causing
 * shift or reduce conflicts.  The earlier lists define "less reserved"
 * categories of keywords.
 *
 * Make sure that each keyword's category in keywords.c matches where
 * it is listed here.  (Someday we may be able to generate these lists and
 * keywords.c's table from a common master list.)
 */

/* "Unreserved" keywords --- available for use as any kind of name.
 */
unreserved_keyword:
			  ABORT_P
			| ABSOLUTE_P
			| ACCESS
			| ACTION
			| ADD_P
			| ADMIN
			| AFTER
			| AGGREGATE
			| ALSO
			| ALTER
			| ALWAYS
			| ASSERTION
			| ASSIGNMENT
			| AT
			| BACKWARD
			| BEFORE
			| BEGIN_P
			| BY
			| CACHE
			| CALLED
			| CASCADE
			| CASCADED
			| CATALOG_P
			| CHAIN
			| CHARACTERISTICS
			| CHECKPOINT
			| CLASS
			| CLOSE
			| CLUSTER
			| COMMENT
			| COMMIT
			| COMMITTED
			| CONCURRENTLY
			| CONFIGURATION
			| CONNECTION
			| CONSTRAINTS
			| CONTENT_P
			| CONTINUE_P
			| CONVERSION_P
			| COPY
			| COST
			| CREATEDB
			| CREATEROLE
			| CREATEUSER
			| CSV
			| CTYPE
			| CURRENT_P
			| CURSOR
			| CYCLE
			| DATA_P
			| DATABASE
			| DAY_P
			| DEALLOCATE
			| DECLARE
			| DEFAULTS
			| DEFERRED
			| DEFINER
			| DELETE_P
			| DELIMITER
			| DELIMITERS
			| DICTIONARY
			| DISABLE_P
			| DISCARD
			| DOCUMENT_P
			| DOMAIN_P
			| DOUBLE_P
			| DROP
			| EACH
			| ENABLE_P
			| ENCODING
			| ENCRYPTED
			| ENUM_P
			| ESCAPE
			| EXCLUDING
			| EXCLUSIVE
			| EXECUTE
			| EXPLAIN
			| EXTERNAL
			| FAMILY
			| FIRST_P
			| FOLLOWING
			| FORCE
			| FORWARD
			| FUNCTION
			| GLOBAL
			| GRANTED
			| HANDLER
			| HEADER_P
			| HOLD
			| HOUR_P
			| IDENTITY_P
			| IF_P
			| IMMEDIATE
			| IMMUTABLE
			| IMPLICIT_P
			| INCLUDING
			| INCREMENT
			| INDEX
			| INDEXES
			| INHERIT
			| INHERITS
			| INPUT_P
			| INSENSITIVE
			| INSERT
			| INSTEAD
			| INVOKER
			| ISOLATION
			| KEY
			| LANCOMPILER
			| LANGUAGE
			| LARGE_P
			| LAST_P
			| LEVEL
			| LISTEN
			| LOAD
			| LOCAL
			| LOCATION
			| LOCK_P
			| LOGIN_P
			| MAPPING
			| MATCH
			| MAXVALUE
			| MINUTE_P
			| MINVALUE
			| MODE
			| MONTH_P
			| MOVE
			| NAME_P
			| NAMES
			| NEXT
			| NO
			| NOCREATEDB
			| NOCREATEROLE
			| NOCREATEUSER
			| NOINHERIT
			| NOLOGIN_P
			| NOSUPERUSER
			| NOTHING
			| NOTIFY
			| NOWAIT
			| NULLS_P
			| OBJECT_P
			| OF
			| OIDS
			| OPERATOR
			| OPTION
			| OPTIONS
			| OWNED
			| OWNER
			| PARSER
			| PARTIAL
			| PARTITION
			| PASSWORD
			| PLANS
			| PRECEDING
			| PREPARE
			| PREPARED
			| PRESERVE
			| PRIOR
			| PRIVILEGES
			| PROCEDURAL
			| PROCEDURE
			| QUOTE
			| RANGE
			| READ
			| REASSIGN
			| RECHECK
			| RECURSIVE
			| REINDEX
			| RELATIVE_P
			| RELEASE
			| RENAME
			| REPEATABLE
			| REPLACE
			| REPLICA
			| RESET
			| RESTART
			| RESTRICT
			| RETURNS
			| REVOKE
			| ROLE
			| ROLLBACK
			| ROWS
			| RULE
			| SAVEPOINT
			| SERVER
			| SCHEMA
			| SCROLL
			| SEARCH
			| SECOND_P
			| SECURITY
			| SEQUENCE
			| SERIALIZABLE
			| SESSION
			| SET
			| SHARE
			| SHOW
			| SIMPLE
			| STABLE
			| STANDALONE_P
			| START
			| STATEMENT
			| STATISTICS
			| STDIN
			| STDOUT
			| STORAGE
			| STRICT_P
			| STRIP_P
			| SUPERUSER_P
			| SYSID
			| SYSTEM_P
			| TABLESPACE
			| TEMP
			| TEMPLATE
			| TEMPORARY
			| TEXT_P
			| TRANSACTION
			| TRIGGER
			| TRUNCATE
			| TRUSTED
			| TYPE_P
			| UNBOUNDED
			| UNCOMMITTED
			| UNENCRYPTED
			| UNKNOWN
			| UNLISTEN
			| UNTIL
			| UPDATE
			| VACUUM
			| VALID
			| VALIDATOR
			| VALUE_P
			| VARYING
			| VERSION_P
			| VIEW
			| VOLATILE
			| WHITESPACE_P
			| WITHOUT
			| WORK
			| WRAPPER
			| WRITE
			| XML_P
			| YEAR_P
			| YES_P
			| ZONE
		;

/* Column identifier --- keywords that can be column, table, etc names.
 *
 * Many of these keywords will in fact be recognized as type or function
 * names too; but they have special productions for the purpose, and so
 * can't be treated as "generic" type or function names.
 *
 * The type names appearing here are not usable as function names
 * because they can be followed by '(' in typename productions, which
 * looks too much like a function call for an LR(1) parser.
 */
col_name_keyword:
			  BIGINT
			| BIT
			| BOOLEAN_P
			| CHAR_P
			| CHARACTER
			| COALESCE
			| DEC
			| DECIMAL_P
			| EXISTS
			| EXTRACT
			| FLOAT_P
			| GREATEST
			| INOUT
			| INT_P
			| INTEGER
			| INTERVAL
			| LEAST
			| NATIONAL
			| NCHAR
			| NONE
			| NULLIF
			| NUMERIC
			| OUT_P
			| OVERLAY
			| POSITION
			| PRECISION
			| REAL
			| ROW
			| SETOF
			| SMALLINT
			| SUBSTRING
			| TIME
			| TIMESTAMP
			| TREAT
			| TRIM
			| VALUES
			| VARCHAR
			| XMLATTRIBUTES
			| XMLCONCAT
			| XMLELEMENT
			| XMLFOREST
			| XMLPARSE
			| XMLPI
			| XMLROOT
			| XMLSERIALIZE
		;

/* Type/function identifier --- keywords that can be type or function names.
 *
 * Most of these are keywords that are used as operators in expressions;
 * in general such keywords can't be column names because they would be
 * ambiguous with variables, but they are unambiguous as function identifiers.
 *
 * Do not include POSITION, SUBSTRING, etc here since they have explicit
 * productions in a_expr to support the goofy SQL9x argument syntax.
 * - thomas 2000-11-28
 */
type_func_name_keyword:
			  AUTHORIZATION
			| BETWEEN
			| BINARY
			| CROSS
			| CURRENT_SCHEMA
			| FREEZE
			| FULL
			| ILIKE
			| INNER_P
			| IS
			| ISNULL
			| JOIN
			| LEFT
			| LIKE
			| NATURAL
			| NOTNULL
			| OUTER_P
			| OVER
			| OVERLAPS
			| RIGHT
			| SIMILAR
			| VERBOSE
		;

/* Reserved keyword --- these keywords are usable only as a ColLabel.
 *
 * Keywords appear here if they could not be distinguished from variable,
 * type, or function names in some contexts.  Don't put things here unless
 * forced to.
 */
reserved_keyword:
			  ALL
			| ANALYSE
			| ANALYZE
			| AND
			| ANY
			| ARRAY
			| AS
			| ASC
			| ASYMMETRIC
			| BOTH
			| CASE
			| CAST
			| CHECK
			| COLLATE
			| COLUMN
			| CONSTRAINT
			| CREATE
			| CURRENT_CATALOG
			| CURRENT_DATE
			| CURRENT_ROLE
			| CURRENT_TIME
			| CURRENT_TIMESTAMP
			| CURRENT_USER
			| DEFAULT
			| DEFERRABLE
			| DESC
			| DISTINCT
			| DO
			| ELSE
			| END_P
			| EXCEPT
			| FALSE_P
			| FETCH
			| FOR
			| FOREIGN
			| FROM
			| GRANT
			| GROUP_P
			| HAVING
			| IN_P
			| INITIALLY
			| INTERSECT
			| INTO
			| LEADING
			| LIMIT
			| LOCALTIME
			| LOCALTIMESTAMP
			| NEW
			| NOT
			| NULL_P
			| OFF
			| OFFSET
			| OLD
			| ON
			| ONLY
			| OR
			| ORDER
			| PLACING
			| PRIMARY
			| REFERENCES
			| RETURNING
			| SELECT
			| SESSION_USER
			| SOME
			| SYMMETRIC
			| TABLE
			| THEN
			| TO
			| TRAILING
			| TRUE_P
			| UNION
			| UNIQUE
			| USER
			| USING
			| VARIADIC
			| WHEN
			| WHERE
			| WINDOW
			| WITH
		;


SpecialRuleRelation:
			OLD
				{
					if (QueryIsRule)
						$$ = "*OLD*";
					else
						ereport(ERROR,
								(errcode(ERRCODE_SYNTAX_ERROR),
								 errmsg("OLD used in query that is not in a rule"),
								 scanner_errposition(@1)));
				}
			| NEW
				{
					if (QueryIsRule)
						$$ = "*NEW*";
					else
						ereport(ERROR,
								(errcode(ERRCODE_SYNTAX_ERROR),
								 errmsg("NEW used in query that is not in a rule"),
								 scanner_errposition(@1)));
				}
		;

%%

static Node *
makeColumnRef(char *colname, List *indirection, int location)
{
	/*
	 * Generate a ColumnRef node, with an A_Indirection node added if there
	 * is any subscripting in the specified indirection list.  However,
	 * any field selection at the start of the indirection list must be
	 * transposed into the "fields" part of the ColumnRef node.
	 */
	ColumnRef  *c = makeNode(ColumnRef);
	int		nfields = 0;
	ListCell *l;

	c->location = location;
	foreach(l, indirection)
	{
		if (IsA(lfirst(l), A_Indices))
		{
			A_Indirection *i = makeNode(A_Indirection);

			if (nfields == 0)
			{
				/* easy case - all indirection goes to A_Indirection */
				c->fields = list_make1(makeString(colname));
				i->indirection = check_indirection(indirection);
			}
			else
			{
				/* got to split the list in two */
				i->indirection = check_indirection(list_copy_tail(indirection,
																  nfields));
				indirection = list_truncate(indirection, nfields);
				c->fields = lcons(makeString(colname), indirection);
			}
			i->arg = (Node *) c;
			return (Node *) i;
		}
		else if (IsA(lfirst(l), A_Star))
		{
			/* We only allow '*' at the end of a ColumnRef */
			if (lnext(l) != NULL)
				yyerror("improper use of \"*\"");
		}
		nfields++;
	}
	/* No subscripting, so all indirection gets added to field list */
	c->fields = lcons(makeString(colname), indirection);
	return (Node *) c;
}

static Node *
makeTypeCast(Node *arg, TypeName *typename, int location)
{
	TypeCast *n = makeNode(TypeCast);
	n->arg = arg;
	n->typename = typename;
	n->location = location;
	return (Node *) n;
}

static Node *
makeStringConst(char *str, int location)
{
	A_Const *n = makeNode(A_Const);

	n->val.type = T_String;
	n->val.val.str = str;
	n->location = location;

	return (Node *)n;
}

static Node *
makeStringConstCast(char *str, int location, TypeName *typename)
{
	Node *s = makeStringConst(str, location);

	return makeTypeCast(s, typename, -1);
}

static Node *
makeIntConst(int val, int location)
{
	A_Const *n = makeNode(A_Const);

	n->val.type = T_Integer;
	n->val.val.ival = val;
	n->location = location;

	return (Node *)n;
}

static Node *
makeFloatConst(char *str, int location)
{
	A_Const *n = makeNode(A_Const);

	n->val.type = T_Float;
	n->val.val.str = str;
	n->location = location;

	return (Node *)n;
}

static Node *
makeBitStringConst(char *str, int location)
{
	A_Const *n = makeNode(A_Const);

	n->val.type = T_BitString;
	n->val.val.str = str;
	n->location = location;

	return (Node *)n;
}

static Node *
makeNullAConst(int location)
{
	A_Const *n = makeNode(A_Const);

	n->val.type = T_Null;
	n->location = location;

	return (Node *)n;
}

static Node *
makeAConst(Value *v, int location)
{
	Node *n;

	switch (v->type)
	{
		case T_Float:
			n = makeFloatConst(v->val.str, location);
			break;

		case T_Integer:
			n = makeIntConst(v->val.ival, location);
			break;

		case T_String:
		default:
			n = makeStringConst(v->val.str, location);
			break;
	}

	return n;
}

/* makeBoolAConst()
 * Create an A_Const string node and put it inside a boolean cast.
 */
static Node *
makeBoolAConst(bool state, int location)
{
	A_Const *n = makeNode(A_Const);

	n->val.type = T_String;
	n->val.val.str = (state ? "t" : "f");
	n->location = location;

	return makeTypeCast((Node *)n, SystemTypeName("bool"), -1);
}

/* makeOverlaps()
 * Create and populate a FuncCall node to support the OVERLAPS operator.
 */
static FuncCall *
makeOverlaps(List *largs, List *rargs, int location)
{
	FuncCall *n = makeNode(FuncCall);

	n->funcname = SystemFuncName("overlaps");
	if (list_length(largs) == 1)
		largs = lappend(largs, largs);
	else if (list_length(largs) != 2)
		ereport(ERROR,
				(errcode(ERRCODE_SYNTAX_ERROR),
				 errmsg("wrong number of parameters on left side of OVERLAPS expression"),
				 scanner_errposition(location)));
	if (list_length(rargs) == 1)
		rargs = lappend(rargs, rargs);
	else if (list_length(rargs) != 2)
		ereport(ERROR,
				(errcode(ERRCODE_SYNTAX_ERROR),
				 errmsg("wrong number of parameters on right side of OVERLAPS expression"),
				 scanner_errposition(location)));
	n->args = list_concat(largs, rargs);
	n->agg_star = FALSE;
	n->agg_distinct = FALSE;
	n->func_variadic = FALSE;
	n->over = NULL;
	n->location = location;
	return n;
}

/* check_qualified_name --- check the result of qualified_name production
 *
 * It's easiest to let the grammar production for qualified_name allow
 * subscripts and '*', which we then must reject here.
 */
static void
check_qualified_name(List *names)
{
	ListCell   *i;

	foreach(i, names)
	{
		if (!IsA(lfirst(i), String))
			yyerror("syntax error");
	}
}

/* check_func_name --- check the result of func_name production
 *
 * It's easiest to let the grammar production for func_name allow subscripts
 * and '*', which we then must reject here.
 */
static List *
check_func_name(List *names)
{
	ListCell   *i;

	foreach(i, names)
	{
		if (!IsA(lfirst(i), String))
			yyerror("syntax error");
	}
	return names;
}

/* check_indirection --- check the result of indirection production
 *
 * We only allow '*' at the end of the list, but it's hard to enforce that
 * in the grammar, so do it here.
 */
static List *
check_indirection(List *indirection)
{
	ListCell *l;

	foreach(l, indirection)
	{
		if (IsA(lfirst(l), A_Star))
		{
			if (lnext(l) != NULL)
				yyerror("improper use of \"*\"");
		}
	}
	return indirection;
}

/* extractArgTypes()
 * Given a list of FunctionParameter nodes, extract a list of just the
 * argument types (TypeNames) for input parameters only.  This is what
 * is needed to look up an existing function, which is what is wanted by
 * the productions that use this call.
 */
static List *
extractArgTypes(List *parameters)
{
	List	   *result = NIL;
	ListCell   *i;

	foreach(i, parameters)
	{
		FunctionParameter *p = (FunctionParameter *) lfirst(i);

		if (p->mode != FUNC_PARAM_OUT && p->mode != FUNC_PARAM_TABLE)
			result = lappend(result, p->argType);
	}
	return result;
}

/* findLeftmostSelect()
 * Find the leftmost component SelectStmt in a set-operation parsetree.
 */
static SelectStmt *
findLeftmostSelect(SelectStmt *node)
{
	while (node && node->op != SETOP_NONE)
		node = node->larg;
	Assert(node && IsA(node, SelectStmt) && node->larg == NULL);
	return node;
}

/* insertSelectOptions()
 * Insert ORDER BY, etc into an already-constructed SelectStmt.
 *
 * This routine is just to avoid duplicating code in SelectStmt productions.
 */
static void
insertSelectOptions(SelectStmt *stmt,
					List *sortClause, List *lockingClause,
					Node *limitOffset, Node *limitCount,
					WithClause *withClause)
{
	Assert(IsA(stmt, SelectStmt));

	/*
	 * Tests here are to reject constructs like
	 *	(SELECT foo ORDER BY bar) ORDER BY baz
	 */
	if (sortClause)
	{
		if (stmt->sortClause)
			ereport(ERROR,
					(errcode(ERRCODE_SYNTAX_ERROR),
					 errmsg("multiple ORDER BY clauses not allowed"),
					 scanner_errposition(exprLocation((Node *) sortClause))));
		stmt->sortClause = sortClause;
	}
	/* We can handle multiple locking clauses, though */
	stmt->lockingClause = list_concat(stmt->lockingClause, lockingClause);
	if (limitOffset)
	{
		if (stmt->limitOffset)
			ereport(ERROR,
					(errcode(ERRCODE_SYNTAX_ERROR),
					 errmsg("multiple OFFSET clauses not allowed"),
					 scanner_errposition(exprLocation(limitOffset))));
		stmt->limitOffset = limitOffset;
	}
	if (limitCount)
	{
		if (stmt->limitCount)
			ereport(ERROR,
					(errcode(ERRCODE_SYNTAX_ERROR),
					 errmsg("multiple LIMIT clauses not allowed"),
					 scanner_errposition(exprLocation(limitCount))));
		stmt->limitCount = limitCount;
	}
	if (withClause)
	{
		if (stmt->withClause)
			ereport(ERROR,
					(errcode(ERRCODE_SYNTAX_ERROR),
					 errmsg("multiple WITH clauses not allowed"),
					 scanner_errposition(exprLocation((Node *) withClause))));
		stmt->withClause = withClause;
	}
}

static Node *
makeSetOp(SetOperation op, bool all, Node *larg, Node *rarg)
{
	SelectStmt *n = makeNode(SelectStmt);

	n->op = op;
	n->all = all;
	n->larg = (SelectStmt *) larg;
	n->rarg = (SelectStmt *) rarg;
	return (Node *) n;
}

/* SystemFuncName()
 * Build a properly-qualified reference to a built-in function.
 */
List *
SystemFuncName(char *name)
{
	return list_make2(makeString("pg_catalog"), makeString(name));
}

/* SystemTypeName()
 * Build a properly-qualified reference to a built-in type.
 *
 * typmod is defaulted, but may be changed afterwards by caller.
 * Likewise for the location.
 */
TypeName *
SystemTypeName(char *name)
{
	return makeTypeNameFromNameList(list_make2(makeString("pg_catalog"),
											   makeString(name)));
}

/* doNegate()
 * Handle negation of a numeric constant.
 *
 * Formerly, we did this here because the optimizer couldn't cope with
 * indexquals that looked like "var = -4" --- it wants "var = const"
 * and a unary minus operator applied to a constant didn't qualify.
 * As of Postgres 7.0, that problem doesn't exist anymore because there
 * is a constant-subexpression simplifier in the optimizer.  However,
 * there's still a good reason for doing this here, which is that we can
 * postpone committing to a particular internal representation for simple
 * negative constants.	It's better to leave "-123.456" in string form
 * until we know what the desired type is.
 */
static Node *
doNegate(Node *n, int location)
{
	if (IsA(n, A_Const))
	{
		A_Const *con = (A_Const *)n;

		/* report the constant's location as that of the '-' sign */
		con->location = location;

		if (con->val.type == T_Integer)
		{
			con->val.val.ival = -con->val.val.ival;
			return n;
		}
		if (con->val.type == T_Float)
		{
			doNegateFloat(&con->val);
			return n;
		}
	}

	return (Node *) makeSimpleA_Expr(AEXPR_OP, "-", NULL, n, location);
}

static void
doNegateFloat(Value *v)
{
	char   *oldval = v->val.str;

	Assert(IsA(v, Float));
	if (*oldval == '+')
		oldval++;
	if (*oldval == '-')
		v->val.str = oldval+1;	/* just strip the '-' */
	else
	{
		char   *newval = (char *) palloc(strlen(oldval) + 2);

		*newval = '-';
		strcpy(newval+1, oldval);
		v->val.str = newval;
	}
}

static Node *
makeAArrayExpr(List *elements, int location)
{
	A_ArrayExpr *n = makeNode(A_ArrayExpr);

	n->elements = elements;
	n->location = location;
	return (Node *) n;
}

static Node *
makeXmlExpr(XmlExprOp op, char *name, List *named_args, List *args,
			int location)
{
	XmlExpr    *x = makeNode(XmlExpr);

	x->op = op;
	x->name = name;
	/*
	 * named_args is a list of ResTarget; it'll be split apart into separate
	 * expression and name lists in transformXmlExpr().
	 */
	x->named_args = named_args;
	x->arg_names = NIL;
	x->args = args;
	/* xmloption, if relevant, must be filled in by caller */
	/* type and typmod will be filled in during parse analysis */
	x->location = location;
	return (Node *) x;
}

/* parser_init()
 * Initialize to parse one query string
 */
void
parser_init(void)
{
	QueryIsRule = FALSE;
}

/*
 * Merge the input and output parameters of a table function.
 */
static List *
mergeTableFuncParameters(List *func_args, List *columns)
{
	ListCell   *lc;

	/* Explicit OUT and INOUT parameters shouldn't be used in this syntax */
	foreach(lc, func_args)
	{
		FunctionParameter *p = (FunctionParameter *) lfirst(lc);

		if (p->mode != FUNC_PARAM_IN && p->mode != FUNC_PARAM_VARIADIC)
			ereport(ERROR,
					(errcode(ERRCODE_SYNTAX_ERROR),
					 errmsg("OUT and INOUT arguments aren't allowed in TABLE functions")));
	}

	return list_concat(func_args, columns);
}

/*
 * Determine return type of a TABLE function.  A single result column
 * returns setof that column's type; otherwise return setof record.
 */
static TypeName *
TableFuncTypeName(List *columns)
{
	TypeName *result;

	if (list_length(columns) == 1)
	{
		FunctionParameter *p = (FunctionParameter *) linitial(columns);

		result = (TypeName *) copyObject(p->argType);
	}
	else
		result = SystemTypeName("record");

	result->setof = true;

	return result;
}

/*
 * Must undefine base_yylex before including scan.c, since we want it
 * to create the function base_yylex not filtered_base_yylex.
 */
#undef base_yylex

#include "scan.c"