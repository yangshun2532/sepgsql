/* -------------------------------------------------------
 * pgcheck -- a SE-PostgreSQL regression test utility
 *
 * copyright: 2007 - KaiGai Kohei <kaigai@kaigai.gr.jp>
 * ------------------------------------------------------- */
#include <libpq-fe.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static void usage(int exitcode) {
	fputs("pgcheck -- a support utility for SE-PostgreSQL regression test\n"
		  "\n"
		  "Usage: pgcheck [OPTIONS] ... [QUERIES] ...\n"
		  "\n"
		  "Connect options:\n"
		  "  -d DBNAME     specify database name to connect to \n"
		  "  -h HOSTNAME   database server host or socket directory \n"
		  "  -p PORT       database server port \n"
		  "  -U NAME       database user name \n"
		  "  -P PASSWORD   password to connect \n"
		  "\n"
		  "Output options:\n"
		  "  "
		  "  --disable-caption   disable to print caption for each column\n"
		  "  --disable-ntuples   disable to print @NTUPLES: <number> line \n"
		  "  --disable-nfields   disable to print @NFIELDS: <number> line \n"
		  "  --disable-error     disable to print @ERROR: <message> line \n"
		  "  --disable-notice    disable to print @NOTICE: <message> line \n",
		  stderr);

	exit(exitcode);
}

static char *opt_dbname = NULL;
static char *opt_hostname = NULL;
static char *opt_username = NULL;
static char *opt_password = NULL;
static int opt_portno = -1;
static int opt_enable_caption = 1;
static int opt_enable_ntuples = 1;
static int opt_enable_nfields = 1;
static int opt_enable_error = 1;
static int opt_enable_notice = 1;

static struct option pgcheck_long_options[] = {
	{ "disable-caption", no_argument, &opt_enable_caption, 0 },
	{ "disable-ntuples", no_argument, &opt_enable_ntuples, 0 },
	{ "disable-nfields", no_argument, &opt_enable_nfields, 0 },
	{ "disable-error",   no_argument, &opt_enable_error,   0 },
	{ "disable-notice",  no_argument, &opt_enable_notice,  0 },
	{ NULL, no_argument, NULL, 0 },
};

/*
 * Save/Print NOTICE Message
 */
struct messageChain {
	struct messageChain *next, *prev;
	char message[1];
};
struct messageChain notice_list = { .next = &notice_list, .prev = &notice_list };

static void saveNotice(void *arg, const char *message) {
	struct messageChain *tail, *cur, *head = &notice_list;
	int len;

	printf("%s called!\n", __FUNCTION__);

	if (!opt_enable_notice)
		return;		/* do nothing */

	len = sizeof(struct messageChain) + strlen(message);
	cur = malloc(len);
	if (!cur) {
		fprintf(stderr, "malloc(%u) returns NULL (%s)\n",
				len, strerror(errno));
		return;
	}

	strcpy(cur->message, message);

	tail = head->prev;
	cur->prev = tail;
	tail->next = cur;
	cur->next = head;
	head->prev = cur;
}

static printNotice(PGconn *pgcon, PGresult *res) {
	struct messageChain *next, *cur, *head = &notice_list;

	if (opt_enable_notice) {
		for (cur=head->next; cur != head; cur = next) {
			next = cur->next;
			printf("@NOTICE: %s\n", cur->message);
			free(cur);
		}
	}
	/* cleanup list */
	notice_list.prev = notice_list.next = &notice_list;
}

static PGresult *execQuery(PGconn *pgcon, const char *query_str) {
	printf("do: %s\n", query_str);
	return NULL;
}

int main(int argc, char *argv[]) {
	PGconn *pgcon;
	char buffer[1024];
	int offset = 0;
	int error = 0;
	int i, c;

	/* parse option */
	while ((c = getopt_long(argc, argv, "d:h:p:u:P:h",
							pgcheck_long_options, NULL)) > 0) {
		switch (c) {
		case 'd':
			if (opt_dbname)
				goto duplicate_option;
			opt_dbname = optarg;
			break;
		case 'h':
			if (opt_hostname)
				goto duplicate_option;
			opt_hostname = optarg;
			break;
		case 'p':
			if (opt_portno > 0)
				goto duplicate_option;
			opt_portno = atoi(optarg);
			break;
		case 'u':
			if (opt_username)
				goto duplicate_option;
			opt_username = optarg;
			break;
		case 'P':
			if (opt_password)
				goto duplicate_option;
			opt_password = optarg;
			break;
		default:
			fprintf(stderr, "unknown option -%c\n", c);
		case '?':
			usage(c=='?' ? 0 : 1);
			break;
		}


	}
	if (!argv[optind]) {
		fprintf(stderr, "no queries are specified\n");
		usage(1);
	}
	close(fileno(stderr));
	open("/dev/null", O_WRONLY);

	/* connect to database */
	buffer[offset] = '\0';
	if (opt_dbname)
		offset += snprintf(buffer + offset, sizeof(buffer) - offset,
						   " dbname=%s", opt_dbname);
	if (opt_hostname)
		offset += snprintf(buffer + offset, sizeof(buffer) - offset,
						   " host=%s", opt_hostname);
	if (opt_portno > 0)
		offset += snprintf(buffer + offset, sizeof(buffer) - offset,
						   " port=%d", opt_portno);
	if (opt_username)
		offset += snprintf(buffer + offset, sizeof(buffer) - offset,
						   " user=%s", opt_username);
	if (opt_password)
		offset += snprintf(buffer + offset, sizeof(buffer) - offset,
						   " password=%s", opt_password);
	pgcon = PQconnectdb(buffer);
	if (PQstatus(pgcon) != CONNECTION_OK) {
		fprintf(stderr, "could not connect PostgreSQL with '%s'\n", buffer);
		PQfinish(pgcon);
		return 1;
	}
	/* prepare to query */
	PQsetNoticeProcessor(pgcon, saveNotice, NULL);

	/* execute queries */
	for (i=optind; argv[i]; i++) {
		PGresult *res = execQuery(pgcon, argv[i]);

		if (opt_enable_notice)
			printNotice(pgcon, res);
	}
	
	/* close connection */
	PQfinish(pgcon);
	
	return 0;
duplicate_option:
	fprintf(stderr, "option -%c was found twice or more\n", c);
	usage(1);
	return 1;
}
