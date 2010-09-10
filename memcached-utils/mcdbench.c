/*
 * mcdbench.c
 *
 * a benchmark tool of memcached
 *
 */
typedef struct mcdbench_t
{
	pthread_t		thread;
	memcached_st   *st;
	uint32_t		num_gets;
	uint32_t		num_stores;
	uint32_t		num_append;
	uint32_t		num_cas;
	uint64_t		total_send;
	uint64_t		total_recv;
};

static bool		use_binary = false;
static int		num_threads = 1;
static int		value_size = 256;
static int		time_to_run = 30;
static bool		worker_exit = false;






static void *exec_simple_bench(void *args)
{}





static void
parse_conn_string(char *conn, in_port_t *port, uint32_t *weight)
{
	char   *pos;
	char   *cur;

	if (weight != NULL)
	{
		*weight = 100;	/* default */

		if ((pos = strrchr(conn, '@')) != NULL)
		{
			for (cur = pos + 1; isdigit(*cur); cur++);
			if (*cur == '\0')
			{
				*weight = atoi(pos+1);
				*pos = '\0';
			}
		}
	}

	if (port != NULL)
	{
		*port = 11211;	/* default */

		if ((pos = strrchr(conn, ':')) != NULL)
		{
			for (cur = pos + 1; isdigit(*cur); cur++);
			if (*cur == '\0')
			{
				*port = atoi(pos+1);
				*pos = '\0';
			}
		}
	}
}

static void usage(void)
{
	fprintf(stderr, "usage: %s [options]\n"
			"  -b          : use binary protocol\n"
			"  -c <conn>   : connection string\n"
			"                [tcp://]<host>[:<port>[@<weight>]]\n"
			"                udp://<host>[:<port>[@<weight>]]\n"
			"                unix://<path>[@<weight>\n"
			"  -n <num>    : number of threads\n"
			"  -p <policy> : test policy (default: simple)\n"
			"  -s <scale>  : average size of values (default: 256)\n"
			"  -t <time>   : time to run benchmark (default: 30)\n"
			"  -h          : print this message\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	mcdbench_t		   *bench;
	memcached_st	   *mcd;
	memcached_return_t	rc;
	in_port_t			port;
	uint32_t			weight;
	int					code;
	int					num_conns = 0;
	void *			  (*worker_fn)(void *) = exec_simple_bench;

	mcd = memcached_create(NULL);
	if (!mcd)
	{
		fprintf(stderr, "memcached_create() failed: %s\n", strerror(errno));
		return 1;
	}

	while ((code = getopt(argc, argv, "bc:n:p:s:t:hv")) >= 0)
	{
		switch (code)
		{
			case 'b':
				use_binary = true;
				break;

			case 'c':
				if (strncmp(optarg, "tcp://", 6) == 0)
				{
					parse_conn_string(optarg, &port, &weight);
					rc = memcached_server_add_with_weight(mcd, optarg + 6,
														  port, weight);
					if (rc != MEMCACHED_SUCCESS)
					{
						fprintf(stderr, "failed to add tcp://%s:%u@%u\n",
								optarg + 6, port, weight);
						return 1;
					}
				}
				else if (strncmp(optarg, "udp://", 6) == 0)
				{
					parse_conn_string(optarg, &port, &weight);
                    rc = memcached_server_add_udp_with_weight(mcd, optarg + 6,
															  port, weight);
					if (rc != MEMCACHED_SUCCESS)
					{
						fprintf(stderr, "failed to add udp://%s:%u@%u\n",
								optarg + 6, port, weight);
						return 1;
					}
				}
				else if (strncmp(optarg, "unix://", 7) == 0)
				{
					parse_conn_string(optarg, NULL, &weight);
					rc = memcached_server_add_unix_socket_with_weight(mcd,
																	  optarg+7,
																	  weight);
					if (rc != MEMCACHED_SUCCESS)
					{
						fprintf(stderr, "failed to add unix://%s@%u\n",
								optarg+7, weight);
						return 1;
					}
				}
				else
				{
					fprintf(stderr, "invalid connection string: %s\n", optarg);
					return 1;
				}
				break;

			case 'n':
				num_threads = atoi(optarg);
				if (num_threads < 1)
					usage();
				break;

			case 'p':
				if (strcmp(optarg, "simple") == 0)
					worker_fn = exec_simple_bench;
				else
				{
					fprintf(stderr, "unknown test policy: %s\n", optarg);
					return 1;
				}
				break;

			case 's':
				value_size = atoi(optarg);
				if (value_size < 16)
					value_size = 16;
				break;

			case 't':
				time_to_run = atoi(optarg);
				if (time_to_run < 5)
					time_to_run = 5;
				break;

			case 'h':
			default:
				usage();
				break;
		}
	}


}
