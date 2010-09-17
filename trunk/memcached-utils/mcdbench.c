/*
 * mcdbench.c
 *
 * a benchmark tool of memcached
 *
 */
#include <errno.h>
#include <libmemcached/memcached.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct
{
	pthread_t		thread;
	memcached_st   *mcd;
	int				scale;
	int				duration;
	uint32_t		num_get;
	uint32_t		num_store;
	uint32_t		num_append;
	uint32_t		num_cas;
	uint32_t		num_remove;
	uint64_t		total_send;
	uint64_t		total_recv;
} mcdbench_t;

static bool		worker_exit = false;

static void *exec_simple_bench(void *args)
{
	mcdbench_t		   *bench = args;
	unsigned int		seed = (int)bench->thread;
	char			   *value;
	char				kbuf[256];
	char				vbuf[128 * 1024];
	int					count = 0;

	while (!worker_exit)
	{
		memcached_return_t	error;
		uint32_t			flags;
		int					key;
		size_t				klen;
		size_t				vlen;

		key = ((uint64_t)bench->scale *
			   (uint64_t)bench->duration *
			   (uint64_t)rand_r(&seed)) / RAND_MAX;
		klen = sprintf(kbuf, "simple_bench_%08d", key);

		value = memcached_get(bench->mcd, kbuf, klen, &vlen, &flags, &error);
		if (!value)
		{
			unsigned int	vseed = (unsigned int)key;
			size_t			pos = 0;
			int				l;
#if 0
			if (error != MEMCACHED_NOTFOUND)
			{
				fprintf(stderr, "GET: key=%s error=%s value=%p\n",
						kbuf, memcached_strerror(bench->mcd, error), value);
				sleep(1);
				continue;
			}
#endif
			if (count++ > 100)
				continue;

			l = rand_r(&vseed);
			vlen = (bench->scale * (((l>>2) & 0x0f) *
									((l>>7) & 0x0f) *
									((l>>12) & 0x0f)) / 100) & ~7;
			if (vlen > sizeof(vbuf))
				vlen = sizeof(vbuf);

			while (pos < vlen)
				pos += sprintf(vbuf + pos, "%08x", rand_r(&vseed));

			error = memcached_set(bench->mcd, kbuf, klen, vbuf, vlen, 0, 0);
			if (error != MEMCACHED_SUCCESS)
			{
				fprintf(stderr, "SET: key=%s error=%s\n",
                        kbuf, memcached_strerror(bench->mcd, error));
				continue;
			}
			bench->num_store++;
			bench->total_send += vlen;
		}
		else
		{
			bench->num_get++;
			bench->total_recv += vlen;
			free(value);
		}
	}
	return NULL;
}

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
			"  -s <scale>  : scaling factor (default: 100)\n"
			"  -t <time>   : time to run benchmark (default: 30)\n"
			"  -h          : print this message\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	mcdbench_t		   *workers, stat;
	memcached_st	   *mcd;
	memcached_return_t	rc;
	int					code;
	int					index;
	int					num_conns = 0;
	int					num_threads = 1;
	int					duration = 10;
	int					scale = 100;
	void *			  (*worker_fn)(void *) = exec_simple_bench;
	uint32_t			total_cmds;
	struct timeval		tv1, tv2;
	double				interval;

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
				rc = memcached_behavior_set(mcd, MEMCACHED_BEHAVIOR_BINARY_PROTOCOL, 1);
				if (rc != MEMCACHED_SUCCESS)
				{
					fprintf(stderr, "failed to switch to binary protocol: %s\n",
							memcached_strerror(mcd, rc));
					return 1;
				}
				break;

			case 'c':
			{
				in_port_t		port;
				uint32_t		weight;

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
					num_conns++;
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
					num_conns++;
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
					num_conns++;
				}
				else
				{
					fprintf(stderr, "invalid connection string: %s\n", optarg);
					return 1;
				}
				break;
			}
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
				scale = atoi(optarg);
				if (scale < 10)
					scale = 10;
				break;

			case 't':
				duration = atoi(optarg);
				if (duration < 5)
					duration = 5;
				break;

			case 'h':
			default:
				usage();
				break;
		}
	}

	/*
	 * If no -c option, add 127.0.0.1:11211 instead.
	 */
	if (num_conns == 0 &&
		memcached_server_add(mcd, "localhost", 11211) != MEMCACHED_SUCCESS)
	{
		fprintf(stderr, "failed to add tcp://localhost:11211\n");
		return 1;
	}

	/*
	 * Clear the cache
	 */
	rc = memcached_flush(mcd, 0);
	if (rc != MEMCACHED_SUCCESS)
	{
		fprintf(stderr, "failed on memcached_flush: %s\n",
				memcached_strerror(mcd, rc));
		return 1;
	}

	/*
	 * Launch worker threads
	 */
	memset(&stat, 0, sizeof(mcdbench_t));

	workers = calloc(num_threads, sizeof(mcdbench_t));
	if (!workers)
	{
		fprintf(stderr, "momory allocation failed: %s\n", strerror(errno));
		return 1;
	}

	gettimeofday(&tv1, NULL);
	for (index=0; index < num_threads; index++)
	{
		workers[index].scale = scale;
		workers[index].duration = duration;
		workers[index].mcd = memcached_clone(NULL, mcd);
		if (!workers[index].mcd)
		{
			fprintf(stderr, "momory allocation failed: %s\n", strerror(errno));
			return 1;
		}
		if (pthread_create(&workers[index].thread, NULL,
						   worker_fn, (void *)&workers[index]) != 0)
		{
			fprintf(stderr, "failed to create worker thread: %s", strerror(errno));
			return 1;
		}
	}
	/*
	 * Now worker thread working...
	 */
	sleep(duration);

	worker_exit = true;

	for (index=0; index < num_threads; index++)
	{
		if (pthread_join(workers[index].thread, NULL) != 0)
		{
			fprintf(stderr, "failed on pthread_join : %s\n", strerror(errno));
			return 1;
		}
		stat.num_get	+= workers[index].num_get;
		stat.num_store	+= workers[index].num_store;
		stat.num_append	+= workers[index].num_append;
		stat.num_cas	+= workers[index].num_cas;
		stat.num_remove	+= workers[index].num_remove;
		stat.total_send	+= workers[index].total_send;
		stat.total_recv	+= workers[index].total_recv;
	}
	gettimeofday(&tv2, NULL);

	total_cmds = (stat.num_get + 
				  stat.num_store + 
				  stat.num_append +
				  stat.num_cas +
				  stat.num_remove);
	interval = ((tv2.tv_sec - tv1.tv_sec)    * 1000000 +
				(tv2.tv_usec - tv1.tv_usec)) / 1000000.0;

	printf("number of thread:         % 8d\n"
		   "total time of run:        % 8.2f\n"
		   "number of GET command:    % 8" PRIu32 " (%.2f/s)\n"
		   "number of STORE command:  % 8" PRIu32 " (%.2f/s)\n"
		   "number of APPEND command: % 8" PRIu32 " (%.2f/s)\n"
		   "number of CAS command:    % 8" PRIu32 " (%.2f/s)\n"
		   "number of REMOVE command: % 8" PRIu32 " (%.2f/s)\n"
		   "number of total commands: % 8" PRIu32 " (%.2f/s)\n"
		   "total bytes of send:      %" PRIu64 " (%.2f/s)\n"
		   "total bytes of recv:      %" PRIu64 " (%.2f/s)\n",
		   num_threads,
		   interval,
		   stat.num_get,	((double)stat.num_get) /interval,
		   stat.num_store,	((double)stat.num_store) / interval,
		   stat.num_append,	((double)stat.num_append) / interval,
		   stat.num_cas,	((double)stat.num_cas) / interval,
		   stat.num_remove,	((double)stat.num_remove) / interval,
		   total_cmds,		((double)total_cmds) / interval,
		   stat.total_send,	((double)stat.total_send) / interval,
		   stat.total_recv,	((double)stat.total_recv) / interval,
		   (stat.total_send + stat.total_recv),
		   ((double)(stat.total_send + stat.total_recv)) / interval);

	return 0;
}
