/*
 * $PostgreSQL: pgsql/contrib/pg_standby/pg_standby.c,v 1.20 2009/03/18 20:30:35 heikki Exp $ 
 *
 *
 * pg_standby.c
 *
 * Production-ready example of how to create a Warm Standby
 * database server using continuous archiving as a
 * replication mechanism
 *
 * We separate the parameters for archive and nextWALfile
 * so that we can check the archive exists, even if the
 * WAL file doesn't (yet).
 *
 * This program will be executed once in full for each file
 * requested by the warm standby server.
 *
 * It is designed to cater to a variety of needs, as well
 * providing a customizable section.
 *
 * Original author:		Simon Riggs  simon@2ndquadrant.com
 * Current maintainer:	Simon Riggs
 */
#include "postgres_fe.h"

#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <signal.h>

#ifdef WIN32
int			getopt(int argc, char *const argv[], const char *optstring);
#else
#include <sys/time.h>
#include <unistd.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif
#endif   /* ! WIN32 */

extern char *optarg;
extern int	optind;

const char *progname;

/* Options and defaults */
int			sleeptime = 5;		/* amount of time to sleep between file checks */
int			waittime = -1;		/* how long we have been waiting, -1 no wait
								 * yet */
int			maxwaittime = 0;	/* how long are we prepared to wait for? */
int			keepfiles = 0;		/* number of WAL files to keep, 0 keep all */
int			maxretries = 3;		/* number of retries on restore command */
bool		debug = false;		/* are we debugging? */
bool		triggered = false;	/* have we been triggered? */
bool		need_cleanup = false;		/* do we need to remove files from
										 * archive? */

static volatile sig_atomic_t signaled = false;

char	   *archiveLocation;	/* where to find the archive? */
char	   *triggerPath;		/* where to find the trigger file? */
char	   *xlogFilePath;		/* where we are going to restore to */
char	   *nextWALFileName;	/* the file we need to get from archive */
char	   *restartWALFileName; /* the file from which we can restart restore */
char	   *priorWALFileName;	/* the file we need to get from archive */
char		WALFilePath[MAXPGPATH];		/* the file path including archive */
char		restoreCommand[MAXPGPATH];	/* run this to restore */
char		exclusiveCleanupFileName[MAXPGPATH];		/* the file we need to
														 * get from archive */

#define RESTORE_COMMAND_COPY 0
#define RESTORE_COMMAND_LINK 1
int			restoreCommandType;

#define XLOG_DATA			 0
#define XLOG_HISTORY		 1
#define XLOG_BACKUP_LABEL	 2
int			nextWALFileType;

#define SET_RESTORE_COMMAND(cmd, arg1, arg2) \
	snprintf(restoreCommand, MAXPGPATH, cmd " \"%s\" \"%s\"", arg1, arg2)

struct stat stat_buf;

/* =====================================================================
 *
 *		  Customizable section
 *
 * =====================================================================
 *
 *	Currently, this section assumes that the Archive is a locally
 *	accessible directory. If you want to make other assumptions,
 *	such as using a vendor-specific archive and access API, these
 *	routines are the ones you'll need to change. You're
 *	enouraged to submit any changes to pgsql-hackers@postgresql.org
 *	or personally to the current maintainer. Those changes may be
 *	folded in to later versions of this program.
 */

#define XLOG_DATA_FNAME_LEN		24
/* Reworked from access/xlog_internal.h */
#define XLogFileName(fname, tli, log, seg)	\
	snprintf(fname, XLOG_DATA_FNAME_LEN + 1, "%08X%08X%08X", tli, log, seg)

/*
 *	Initialize allows customized commands into the warm standby program.
 *
 *	As an example, and probably the common case, we use either
 *	cp/ln commands on *nix, or copy/move command on Windows.
 *
 */
static void
CustomizableInitialize(void)
{
#ifdef WIN32
	snprintf(WALFilePath, MAXPGPATH, "%s\\%s", archiveLocation, nextWALFileName);
	switch (restoreCommandType)
	{
		case RESTORE_COMMAND_LINK:
			SET_RESTORE_COMMAND("mklink", WALFilePath, xlogFilePath);
			break;
		case RESTORE_COMMAND_COPY:
		default:
			SET_RESTORE_COMMAND("copy", WALFilePath, xlogFilePath);
			break;
	}
#else
	snprintf(WALFilePath, MAXPGPATH, "%s/%s", archiveLocation, nextWALFileName);
	switch (restoreCommandType)
	{
		case RESTORE_COMMAND_LINK:
#if HAVE_WORKING_LINK
			SET_RESTORE_COMMAND("ln -s -f", WALFilePath, xlogFilePath);
			break;
#endif
		case RESTORE_COMMAND_COPY:
		default:
			SET_RESTORE_COMMAND("cp", WALFilePath, xlogFilePath);
			break;
	}
#endif

	/*
	 * This code assumes that archiveLocation is a directory You may wish to
	 * add code to check for tape libraries, etc.. So, since it is a
	 * directory, we use stat to test if its accessible
	 */
	if (stat(archiveLocation, &stat_buf) != 0)
	{
		fprintf(stderr, "%s: archiveLocation \"%s\" does not exist\n", progname, archiveLocation);
		fflush(stderr);
		exit(2);
	}
}

/*
 * CustomizableNextWALFileReady()
 *
 *	  Is the requested file ready yet?
 */
static bool
CustomizableNextWALFileReady()
{
	if (stat(WALFilePath, &stat_buf) == 0)
	{
		/*
		 * If its a backup file, return immediately If its a regular file
		 * return only if its the right size already
		 */
		if (strlen(nextWALFileName) > 24 &&
			strspn(nextWALFileName, "0123456789ABCDEF") == 24 &&
		strcmp(nextWALFileName + strlen(nextWALFileName) - strlen(".backup"),
			   ".backup") == 0)
		{
			nextWALFileType = XLOG_BACKUP_LABEL;
			return true;
		}
		else if (stat_buf.st_size == XLOG_SEG_SIZE)
		{
#ifdef WIN32

			/*
			 * Windows 'cp' sets the final file size before the copy is
			 * complete, and not yet ready to be opened by pg_standby.
			 * So we wait for sleeptime secs before attempting to restore.
			 * If that is not enough, we will rely on the retry/holdoff
			 * mechanism.  GNUWin32's cp does not have this problem.
			 */
			pg_usleep(sleeptime * 1000000L);
#endif
			nextWALFileType = XLOG_DATA;
			return true;
		}

		/*
		 * If still too small, wait until it is the correct size
		 */
		if (stat_buf.st_size > XLOG_SEG_SIZE)
		{
			if (debug)
			{
				fprintf(stderr, "file size greater than expected\n");
				fflush(stderr);
			}
			exit(3);
		}
	}

	return false;
}

#define MaxSegmentsPerLogFile ( 0xFFFFFFFF / XLOG_SEG_SIZE )

static void
CustomizableCleanupPriorWALFiles(void)
{
	/*
	 * Work out name of prior file from current filename
	 */
	if (nextWALFileType == XLOG_DATA)
	{
		int			rc;
		DIR		   *xldir;
		struct dirent *xlde;

		/*
		 * Assume its OK to keep failing. The failure situation may change
		 * over time, so we'd rather keep going on the main processing than
		 * fail because we couldnt clean up yet.
		 */
		if ((xldir = opendir(archiveLocation)) != NULL)
		{
			while ((xlde = readdir(xldir)) != NULL)
			{
				/*
				 * We ignore the timeline part of the XLOG segment identifiers
				 * in deciding whether a segment is still needed.  This
				 * ensures that we won't prematurely remove a segment from a
				 * parent timeline. We could probably be a little more
				 * proactive about removing segments of non-parent timelines,
				 * but that would be a whole lot more complicated.
				 *
				 * We use the alphanumeric sorting property of the filenames
				 * to decide which ones are earlier than the
				 * exclusiveCleanupFileName file. Note that this means files
				 * are not removed in the order they were originally written,
				 * in case this worries you.
				 */
				if (strlen(xlde->d_name) == XLOG_DATA_FNAME_LEN &&
					strspn(xlde->d_name, "0123456789ABCDEF") == XLOG_DATA_FNAME_LEN &&
				  strcmp(xlde->d_name + 8, exclusiveCleanupFileName + 8) < 0)
				{
#ifdef WIN32
					snprintf(WALFilePath, MAXPGPATH, "%s\\%s", archiveLocation, xlde->d_name);
#else
					snprintf(WALFilePath, MAXPGPATH, "%s/%s", archiveLocation, xlde->d_name);
#endif

					if (debug)
						fprintf(stderr, "\nremoving \"%s\"", WALFilePath);

					rc = unlink(WALFilePath);
					if (rc != 0)
					{
						fprintf(stderr, "\n%s: ERROR failed to remove \"%s\": %s",
								progname, WALFilePath, strerror(errno));
						break;
					}
				}
			}
			if (debug)
				fprintf(stderr, "\n");
		}
		else
			fprintf(stderr, "%s: archiveLocation \"%s\" open error\n", progname, archiveLocation);

		closedir(xldir);
		fflush(stderr);
	}
}

/* =====================================================================
 *		  End of Customizable section
 * =====================================================================
 */

/*
 * SetWALFileNameForCleanup()
 *
 *	  Set the earliest WAL filename that we want to keep on the archive
 *	  and decide whether we need_cleanup
 */
static bool
SetWALFileNameForCleanup(void)
{
	uint32		tli = 1,
				log = 0,
				seg = 0;
	uint32		log_diff = 0,
				seg_diff = 0;
	bool		cleanup = false;

	if (restartWALFileName)
	{
		/*
		 * Don't do cleanup if the restartWALFileName provided
		 * is later than the xlog file requested. This is an error
		 * and we must not remove these files from archive.
		 * This shouldn't happen, but better safe than sorry.
		 */
		if (strcmp(restartWALFileName, nextWALFileName) > 0)
			return false;

		strcpy(exclusiveCleanupFileName, restartWALFileName);
		return true;
	}

	if (keepfiles > 0)
	{
		sscanf(nextWALFileName, "%08X%08X%08X", &tli, &log, &seg);
		if (tli > 0 && log >= 0 && seg > 0)
		{
			log_diff = keepfiles / MaxSegmentsPerLogFile;
			seg_diff = keepfiles % MaxSegmentsPerLogFile;
			if (seg_diff > seg)
			{
				log_diff++;
				seg = MaxSegmentsPerLogFile - (seg_diff - seg);
			}
			else
				seg -= seg_diff;

			if (log >= log_diff)
			{
				log -= log_diff;
				cleanup = true;
			}
			else
			{
				log = 0;
				seg = 0;
			}
		}
	}

	XLogFileName(exclusiveCleanupFileName, tli, log, seg);

	return cleanup;
}

/*
 * CheckForExternalTrigger()
 *
 *	  Is there a trigger file?
 */
static bool
CheckForExternalTrigger(void)
{
	int			rc;

	/*
	 * Look for a trigger file, if that option has been selected
	 *
	 * We use stat() here because triggerPath is always a file rather than
	 * potentially being in an archive
	 */
	if (triggerPath && stat(triggerPath, &stat_buf) == 0)
	{
		fprintf(stderr, "trigger file found\n");
		fflush(stderr);

		/*
		 * If trigger file found, we *must* delete it. Here's why: When
		 * recovery completes, we will be asked again for the same file from
		 * the archive using pg_standby so must remove trigger file so we can
		 * reload file again and come up correctly.
		 */
		rc = unlink(triggerPath);
		if (rc != 0)
		{
			fprintf(stderr, "\n ERROR: could not remove \"%s\": %s", triggerPath, strerror(errno));
			fflush(stderr);
			exit(rc);
		}
		return true;
	}

	return false;
}

/*
 * RestoreWALFileForRecovery()
 *
 *	  Perform the action required to restore the file from archive
 */
static bool
RestoreWALFileForRecovery(void)
{
	int			rc = 0;
	int			numretries = 0;

	if (debug)
	{
		fprintf(stderr, "\nrunning restore		:");
		fflush(stderr);
	}

	while (numretries < maxretries)
	{
		rc = system(restoreCommand);
		if (rc == 0)
		{
			if (debug)
			{
				fprintf(stderr, " OK");
				fflush(stderr);
			}
			return true;
		}
		pg_usleep(numretries++ * sleeptime * 1000000L);
	}

	/*
	 * Allow caller to add additional info
	 */
	if (debug)
		fprintf(stderr, "not restored		: ");
	return false;
}

static void
usage(void)
{
	printf("%s allows PostgreSQL warm standby servers to be configured.\n\n", progname);
	printf("Usage:\n");
	printf("  %s [OPTION]... ARCHIVELOCATION NEXTWALFILE XLOGFILEPATH [RESTARTWALFILE]\n", progname);
	printf("\n"
		   "with main intended use as a restore_command in the recovery.conf:\n"
		   "  restore_command = 'pg_standby [OPTION]... ARCHIVELOCATION %%f %%p %%r'\n"
		   "e.g.\n"
		   "  restore_command = 'pg_standby -l /mnt/server/archiverdir %%f %%p %%r'\n");
	printf("\nOptions:\n");
	printf("  -c                 copies file from archive (default)\n");
	printf("  -d                 generate lots of debugging output (testing only)\n");
	printf("  -k NUMFILESTOKEEP  if RESTARTWALFILE not used, removes files prior to limit\n"
		   "                     (0 keeps all)\n");
	printf("  -l                 links into archive (leaves file in archive)\n");
	printf("  -r MAXRETRIES      max number of times to retry, with progressive wait\n"
		   "                     (default=3)\n");
	printf("  -s SLEEPTIME       seconds to wait between file checks (min=1, max=60,\n"
		   "                     default=5)\n");
	printf("  -t TRIGGERFILE     defines a trigger file to initiate failover (no default)\n");
	printf("  -w MAXWAITTIME     max seconds to wait for a file (0=no limit) (default=0)\n");
	printf("  --help             show this help, then exit\n");
	printf("  --version          output version information, then exit\n");
	printf("\nReport bugs to <pgsql-bugs@postgresql.org>.\n");
}

static void
sighandler(int sig)
{
	signaled = true;
}

#ifndef WIN32
/* We don't want SIGQUIT to core dump */
static void
sigquit_handler(int sig)
{
	signal(SIGINT, SIG_DFL);
	kill(getpid(), SIGINT);
}
#endif

/*------------ MAIN ----------------------------------------*/
int
main(int argc, char **argv)
{
	int			c;

	progname = get_progname(argv[0]);

	if (argc > 1)
	{
		if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-?") == 0)
		{
			usage();
			exit(0);
		}
		if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-V") == 0)
		{
			puts("pg_standby (PostgreSQL) " PG_VERSION);
			exit(0);
		}
	}

	/*
	 * You can send SIGUSR1 to trigger failover.
	 *
	 * Postmaster uses SIGQUIT to request immediate shutdown. The default
	 * action is to core dump, but we don't want that, so trap it and
	 * commit suicide without core dump.
	 *
	 * We used to use SIGINT and SIGQUIT to trigger failover, but that
	 * turned out to be a bad idea because postmaster uses SIGQUIT to
	 * request immediate shutdown. We still trap SIGINT, but that may
	 * change in a future release.
	 */
	(void) signal(SIGUSR1, sighandler);
	(void) signal(SIGINT, sighandler); /* deprecated, use SIGUSR1 */
#ifndef WIN32
	(void) signal(SIGQUIT, sigquit_handler);
#endif

	while ((c = getopt(argc, argv, "cdk:lr:s:t:w:")) != -1)
	{
		switch (c)
		{
			case 'c':			/* Use copy */
				restoreCommandType = RESTORE_COMMAND_COPY;
				break;
			case 'd':			/* Debug mode */
				debug = true;
				break;
			case 'k':			/* keepfiles */
				keepfiles = atoi(optarg);
				if (keepfiles < 0)
				{
					fprintf(stderr, "%s: -k keepfiles must be >= 0\n", progname);
					exit(2);
				}
				break;
			case 'l':			/* Use link */
				restoreCommandType = RESTORE_COMMAND_LINK;
				break;
			case 'r':			/* Retries */
				maxretries = atoi(optarg);
				if (maxretries < 0)
				{
					fprintf(stderr, "%s: -r maxretries must be >= 0\n", progname);
					exit(2);
				}
				break;
			case 's':			/* Sleep time */
				sleeptime = atoi(optarg);
				if (sleeptime <= 0 || sleeptime > 60)
				{
					fprintf(stderr, "%s: -s sleeptime incorrectly set\n", progname);
					exit(2);
				}
				break;
			case 't':			/* Trigger file */
				triggerPath = optarg;
				if (CheckForExternalTrigger())
					exit(1);	/* Normal exit, with non-zero */
				break;
			case 'w':			/* Max wait time */
				maxwaittime = atoi(optarg);
				if (maxwaittime < 0)
				{
					fprintf(stderr, "%s: -w maxwaittime incorrectly set\n", progname);
					exit(2);
				}
				break;
			default:
				fprintf(stderr, "Try \"%s --help\" for more information.\n", progname);
				exit(2);
				break;
		}
	}

	/*
	 * Parameter checking - after checking to see if trigger file present
	 */
	if (argc == 1)
	{
		fprintf(stderr, "%s: not enough command-line arguments\n", progname);
		exit(2);
	}

	/*
	 * We will go to the archiveLocation to get nextWALFileName.
	 * nextWALFileName may not exist yet, which would not be an error, so we
	 * separate the archiveLocation and nextWALFileName so we can check
	 * separately whether archiveLocation exists, if not that is an error
	 */
	if (optind < argc)
	{
		archiveLocation = argv[optind];
		optind++;
	}
	else
	{
		fprintf(stderr, "%s: must specify archive location\n", progname);
		fprintf(stderr, "Try \"%s --help\" for more information.\n", progname);
		exit(2);
	}

	if (optind < argc)
	{
		nextWALFileName = argv[optind];
		optind++;
	}
	else
	{
		fprintf(stderr, "%s: use %%f to specify nextWALFileName\n", progname);
		fprintf(stderr, "Try \"%s --help\" for more information.\n", progname);
		exit(2);
	}

	if (optind < argc)
	{
		xlogFilePath = argv[optind];
		optind++;
	}
	else
	{
		fprintf(stderr, "%s: use %%p to specify xlogFilePath\n", progname);
		fprintf(stderr, "Try \"%s --help\" for more information.\n", progname);
		exit(2);
	}

	if (optind < argc)
	{
		restartWALFileName = argv[optind];
		optind++;
	}

	CustomizableInitialize();

	need_cleanup = SetWALFileNameForCleanup();

	if (debug)
	{
		fprintf(stderr, "\nTrigger file 		: %s", triggerPath ? triggerPath : "<not set>");
		fprintf(stderr, "\nWaiting for WAL file	: %s", nextWALFileName);
		fprintf(stderr, "\nWAL file path		: %s", WALFilePath);
		fprintf(stderr, "\nRestoring to...		: %s", xlogFilePath);
		fprintf(stderr, "\nSleep interval		: %d second%s",
				sleeptime, (sleeptime > 1 ? "s" : " "));
		fprintf(stderr, "\nMax wait interval	: %d %s",
				maxwaittime, (maxwaittime > 0 ? "seconds" : "forever"));
		fprintf(stderr, "\nCommand for restore	: %s", restoreCommand);
		fprintf(stderr, "\nKeep archive history	: ");
		if (need_cleanup)
			fprintf(stderr, "%s and later", exclusiveCleanupFileName);
		else
			fprintf(stderr, "No cleanup required");
		fflush(stderr);
	}

	/*
	 * Check for initial history file: always the first file to be requested
	 * It's OK if the file isn't there - all other files need to wait
	 */
	if (strlen(nextWALFileName) > 8 &&
		strspn(nextWALFileName, "0123456789ABCDEF") == 8 &&
		strcmp(nextWALFileName + strlen(nextWALFileName) - strlen(".history"),
			   ".history") == 0)
	{
		nextWALFileType = XLOG_HISTORY;
		if (RestoreWALFileForRecovery())
			exit(0);
		else
		{
			if (debug)
			{
				fprintf(stderr, "history file not found\n");
				fflush(stderr);
			}
			exit(1);
		}
	}

	/*
	 * Main wait loop
	 */
	while (!CustomizableNextWALFileReady() && !triggered)
	{
		if (sleeptime <= 60)
			pg_usleep(sleeptime * 1000000L);

		if (signaled)
		{
			triggered = true;
			if (debug)
			{
				fprintf(stderr, "\nsignaled to exit\n");
				fflush(stderr);
			}
		}
		else
		{

			if (debug)
			{
				fprintf(stderr, "\nWAL file not present yet.");
				if (triggerPath)
					fprintf(stderr, " Checking for trigger file...");
				fflush(stderr);
			}

			waittime += sleeptime;

			if (!triggered && (CheckForExternalTrigger() || (waittime >= maxwaittime && maxwaittime > 0)))
			{
				triggered = true;
				if (debug && waittime >= maxwaittime && maxwaittime > 0)
					fprintf(stderr, "\nTimed out after %d seconds\n", waittime);
			}
		}
	}

	/*
	 * Action on exit
	 */
	if (triggered)
		exit(1);				/* Normal exit, with non-zero */

	/*
	 * Once we have restored this file successfully we can remove some prior
	 * WAL files. If this restore fails we musn't remove any file because some
	 * of them will be requested again immediately after the failed restore,
	 * or when we restart recovery.
	 */
	if (RestoreWALFileForRecovery() && need_cleanup)
		CustomizableCleanupPriorWALFiles();

	return 0;
}
