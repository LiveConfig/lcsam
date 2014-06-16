/*  _    _          ___           __ _     (R)
 * | |  (_)_ _____ / __|___ _ _  / _(_)__ _
 * | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
 * |____|_|\_/\___|\___\___/_||_|_| |_\__, |
 *                                    |___/
 * lcsam - LiveConfig SpamAssassin Milter
 */

/*lint -esym(534, sleep, umask) / safely ignore return value */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>

#include "lcsam.h"
#include "log.h"
#include "pid.h"

static int __pid_fd = -1;
static pid_t __pid_opened = -1;	/* own PID while opening (creating) the pid file */

/* ----------------------------------------------------------------------
 * create PID file
 * ---------------------------------------------------------------------- */
int pid_create(const char *filename) {
	mode_t old_umask;
	int fd;
	char pidbuf[16];
	struct flock fl;
	struct stat lst, fst;
	int existed = 0;

	/* get file stats for file (or link): */
	if (lstat(filename, &lst) == 0) {
		existed = 1;
		if (!S_ISREG(lst.st_mode)) {
			log_print(LOG_ERR, NULL, "Existing PID file '%s' is not a regular file - aborting...", filename);
			return(-1);
		}
	} else if (errno != ENOENT) {
		log_print(LOG_ERR, NULL, "pid_create: lstat: %s", strerror(errno));
		return(-1);
	}

	/* set safe umask */
	old_umask = umask(022);

	/* open PID file */
	while ((fd = open(filename, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1) {
		if (errno == EINTR) continue;
		log_print(LOG_ERR, NULL, "pid_create: open: %s", strerror(errno));
		umask(old_umask);
		return(-1);
	}

	/* restore umask */
	umask(old_umask);

	/* get file stats */
	if (fstat(fd, &fst) == -1) {
		log_print(LOG_ERR, NULL, "pid_create: fstat: %s", strerror(errno));
		close(fd);
		return(-1);
	}

	if (!existed) {
		/* get file stats for new created file */
		if (lstat(filename, &lst) == -1) {
			log_print(LOG_ERR, NULL, "pid_create: lstat: %s", strerror(errno));
			close(fd);
			return(-1);
		}
	}

	if (lst.st_mode != fst.st_mode || lst.st_ino != fst.st_ino || lst.st_dev != fst.st_dev || !S_ISREG(lst.st_mode)) {
		log_print(LOG_ERR, NULL, "Race condition on PID creation detected - aborting...");
		close(fd);
		return(-1);
	}

	/* acquire exclusive lock */
	memset(&fl, 0, sizeof(struct flock));
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;
	while (fcntl(fd, F_SETLK, &fl) == -1) {
		if (errno == EINTR) continue;
		if (errno == EACCES || errno == EAGAIN) {
			/* lock already exists; find out PID of blocking process */
			while (fcntl(fd, F_GETLK, &fl) == -1) {
				if (errno == EINTR) continue;
				log_print(LOG_ERR, NULL, "pid_create: lock: %s", strerror(errno));
				close(fd);
				return(-1);
			}
			if (fl.l_pid == getpid()) {
				/* already locked by this program */
				break;
			}
			log_print(LOG_ERR, NULL, "Can't lock PID file, already in use by PID %u (program already running?)\n", fl.l_pid);
		} else {
			log_print(LOG_ERR, NULL, "pid_create: lock: %s", strerror(errno));
		}
		close(fd);
		return(-1);
	}

	/* ok, we have an exclusive lock */
	/* now write PID into this file */
	snprintf(pidbuf, sizeof(pidbuf)-1, "%u\n", getpid());

	while (write(fd, pidbuf, strlen(pidbuf)) == -1) {
		if (errno == EINTR) continue;
		log_print(LOG_ERR, NULL, "pid_create: write: %s", strerror(errno));
		/* close/unlock and delete PID file */
		unlink(filename);
		close(fd);
		return(-1);
	}

	__pid_fd = fd;
	__pid_opened = getpid();

	return(0);
}

/* ----------------------------------------------------------------------
 * update PID
 * ---------------------------------------------------------------------- */
int pid_update(void) {
	char pidbuf[16];

	if (__pid_fd < 0) return(-1);

	/* if our PID has changed (due to fork()), re-lock the PID file */
	if (getpid() != __pid_opened) {
		struct flock fl;
		memset(&fl, 0, sizeof(struct flock));
		fl.l_type = F_WRLCK;
		fl.l_whence = SEEK_SET;
		fl.l_start = 0;
		fl.l_len = 0;
		while (fcntl(__pid_fd, F_SETLK, &fl) == -1) {
			if (errno == EINTR) continue;
			if (errno == EACCES || errno == EAGAIN) {
				/* lock already exists; find out PID of blocking process */
				while (fcntl(__pid_fd, F_GETLK, &fl) == -1) {
					if (errno == EINTR) continue;
					log_print(LOG_ERR, NULL, "pid_update: lock: %s", strerror(errno));
					close(__pid_fd);
					return(-1);
				}
				if (fl.l_pid == __pid_opened) {
					/* still locked by parent, wait until it has exited and then try again */
					sleep(1);
					continue;
				}
				log_print(LOG_ERR, NULL, "Can't lock PID file, already in use by PID %u (program already running?)\n", fl.l_pid);
			} else {
				log_print(LOG_ERR, NULL, "pid_update: lock: %s", strerror(errno));
			}
			close(__pid_fd);
			return(-1);
		}
	}


	/* truncate PID file and write new PID */
	while (ftruncate(__pid_fd, 0L) == -1) {
		if (errno == EINTR) continue;
		log_print(LOG_ERR, NULL, "pid_update: truncate: %s", strerror(errno));
		return(-1);
	}

	while (lseek(__pid_fd, 0L, SEEK_SET) == -1) {
		if (errno == EINTR) continue;
		log_print(LOG_ERR, NULL, "pid_update: lseek: %s", strerror(errno));
		return(-1);
	}

	snprintf(pidbuf, sizeof(pidbuf)-1, "%u\n", getpid());

	while (write(__pid_fd, pidbuf, strlen(pidbuf)) == -1) {
		if (errno == EINTR) continue;
		log_print(LOG_ERR, NULL, "pid_update: write: %s", strerror(errno));
		return(-1);
	}

	return(0);
}

/* ----------------------------------------------------------------------
 * remove PID file
 * ---------------------------------------------------------------------- */
void pid_release(const char *filename) {
	if (__pid_fd < 0) return;

	/* unlink PID file */
	unlink(filename);

	/* close file (also releases lock) */
	close(__pid_fd);
	__pid_fd = -1;
}

/* <EOF> ---------------------------------------------------------------- */
