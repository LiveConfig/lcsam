/*  _    _          ___           __ _     (R)
 * | |  (_)_ _____ / __|___ _ _  / _(_)__ _
 * | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
 * |____|_|\_/\___|\___\___/_||_|_| |_\__, |
 *                                    |___/
 * lcsam - LiveConfig SpamAssassin Milter
 */

/*lint -esym(534, setgroups) */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <syslog.h>
#include <errno.h>
#include <paths.h>
#include <sys/resource.h>
#include <string.h>

#include "lcsam.h"
#include "args.h"
#include "log.h"
#include "safety.h"

#ifndef OPEN_MAX
#define OPEN_MAX 256		/*!< defined as "open files a process may have"... */
#endif

static long		orig_ngroups	= -1;
static uid_t	orig_uid		= 65534;
static gid_t	orig_gid		= 65534;
static gid_t	orig_groups[NGROUPS_MAX];

#if __STDC_VERSION__ < 199901L
# if __GNUC__ >= 2
#  define __func__ __FUNCTION__
# else
#  define __func__ "<unknown>"
# endif
#endif
#define SAFETY_ERROR(fmt, x...) log_print(LOG_ERR, NULL, "%s: " fmt, __func__, ## x); return(-1)

/* ----------------------------------------------------------------------
 * safety_first()
 * run first safety checks
 * ---------------------------------------------------------------------- */
int safety_first(void) {
#ifndef WIN32
	uid_t			uid;
	struct passwd	*pwd;
	int				fd, fmax;
	struct stat		fst;
	FILE			*f;

	orig_uid = geteuid();
	orig_gid = getegid();

	/* check if we're running as setuid */
	if (getuid() != geteuid()) {
		SAFETY_ERROR("running as setuid program (uid %i != euid %i)", getuid(), geteuid());
	}

	/* get password entry to enshure we're running under a valid user id */
	uid = getuid();
	pwd = getpwuid(uid);
	if (pwd == NULL) {
		SAFETY_ERROR("Can't get password file record for current user id");
	}

	/* set safe umask: */
	umask(0077U);

	/* make shure that all open descriptors other than the standard ones are closed */
	if ((fmax = getdtablesize()) == -1) fmax = OPEN_MAX;
	for (fd=3; fd < fmax; fd++) {
		close(fd);
	}

	/* verify that the standard descriptors are open. If they're not, attempt to
	 * open them using /dev/null. If any are unsuccessful, abort. */
	for (fd = 0; fd < 3; fd++) {
		if (fstat(fd, &fst) == -1) {
			if (errno != EBADF) {
				SAFETY_ERROR("Standard file descriptor is not ok");
			}
			if (fd == 0) {
				f = freopen(_PATH_DEVNULL, "rb", stdin);
			} else if (fd == 1) {
				f = freopen(_PATH_DEVNULL, "wb", stdout);
			} else { /* fd == 2 */
				f = freopen(_PATH_DEVNULL, "wb", stderr);
			}
			if (f == NULL) {
				SAFETY_ERROR("Error while re-opening standard file descriptor to /dev/null");
			}
			if (fileno(f) != fd) {
				SAFETY_ERROR("new fileno for standard descriptor %i is %i!", fd, fileno(f));
			}
		}
	}

	/* when we are in debug mode: enable core dumps: */
	if (args_debug == 1) {
		struct rlimit srl;
		srl.rlim_cur = srl.rlim_max = RLIM_INFINITY;
		if (setrlimit((int)RLIMIT_CORE, &srl) == -1) {
			SAFETY_ERROR("can't enable core dumps in debug mode: %s", strerror(errno));
		}
	}

#endif /* !WIN32 */

	return(0);
}

/* ----------------------------------------------------------------------
 * safety_user_change()
 * change privileges to a certain user/group
 * ---------------------------------------------------------------------- */
int safety_user_change(int permanent, const char *new_user, const char *new_group) {
	struct passwd *spw;
	struct group *sgr;
	uid_t olduid = geteuid();
	gid_t oldgid = getegid();
	uid_t newuid;
	gid_t newgid;

	/* get uid and gid */
	spw = getpwnam(new_user);
	if (spw == NULL) {
		SAFETY_ERROR("can't get id of user '%s': %s", new_user, strerror(errno));
	}
	newuid = spw->pw_uid;

	sgr = getgrnam(new_group);
	if (sgr == NULL) {
		SAFETY_ERROR("can't get id of group '%s': %s", new_group, strerror(errno));
	}
	newgid = sgr->gr_gid;

	if (!permanent) {
		/* save information about the privileges that are being dropped
		 * so that they can be restored later: */
		orig_uid = olduid;
		orig_gid = oldgid;
		orig_ngroups = getgroups(NGROUPS_MAX, orig_groups);
	}

	/* If root privileges are to be dropped, be sure to pare down the ancillary
	 * groups for the process before doing anything else because the setgroups()
	 * system call requires root privileges. Drop ancillary groups regardless of
	 * whether privileges are being dropped temporarily or permanently. */
	if (olduid == 0) setgroups(1UL, &newgid);

	if (newgid != oldgid) {
#ifdef linux
		/*lint -e(737) */
		if (setregid((permanent ? newgid : -1), newgid) == -1) return(-1);
#else
		setegid(newgid);
		if (permanent && setgid(newgid) == -1) return(-1);
#endif
	}

	if (newuid != olduid) {
#ifdef linux
		/*lint -e(737) */
		if (setreuid((permanent ? newuid : -1), newuid) == -1) return(-1);
#else
		seteuid(newuid);
		if (permanent && setuid(newuid) == -1) return(-1);
#endif
	}

	/* verify that the changes were successful: */
	if (permanent) {
		if (newgid != oldgid && (setegid(oldgid) != -1 || getegid() != newgid)) return(-1);
		if (newuid != olduid && (seteuid(olduid) != -1 || geteuid() != newuid)) return(-1);
	} else {
		if (newgid != oldgid && getegid() != newgid) return(-1);
		if (newuid != olduid && geteuid() != newuid) return(-1);
	}

	return(0);
}

/* ----------------------------------------------------------------------
 * safety_user_restore()
 * restore root privileges
 * ---------------------------------------------------------------------- */
int safety_user_restore(void) {
	if (geteuid() != orig_uid) {
		if (seteuid(orig_uid) == -1 || geteuid() != orig_uid) return(-1);
	}
	if (getegid() != orig_gid) {
		if (setegid(orig_gid) == -1 || getegid() != orig_gid) return(-1);
	}
	if (orig_uid != 0) {
		setgroups((size_t)orig_ngroups, orig_groups);
	}
	return(0);
}


/* <EOF> ---------------------------------------------------------------- */
