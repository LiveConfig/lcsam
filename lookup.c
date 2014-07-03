/*  _    _          ___           __ _     (R)
 * | |  (_)_ _____ / __|___ _ _  / _(_)__ _
 * | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
 * |____|_|\_/\___|\___\___/_||_|_| |_\__, |
 *                                    |___/
 * lcsam - LiveConfig SpamAssassin Milter
 */

/*lint -esym(534, pthread_mutex_lock, pthread_mutex_unlock, __db::close) / safely ignore return value */
/*lint -sem(lookup_prefs, thread_protected) */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>

#ifdef BDB_H
#include BDB_H
#else
#include <db.h>
#endif

#include "lcsam.h"
#include "args.h"
#include "log.h"
#include "lookup.h"

/* mutex for thread-safe access to the database handle */
/*lint -e(708) */
static pthread_mutex_t lcsam_db_mutex = PTHREAD_MUTEX_INITIALIZER;

/* database environment handle */
static DB *dbp = NULL;

/* database filename */
static char *db_filename = NULL;

/* last modification of database file */
static time_t db_mtime;

/* ----------------------------------------------------------------------
 * open_db()
 * Open database file
 * API: http://www.stanford.edu/class/cs276a/projects/docs/berkeleydb/api_c/db_open.html
 * ---------------------------------------------------------------------- */
static int open_db(struct lcsam_priv *priv, const char *filename) {
	int ret;
	DB *d;

	if (db_filename != NULL && db_filename != filename) {
		free(db_filename);
		db_filename = strdup(filename);
		if (db_filename == NULL) {
			log_print(LOG_ERR, priv, "strdup(%s) failed: %s", filename, strerror(errno));
			return(-1);
		}
	}

	/* create environment */
	if ((ret = db_create(&d, NULL, 0)) != 0) {
		log_print(LOG_ERR, priv, "db_create: %s", db_strerror(ret));
		return(-1);
	}

	if ((ret = d->open(d, NULL, filename, NULL, DB_UNKNOWN, DB_RDONLY, 0)) != 0) {
		log_print(LOG_ERR, priv, "db_open(%s): %s", filename, db_strerror(ret));
		d->close(d, 0);
		return(-1);
	}

	dbp = d;
	return(0);
}

/* ----------------------------------------------------------------------
 * lookup_prefs()
 * Lookup per-user preferences from database file
 * ---------------------------------------------------------------------- */
int lookup_prefs(struct lcsam_priv *priv, const char *addr, struct lookup_result *res) {
	int ret;
	DBT key, data;
	struct stat st;

	if (addr == NULL || addr[0] == '\0') return(-1);

	/* acquire mutex */
	pthread_mutex_lock(&lcsam_db_mutex);

	if (stat(db_filename, &st) == -1) {
		log_print(LOG_ERR, priv, "lcsam_lookup(%s): stat(%s) failed: '%s'", addr, db_filename, strerror(errno));
		pthread_mutex_unlock(&lcsam_db_mutex);
		return(-1);
	}

	if (dbp != NULL && db_mtime != st.st_mtime) {
		/* database file was modified. close now and open again (below). */
		(void)dbp->close(dbp, 0);
		dbp = NULL;
	}

	if (dbp == NULL) {
		/* open database */
		if (open_db(priv, args_usermap) != 0) {
			pthread_mutex_unlock(&lcsam_db_mutex);
			return(-1);
		}
		db_mtime = st.st_mtime;
	}

	/* unlock mutex */
	pthread_mutex_unlock(&lcsam_db_mutex);

	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));
	key.data = (char*)addr;
	key.size = (unsigned int)strlen(addr)+1;

	ret = dbp->get(dbp, NULL, &key, &data, 0);
	if (ret == 0) {
		/* found key */
		/* expected response: "Version Warn Reject Action UserID SubjectPrefix" */
		if (res != NULL) {
			unsigned int version;
			int parsed;
			char *subj;
			ret = sscanf(data.data, "%u %f %f %d %64s %n",
					&version, &res->warn_score, &res->reject_score, &res->action,
					res->userid, &parsed);
			if (ret != 5 && ret != 6) {
				log_print(LOG_ERR, priv, "lcsam_lookup(%s): unexpected result: '%s' (ret=%i)", addr, (char*)data.data, ret);
				return(-1);
			}
			if (version != 1) {
				log_print(LOG_ERR, priv, "lcsam_lookup(%s): unsupported record version %u", addr, version);
				return(-1);
			}
			subj = (char*)data.data + parsed;
			strncpy(res->subjectprefix, subj, sizeof(res->subjectprefix));
			res->subjectprefix[sizeof(res->subjectprefix)-1] = '\0';
		}
	} else if (ret == DB_NOTFOUND) {
		/* not found... */
		log_print(LOG_DEBUG, priv, "lcsam_lookup(%s): not found", addr);
		return(-1);
	} else {
		/* any other error */
		log_print(LOG_ERR, priv, "lcsam_lookup(%s): %s", addr, db_strerror(ret));
		return(-1);
	}

	return(0);
}

/* ----------------------------------------------------------------------
 * lookup_close()
 * Close database (clean up)
 * ---------------------------------------------------------------------- */
void lookup_close(void) {

	/* acquire mutex */
	pthread_mutex_lock(&lcsam_db_mutex);

	if (dbp != NULL) {
		(void)dbp->close(dbp, 0);
		dbp = NULL;
	}

	if (db_filename != NULL) {
		free(db_filename);
		db_filename = NULL;
	}

	/* unlock mutex */
	pthread_mutex_unlock(&lcsam_db_mutex);

}

/* <EOF> ------------------------------------------------------------------ */
