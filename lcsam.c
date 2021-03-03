/*  _    _          ___           __ _     (R)
 * | |  (_)_ _____ / __|___ _ _  / _(_)__ _
 * | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
 * |____|_|\_/\___|\___\___/_||_|_| |_\__, |
 *                                    |___/
 * lcsam - LiveConfig SpamAssassin Milter
 */

/*
 * Milter API: https://www.milter.org/developers/api/index
 * Postfix before-queue Milter support: http://www.postfix.org/MILTER_README.html
 * spamd protocol: https://svn.apache.org/repos/asf/spamassassin/trunk/spamd/PROTOCOL
 */

/* PC-Lint options */
/*lint -efile(451, stdarg.h, time.h) / no include guard present */
/*lint -esym(459, args_scan_auth) / "unprotected access" from lcsam_envfrom() */
/*lint -esym(526,__builtin_va_start) */
/*lint -emacro(530, va_start) / do not init first parameter */
/*lint -esym(534,snprintf, vsnprintf, smfi_setpriv, umask) / safely ignore return value */
/*lint -efile(537, stdarg.h, time.h, sys/types.h) / no include guard present */
/*lint -esym(628,__builtin_va_start) */
/*lint -e801 / Use of goto is deprecated */
/*lint -e834 / Operator '-' followed by operator '-' is confusing */
/*lint -efunc(818, lcsam_connect, lcsam_envfrom, lcsam_envrcpt, lcsam_body) / can't declare 'const', would break API :( */
/*lint -sem(smfi_setpriv, custodial(2)) */

/*lint -emacro(529, FD_ZERO) */
/*lint -emacro(717, FD_ZERO) */
/*lint -emacro(703, FD_SET) */
/*lint -emacro(530, FD_SET) */
/*lint -emacro(703, FD_ISSET) */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <time.h>
#include <libmilter/mfapi.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <paths.h>

#include "lcsam.h"
#include "args.h"
#include "log.h"
#include "lookup.h"
#include "pid.h"
#include "safety.h"

static const char LCSAM_VERSION[] = "2019-04-02";

#define RCODE_REJECT	"554"
#define XCODE_REJECT	"5.7.1"
#define MSG_REJECT		"Your message was rejected because it appears to be spam"

static void fdprintf(struct lcsam_priv *priv, const char *fmt, ...)
#if defined(__GNUC__) && __GNUC__ >= 4
			__attribute__ (( format( __printf__, 2, 3 )))
#endif
	;

/* ----------------------------------------------------------------------
 * print_help()
 * print usage informations
 * ---------------------------------------------------------------------- */
static void print_help(void) {
	printf(
		"--------------------------------------\n"
		"lcsam - LiveConfig SpamAssassin Milter\n"
		"--------------------------------------\n"
		"Source: https://github.com/LiveConfig/lcsam\n"
		"Version: %s\n"
		"Usage: lcsam [options...]\n"
		"\n"
		"  -a             also scan (outgoing) mails from SASL authenticated users\n"
		"  -A SCORE       reject outgoing mails exceeding this SpamAssassin score\n"
		"  -c PROTO:ADDR  communication socket for incoming connections:\n"
		"                   {unix|local}:/path/to/file       -- a named pipe\n"
		"                   inet:port@{hostname|ip-address}  -- an IPv4 socket\n"
		"                   inet6:port@{hostname|ip-address} -- an IPv6 socket\n"
		"                 default value: \"unix:/var/run/lcsam.sock\"\n"
		"  -d             debug mode - stay in foreground, print debug messages\n"
		"  -h             show this help text\n"
		"  -m FILE        location of the user map file\n"
		"                 default value: \"/etc/postfix/spamassassin.db\"\n"
		"  -p FILE        location of the PID file\n"
		"                 default value: \"/run/lcsam.pid\"\n"
		"  -r             add \"X-Spam-Report:\" header containing detailed\n"
		"                 informations about all rules hit\n"
		"  -s ADDRESS     address of SpamAssassin spamd to connect to\n"
		"                 this can be either an ip address/hostname & port\n"
		"                 or a UNIX domain socket\n"
		"                 default value: \"/var/run/spamd.sock\"\n"
		"  -u USER        user to run lcsam as (default: nobody)\n"
		"  -g GROUP       group to run lcsam as (default: nogroup)\n"
		"  -U USER        owner (user) of the UNIX domain socket (default: mail)\n"
		"  -G GROUP       owner (group) of the UNIX domain socket (default: mail)\n"
		"\n",
		LCSAM_VERSION
		);
}

/* ----------------------------------------------------------------------
 * safe_free()
 * clear memory content, then free() it
 * ---------------------------------------------------------------------- */
static void safe_free(void *ptr, size_t len) {
	if (ptr == NULL) return;
	if (len == 0) len = strlen(ptr);
	memset(ptr, 0, len);
	free(ptr);
}

/* ----------------------------------------------------------------------
 * fdprintf()
 * write formatted text into a file descriptor
 * ---------------------------------------------------------------------- */
static void fdprintf(struct lcsam_priv *priv, const char *fmt, ...) {
	va_list ap;
	int n;
	size_t newsz;
	char *tmpbuf;

	if (priv == NULL || priv->fd < 0 || fmt == NULL || fmt[0] == '\0') return;

	if (priv->sendbuf == NULL) {
		/* allocate send buffer */
		priv->sendbufsize = 2048;
		priv->sendbuf = (char*)malloc(priv->sendbufsize);
		if (priv->sendbuf == NULL) {
			log_print(LOG_ERR, priv, "malloc(%zi) failed: %s", priv->sendbufsize, strerror(errno));
			return;
		}
	}

	/* print formatted message into buffer */
	for (;;) {
		va_start(ap, fmt);
		n = vsnprintf(priv->sendbuf, priv->sendbufsize, fmt, ap);
		va_end(ap);
		if (n > -1 && n < (int)priv->sendbufsize) break;
		/* try again with more space */
		if (n > -1) {
			/* glibc 2.1 */
			newsz = /*lint -e(571) */ (size_t)n + 1;
		} else {
			/* glibc 2.0 */
			newsz = priv->sendbufsize * 2;
		}
		tmpbuf = (char*)realloc(priv->sendbuf, newsz);
		if (tmpbuf == NULL) {
			log_print(LOG_ERR, priv, "realloc(%zi) failed: %s", newsz, strerror(errno));
			return;
		}
		priv->sendbuf = tmpbuf;
		priv->sendbufsize = newsz;
	}

	/* send message */
	while (write(priv->fd, priv->sendbuf, /*lint -e(571) */ (size_t)n) == -1) {
		if (errno == EINTR) continue;
		log_print(LOG_ERR, priv, "write() failed: %s", strerror(errno));
		return;
	}
}

/* ----------------------------------------------------------------------
 * get_spamd_fd()
 * connect to SpamAssassin (spamd) and return socket file descriptor
 * ---------------------------------------------------------------------- */
static int get_spamd_fd(struct lcsam_priv *priv) {
	int fd = -1;

	if (args_spamdsocket[0] == '/') {
		/* UNIX domain socket */
		struct sockaddr_un sun;
#ifndef UNIX_PATH_MAX
		size_t UNIX_PATH_MAX = sizeof(sun.sun_path);
#endif
		size_t sunlen;
		if (strlen(args_spamdsocket) >= UNIX_PATH_MAX) {
			log_print(LOG_ERR, priv, "get_spamd_fd: UNIX socket name too long (only up to %zi characters allowed)", UNIX_PATH_MAX-1);
			return(-1);
		}

		fd = socket(AF_UNIX, (int)SOCK_STREAM, 0);
		if (fd == -1) {
			log_print(LOG_ERR, priv, "get_spamd_fd: socket() failed: %s", strerror(errno));
			return(-1);
		}

		sun.sun_family = AF_UNIX;
		strncpy(sun.sun_path, args_spamdsocket, UNIX_PATH_MAX-1);
		sun.sun_path[UNIX_PATH_MAX-1]='\0';
		sunlen = sizeof(sun.sun_family) + strlen(sun.sun_path);
		/*lint -e(740) */
		if (connect(fd, (struct sockaddr*)&sun, (socklen_t)sunlen) == -1) {
			log_print(LOG_ERR, priv, "get_spamd_fd: can't connect to '%s': %s", args_spamdsocket, strerror(errno));
			close(fd);
			return(-1);
		}

	} else {
		/* assume hostname/port */
		struct addrinfo *ai, *rp, hints;
		int s;
		char *addr;
		const char *port = strchr(args_spamdsocket, ':');
		if (port == NULL) {
			log_print(LOG_ERR, priv, "get_spamd_fd: no port number found in '%s' - check '-s' option", args_spamdsocket);
			return(-1);
		}

		addr = strndup(args_spamdsocket, /*lint -e(571)*/ (size_t)(port - args_spamdsocket));
		if (addr == NULL) {
			log_print(LOG_ERR, priv, "get_spamd_fd: strdup(len=%zi) failed: %s", port - args_spamdsocket, strerror(errno));
			return(-1);
		}
		port++;

		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;	/* allow both IPv4 and IPv6 (or IPv7... ;) */
		hints.ai_socktype = SOCK_STREAM /*lint --e(641) */;
		if ((s = getaddrinfo(addr, port, &hints, &ai)) != 0) {
			log_print(LOG_ERR, priv, "get_spamd_fd: getaddrinfo(%s:%s) failed: %s", addr, port, gai_strerror(s));
			free(addr);
			return(-1);
		}

		/* now connect to spamd */
		for (rp=ai; rp != NULL; rp = rp->ai_next) {
			fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
			if (fd == -1) continue;
			if (connect(fd, rp->ai_addr, rp->ai_addrlen) == -1) {
				log_print(LOG_DEBUG, priv, "get_spamd_fd: connect(%s:%s) failed: %s", addr, port, strerror(errno));
			} else {
				log_print(LOG_DEBUG, priv, "get_spamd_fd: connected to %s:%s", addr, port);
				break;	/* success */
			}
			close(fd);
		}

		if (rp == NULL) {
			log_print(LOG_ERR, priv, "get_spamd_fd: can't connect to %s:%s", addr, port);
			fd = -1;
		}

		free(addr);
		freeaddrinfo(ai);
	}

	return (fd);
}

/* ----------------------------------------------------------------------
 * sigalrm_handler()
 * Dummy handler for SIGALRM signal (during daemon startup)
 * ---------------------------------------------------------------------- */
static void sigalrm_handler(int s) {
	/* do nothing here... */
}

/* ----------------------------------------------------------------------
 * lcsam_connect()
 * Callback function - called when a new connection comes in
 * API: https://www.milter.org/developers/api/xxfi_connect
 * ---------------------------------------------------------------------- */
static sfsistat lcsam_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr) {
	struct lcsam_priv *priv;

	/* basically just allocate & initialize memory for private data, and copy SMTP peer
	 * information (hostname, address) into it */

	priv = calloc(1UL, sizeof(struct lcsam_priv));
	if (priv == NULL) {
		log_print(LOG_ERR, NULL, "lcsam_connect: calloc(%zi) failed: %s", sizeof(struct lcsam_priv), strerror(errno));
		return(SMFIS_ACCEPT);
	}
	priv->fd = -1;

	if (smfi_setpriv(ctx, priv) != MI_SUCCESS) {
		free(priv);
		log_print(LOG_ERR, NULL, "lcsam_connect: smfi_setpriv");
		return(SMFIS_ACCEPT);
	}

	/* copy hostname */
	strncpy(priv->hostname, hostname, sizeof(priv->hostname)-1);

	/* get & copy host address */
	strncpy(priv->hostaddr, "unknown", sizeof(priv->hostaddr)-1);	/* fallback / default */
	if (hostaddr != NULL) {
		switch (hostaddr->sa_family) {
			case AF_INET: {
				/*lint -e(740) */
				struct sockaddr_in *sin = (struct sockaddr_in *)hostaddr;
				if (inet_ntop(AF_INET, &sin->sin_addr.s_addr, priv->hostaddr, (unsigned int)sizeof(priv->hostaddr)-1) == NULL) {
					log_print(LOG_ERR, NULL, "lcsam_connect: inet_ntop: %s", strerror(errno));
				}
				break;
			}
			case AF_INET6: {
				/*lint -e(740,826) */
				struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)hostaddr;
				if (inet_ntop(AF_INET6, &sin6->sin6_addr, priv->hostaddr, (unsigned int)sizeof(priv->hostaddr)-1) == NULL) {
					log_print(LOG_ERR, NULL, "lcsam_connect: inet_ntop: %s", strerror(errno));
				}
				break;
			}
			default:
				/* unknown address type... ignore for now. */
				break;
		}
	}

	/* continue processing */
	return(SMFIS_CONTINUE);
}

/* ----------------------------------------------------------------------
 * lcsam_helo()
 * Callback function - called with HELO message
 * API: https://www.milter.org/developers/api/xxfi_help
 * ---------------------------------------------------------------------- */
static sfsistat lcsam_helo(SMFICTX *ctx, char *helohost) {
	struct lcsam_priv *priv;

	if ((priv = (struct lcsam_priv *)smfi_getpriv(ctx)) == NULL) {
		log_print(LOG_ERR, NULL, "lcsam_helo: smfi_getpriv");
		return(SMFIS_ACCEPT);
	}

	if (helohost == NULL) return(SMFIS_CONTINUE);

	if (priv->helo != NULL) {
		safe_free(priv->helo, 0L);
	}
	priv->helo = strdup(helohost);
	if (priv->helo == NULL) {
		log_print(LOG_ERR, NULL, "lcsam_helo: strdup(len=%zi) failed: %s", strlen(helohost)+1, strerror(errno));
		return(SMFIS_ACCEPT);
	}

	log_print(LOG_DEBUG, priv, "lcsam_helo('%s')", helohost);

	return (SMFIS_CONTINUE);
}

/* ----------------------------------------------------------------------
 * lcsam_envfrom()
 * Callback function - called with envelope from
 * API: https://www.milter.org/developers/api/xxfi_envfrom
 * ---------------------------------------------------------------------- */
static sfsistat lcsam_envfrom(SMFICTX *ctx, char **args) {
	struct lcsam_priv *priv;
	const char *str;

	if ((priv = (struct lcsam_priv *)smfi_getpriv(ctx)) == NULL) {
		log_print(LOG_ERR, NULL, "lcsam_envfrom: smfi_getpriv");
		return(SMFIS_ACCEPT);
	}

	/* reset most fields of private data (when delivering multiple messages
	 * within one connection) */
	if (priv->env_from != NULL)		{ safe_free(priv->env_from, 0L); priv->env_from = NULL; }
	if (priv->env_rcpt != NULL)		{ safe_free(priv->env_rcpt, 0L); priv->env_rcpt = NULL; }
	if (priv->hdr_from != NULL)		{ safe_free(priv->hdr_from, 0L); priv->hdr_from = NULL; }
	if (priv->hdr_messageid != NULL)		{ safe_free(priv->hdr_messageid, 0L); priv->hdr_messageid = NULL; }
	if (priv->hdr_to != NULL)		{ safe_free(priv->hdr_to, 0L); priv->hdr_to = NULL; }
	if (priv->hdr_subject != NULL)	{ safe_free(priv->hdr_subject, 0L); priv->hdr_subject = NULL; }
	if (priv->sendbuf != NULL)		{ safe_free(priv->sendbuf, priv->sendbufsize); priv->sendbuf = NULL; priv->sendbufsize = 0; }
	if (priv->fd >= 0)				{ close(priv->fd); priv->fd = -1; }
	priv->score = priv->warn = priv->reject = 0;
	priv->spam = priv->state = 0;
	priv->username[0] = priv->subjectprefix[0] = '\0';
	if (priv->report != NULL) {
		free(priv->report);
		priv->report = NULL;
		priv->report_len = 0;
	}

	if (args != NULL && args[0] != NULL) {
		log_print(LOG_DEBUG, priv, "lcsam_envfrom('%s')", args[0]);
		priv->env_from = strdup(args[0]);
	}

	/* check if we have an authenticated mail user: */
	str = smfi_getsymval(ctx, "{auth_authen}");
	if (str != NULL && *str != '\0') {
		priv->auth_sender = 1;
		if (args_scan_auth == 0) {
			/* accept mail without scanning */
			log_print(LOG_DEBUG, priv, "lcsam_envfrom('%s'): bypass spam check for authenticated user '%s'",
				args != NULL && args[0] != NULL ? args[0] : "(?)",
				str
				);
			return(SMFIS_ACCEPT);
		}
	}

	return (SMFIS_CONTINUE);
}

/* ----------------------------------------------------------------------
 * lcsam_envrcpt()
 * Callback function - called with each recipient
 * API: https://www.milter.org/developers/api/xxfi_envrcpt
 * ---------------------------------------------------------------------- */
static sfsistat lcsam_envrcpt(SMFICTX *ctx, char **args) {
	struct lcsam_priv *priv;

	if ((priv = (struct lcsam_priv *)smfi_getpriv(ctx)) == NULL) {
		log_print(LOG_ERR, NULL, "lcsam_envrcpt: smfi_getpriv");
		return(SMFIS_ACCEPT);
	}

	if (args != NULL && args[0] && priv->env_rcpt == NULL) {
		struct lookup_result lr;
		int ret;
		int i;

		/* copy recipient
		 * args[0] contains eg. "<info@example.org>", while symbol {rcpt_addr} contains "info@example.org" (without brackets) */
		const char *rcpt_addr = smfi_getsymval(ctx, "{rcpt_addr}");
		if (rcpt_addr == NULL) {
			log_print(LOG_ERR, NULL, "lcsam_envrcpt: no recipient address in {rcpt_addr}");
			return(SMFIS_ACCEPT);
		}
		priv->env_rcpt = strdup(rcpt_addr);
		if (priv->env_rcpt == NULL) {
			log_print(LOG_ERR, NULL, "lcsam_envrcpt: strdup(len=%zi) failed: %s", strlen(rcpt_addr)+1, strerror(errno));
			return(SMFIS_ACCEPT);
		}
		log_print(LOG_DEBUG, priv, "lcsam_envrcpt('%s')", rcpt_addr);

		/* make address lowercase before performing a database lookup */
		for (i=(int)strlen(priv->env_rcpt)-1; i>=0; i--) priv->env_rcpt[i] = (char)tolower(priv->env_rcpt[i]);

		/* lookup individual spam thresholds */
		ret = lookup_prefs(NULL, rcpt_addr, &lr);
		if (ret == -2) {
			/* not found */
			if (args_scan_auth == 0 || priv->auth_sender == 0) {
				/* don't scan message (no preferences found, or outgoing e-mail) */
				return(SMFIS_ACCEPT);
			}

			/* scan outgoing e-mail:
			 * use some "high" settings - blocking should be done later using the appropriate headers */
			priv->warn = args_scan_auth_score;
			priv->reject = args_scan_auth_score;
			priv->subjectprefix[0] = '\0';
			return(SMFIS_CONTINUE);
		} else if (ret != 0) {
			/* error (exact reason logged by lookup_prefs()) */
			return(SMFIS_ACCEPT);
		}
		priv->warn = lr.warn_score;
		priv->reject = lr.reject_score;
		strncpy(priv->subjectprefix, lr.subjectprefix, sizeof(priv->subjectprefix)-1);
		priv->subjectprefix[sizeof(priv->subjectprefix)-1] = '\0';
		strncpy(priv->username, lr.userid, sizeof(priv->username)-1);
		priv->username[sizeof(priv->username)-1] = '\0';
	}

	return (SMFIS_CONTINUE);
}

/* ----------------------------------------------------------------------
 * lcsam_header()
 * Callback function - called for each message header
 * API: https://www.milter.org/developers/api/xxfi_header
 * ---------------------------------------------------------------------- */
static sfsistat lcsam_header(SMFICTX *ctx, char *name, char *value) {
	struct lcsam_priv *priv;

	if ((priv = (struct lcsam_priv *)smfi_getpriv(ctx)) == NULL) {
		log_print(LOG_ERR, NULL, "lcsam_header: smfi_getpriv");
		return(SMFIS_ACCEPT);
	}

	log_print(LOG_DEBUG, priv, "lcsam_header('%s', '%s')", name, value);

	if (priv->fd < 0) {
		const char *sendmail_name = smfi_getsymval(ctx, "j");
		const char *sendmail_queue = smfi_getsymval(ctx, "i");
		const char *sendmail_date = smfi_getsymval(ctx, "b");
		const char *auth_type = smfi_getsymval(ctx, "{auth_type}");
		const char *auth_ssf = smfi_getsymval(ctx, "{auth_ssf}");

		if ((priv->fd = get_spamd_fd(priv)) < 0) {
			/* connection to SpamAssassin failed - accept mail by default */
			return (SMFIS_ACCEPT);
		}

		/* send protocol header */
		if (args_report) {
			fdprintf(priv, "REPORT SPAMC/1.2\r\n");
		} else {
			fdprintf(priv, "SYMBOLS SPAMC/1.2\r\n");
		}

		if (priv->username[0] != '\0') {
			fdprintf(priv, "User: %s\r\n", priv->username);
		}

		fdprintf(priv, "\r\n");

		if (priv->env_from != NULL) {
			/* send Envelope-From */
			fdprintf(priv, "Return-Path: %s\r\n", priv->env_from);
		}

		/* send fake Received: header */
		fdprintf(priv, "Received: from %s (%s [%s])",
		    priv->helo, priv->hostname, priv->hostaddr);
		if (auth_type != NULL && auth_type[0] != 0) {
			fdprintf(priv, "\r\n\t(authenticated");
			if (auth_ssf != NULL && auth_ssf[0] != 0) {
				fdprintf(priv, " bits=%s", auth_ssf);
			}
			fdprintf(priv, ")");
		}
		if (sendmail_name != NULL && sendmail_name[0] != 0) {
			fdprintf(priv, "\r\n\tby %s (lcsam)", sendmail_name);
			if (sendmail_queue != NULL && sendmail_queue[0]) {
				fdprintf(priv, " id %s", sendmail_queue);
			}
		}
		if (priv->env_rcpt != NULL && priv->env_rcpt[0] != '\0') {
			fdprintf(priv, "\r\n\tfor %s", priv->env_rcpt);
		}
		if (sendmail_date != NULL && sendmail_date[0] != '\0') {
			fdprintf(priv, "; %s", sendmail_date);
		}
		else {
			char d[128];
			time_t t = time(NULL);

			if (strftime(d, sizeof(d), "%a, %e %b %Y %H:%M:%S %z", localtime(&t))) {
				fdprintf(priv, "; %s", d);
			}
		}
		fdprintf(priv, "\r\n");
	}
	fdprintf(priv, "%s: %s\r\n", name, value);
	if (strcasecmp(name, "From") == 0 && priv->hdr_from == 0) {
		priv->hdr_from = strdup(value);
		if (priv->hdr_from == NULL) goto TEMPFAIL;
	} else if (strcasecmp(name, "To") == 0) {
		priv->hdr_to = strdup(value);
		if (priv->hdr_to == NULL) goto TEMPFAIL;
	} else if (strcasecmp(name, "Message-ID") == 0) {
		priv->hdr_messageid = strdup(value);
		if (priv->hdr_messageid == NULL) goto TEMPFAIL;
	} else if (strcasecmp(name, "Subject") == 0) {
		priv->hdr_subject = strdup(value);
		if (priv->hdr_subject == NULL) goto TEMPFAIL;
	}
	return(SMFIS_CONTINUE);

TEMPFAIL:
	/* out of memory!? */
	log_print(LOG_ERR, NULL, "lcsam_header: strdup(%s/len=%zi) failed: %s", name, strlen(value)+1, strerror(errno));
	return(SMFIS_TEMPFAIL);

}

/* ----------------------------------------------------------------------
 * lcsam_eoh()
 * Callback function - called after all headers have been sent
 * API: https://www.milter.org/developers/api/xxfi_eoh
 * ---------------------------------------------------------------------- */
static sfsistat lcsam_eoh(SMFICTX *ctx) {
	struct lcsam_priv *priv;

	if ((priv = (struct lcsam_priv *)smfi_getpriv(ctx)) == NULL) {
		log_print(LOG_ERR, NULL, "lcsam_eoh: smfi_getpriv");
		return(SMFIS_ACCEPT);
	}

	log_print(LOG_DEBUG, priv, "lcsam_eoh()");
	if (priv->fd >= 0) fdprintf(priv, "\r\n");

	return (SMFIS_CONTINUE);
}

/* ----------------------------------------------------------------------
 * lcsam_body()
 * Callback function - called with body data
 * API: https://www.milter.org/developers/api/xxfi_body
 * ---------------------------------------------------------------------- */
static sfsistat lcsam_body(SMFICTX *ctx, u_char *chunk, size_t size) {
	struct lcsam_priv *priv;

	if ((priv = (struct lcsam_priv *)smfi_getpriv(ctx)) == NULL) {
		log_print(LOG_ERR, NULL, "lcsam_body: smfi_getpriv");
		return(SMFIS_ACCEPT);
	}

	if (priv->fd == -1) {
		/* if we have no SpamAssassin fd here, something strange must have happened.
		 * So just accept the mail. */
		return(SMFIS_ACCEPT);
	}

	/* copy complete body 1:1 to SpamAssassin */
	while (write(priv->fd, chunk, size) == -1) {
		if (errno == EINTR) continue;
		log_print(LOG_ERR, priv, "write(len=%zi) failed: %s", size, strerror(errno));
		return(SMFIS_ACCEPT);
	}

	return (SMFIS_CONTINUE);
}

/* ----------------------------------------------------------------------
 * spamd_reply()
 * Parse spamd response
 * API: https://svn.apache.org/repos/asf/spamassassin/trunk/spamd/PROTOCOL
 * ---------------------------------------------------------------------- */
static void spamd_reply(const char *line, struct lcsam_priv *priv, sfsistat *action) {
	const char *p;
	size_t len, line_len;

	switch (priv->state) {
		case 0:
			/* parse first response line */
			if (strncmp(line, "SPAMD/", 6L) != 0) {
				log_print(LOG_ERR, priv, "spamd_reply: first reply not SPAMD version: %s", line);
				*action = SMFIS_ACCEPT;
				break;
			}
			p = line + 6;
			while (*p && *p != ' ') p++;
			while (*p == ' ') p++;
			if (strncmp(p, "0 EX_OK", 7L)) {
				log_print(LOG_ERR, priv, "spamd_reply: first reply not 0 EX_OK: %s", line);
				*action = SMFIS_ACCEPT;
				break;
			}
			priv->state = 1;
			break;
		case 1:
			/* parse response header line(s) */
			if (strncmp(line, "Spam: ", 6L) == 0) {
				char decision[16];
				float score, threshold;
				/* threshold is actually ignored, decision is based on individual settings in user map */

				if (sscanf(line + 6, "%15s ; %f / %f", decision, &score, &threshold) != 3) {
					log_print(LOG_ERR, priv, "spamd_reply: malformed decision reply: %s", line);
					*action = SMFIS_ACCEPT;
					break;
				}
				priv->spam = score >= priv->warn ? 1 : 0;
				priv->score = score;
				priv->state = 2;
			}
			break;
		case 2:
			/* wait for "end-of-header" separator */
			if (line[0] == '\0') priv->state = 3;
			break;
		case 3:
			/* parse content; here: SpamAssassin report OR list of matched SpamAssassin rules */
			if (line == NULL) break;
			line_len = strlen(line);
			if ((priv->report_len == 0) || priv->report_len - strlen(priv->report) < line_len + 3) {	/* plus 3 bytes: \r\n and \0 */
				/* allocate/grow report buffer */
				size_t grow = line_len + 3;
				if (grow < 1024) grow = 1024;
				size_t sz = priv->report_len + grow;
				char *tmp = (char*)realloc(priv->report, sz);
				if (tmp == NULL) {
					/* out of memory! */
					log_print(LOG_ERR, priv, "spamd_reply: out of memory while reallocating %zi bytes", sz);
					*action = SMFIS_ACCEPT;
					break;
				}
				memset(tmp + priv->report_len, 0, grow);	/* clear new memory */
				priv->report = tmp;
				priv->report_len = sz;
			}
			len = strlen(priv->report);
			if (*priv->report != '\0') {
				/* add linebreak (for multi-line responses) */
				memcpy(priv->report + len, "\r\n\0", 3);
				len+=2;
			}
			memcpy(priv->report + len, line, line_len);
			priv->report[len+line_len] = '\0';	/* add terminating \0 */
			break;
		default:
			log_print(LOG_ERR, priv, "spamd_reply: invalid parse state");
			*action = SMFIS_ACCEPT;
	}
}

/* ----------------------------------------------------------------------
 * lcsam_eom()
 * Callback function - called after all body chunks have been sent
 * API: https://www.milter.org/developers/api/xxfi_eom
 * ---------------------------------------------------------------------- */
static sfsistat lcsam_eom(SMFICTX *ctx) {
	struct lcsam_priv *priv;
	sfsistat action = SMFIS_CONTINUE;
	char buf[2048];
	int pos = 0, retry = 0;

	if ((priv = (struct lcsam_priv *)smfi_getpriv(ctx)) == NULL) {
		log_print(LOG_ERR, NULL, "lcsam_eom: smfi_getpriv");
		return(SMFIS_ACCEPT);
	}

	log_print(LOG_DEBUG, priv, "lcsam_eom()");
	if (priv->fd < 0) goto DONE;

	/* no more writing data to spamd, want to read result now */
	if (shutdown(priv->fd, SHUT_WR)) {
		log_print(LOG_ERR, priv, "lcsam_eom: shutdown: %s", strerror(errno));
		goto DONE;
	}

	/* set spamd connection socket to non-blocking, to allow time-out while reading from it */
	if (fcntl(priv->fd, F_SETFL, fcntl(priv->fd, F_GETFL) | O_NONBLOCK)) {
		log_print(LOG_ERR, priv, "lcsam_eom: fcntl: %s", strerror(errno));
		goto DONE;
	}

	/* try at most 6 times (10 seconds timeout each) */
	while (action == SMFIS_CONTINUE && retry < 6) {
		fd_set fds;
		struct timeval tv;
		int i;
		long r;
		char b[8192];

		FD_ZERO(&fds);
		FD_SET(priv->fd, &fds);
		tv.tv_sec = 10;
		tv.tv_usec = 0;
		while ((r = select(priv->fd + 1, &fds, NULL, NULL, &tv)) < 0) {
			if (errno == EINTR) continue;
			log_print(LOG_ERR, priv, "lcsam_eom: select: %s", strerror(errno));
			break;
		}

		if (r < 0) {
			break;
		} else if (r == 0 || !FD_ISSET(priv->fd, &fds)) {
			retry++;
			log_print(LOG_DEBUG, priv, "lcsam_eom: waiting for spamd reply (retry %d)", retry);
			continue;
		}

		r = read(priv->fd, b, sizeof(b));
		if (r < 0) {
			if (errno != EINTR) {
				log_print(LOG_ERR, priv, "lcsam_eom: read: %s", strerror(errno));
				break;
			}
			continue;
		} else if (r == 0) {
			/* connection closed by spamd */
			break;
		}
		for (i = 0; i < r; i++) {
			if (b[i] == '\n' || pos == (int)sizeof(buf) - 1) {
				if (pos > 0 && /*lint -e(530) */ buf[pos - 1] == '\r') {
					buf[pos - 1] = 0;
				} else {
					buf[pos] = 0;
				}
				/* sets action when done */
				spamd_reply(buf, priv, &action);
				pos = 0;
			} else {
				buf[pos++] = b[i];
			}
		}
	}
	if (retry == 6) {
		log_print(LOG_ERR, priv, "lcsam_eom: spamd connection timed out");
	}
DONE:
	if (priv->fd >= 0) {
		close(priv->fd);
		priv->fd = -1;
	}
	/* either way, we don't want to continue */
	if (action == SMFIS_CONTINUE)
		action = priv->score >= priv->reject ? SMFIS_REJECT : SMFIS_ACCEPT;
	log_print(action == SMFIS_REJECT ? LOG_NOTICE : LOG_INFO, priv,
	    "%s (%s %.1f/%.1f/%.1f%s%s), From: %s, To: %s, MessageID: %s, Subject: %s",
	    (action == SMFIS_REJECT ? "REJECT" : "ACCEPT"),
	    (priv->spam ? "SPAM" : "ham"), priv->score, priv->reject, priv->warn,
	    (args_report == 0 && priv->report != NULL ? " " :  ""), (args_report == 0 && priv->report != NULL ? priv->report : ""),
	    priv->hdr_from, priv->hdr_to, priv->hdr_messageid, priv->hdr_subject);
	if (action == SMFIS_REJECT) {
		if (smfi_setreply(ctx, RCODE_REJECT, XCODE_REJECT, MSG_REJECT) != MI_SUCCESS) {
			log_print(LOG_ERR, priv, "lcsam_eom: smfi_setreply");
		}
	} else {
		char m[512];

		/* add/replace "X-Spam-Flag:" header */
		if (smfi_chgheader(ctx, "X-Spam-Flag", 1, priv->spam ? "YES" : "NO") != MI_SUCCESS) {
			log_print(LOG_ERR, priv, "lcsam_eom: smfi_chgheader(X-Spam-Flag)");
		}

		/* add "X-Spam-Score:" header */
		snprintf(m, sizeof(m), "%.1f", priv->score);
		if (smfi_chgheader(ctx, "X-Spam-Score", 1, m) != MI_SUCCESS) {
			log_print(LOG_ERR, priv, "lcsam_eom: smfi_chgheader(X-Spam-Score)");
		}

		/* add "X-Spam-Status:" header */
		if (args_report) {
			/* no symbols available, we have a full report below */
			snprintf(m, sizeof(m), "%s score=%.1f tagged_above=%.1f required=%.1f",
				priv->spam ? "Yes" : "No", priv->score, priv->warn, priv->reject);
		} else {
			snprintf(m, sizeof(m), "%s score=%.1f tagged_above=%.1f required=%.1f tests=[%s]",
				priv->spam ? "Yes" : "No", priv->score, priv->warn, priv->reject, priv->report);
		}
		if (smfi_chgheader(ctx, "X-Spam-Status", 1, m) != MI_SUCCESS) {
			log_print(LOG_ERR, priv, "lcsam_eom: smfi_chgheader(X-Spam-Status)");
		}

		if (args_report && priv->report != NULL) {
			/* add "X-Spam-Report:" header */
			char *readpos, *writepos, *cr;
			size_t space_left = sizeof(buf);
			size_t line_length;

			readpos = priv->report;
			writepos = buf;
			for (;;) {
				cr = strchr(readpos, '\n');
				if (cr == NULL) cr = readpos + strlen(readpos);
				line_length = cr - readpos;
				if (line_length == 0 || space_left <= 4) {
					*writepos = '\0';
					break;
				}
				if (*cr == '\n' && cr > readpos && *(cr-1) == '\r') line_length--;
				if (writepos > buf) {
					/* fold line */
					memcpy(writepos, "\r\n\t", 3UL);
					writepos += 3;
					space_left -= 3;
				}
				if (space_left <= line_length) {
					line_length = space_left - 1;
				}
				memcpy(writepos, readpos, line_length);
				writepos += line_length;
				space_left -= line_length;
				readpos = cr + 1;
				if (*cr == '\0') {
					*writepos = '\0';
					break;
				}
			}

			if (smfi_chgheader(ctx, "X-Spam-Report", 1, buf) != MI_SUCCESS) {
				log_print(LOG_ERR, priv, "lcsam_eom: smfi_chgheader(X-Spam-Report)");
			}
		}

		/* eventually modify subject */
		if (priv->score >= priv->warn && priv->subjectprefix[0] != '\0') {
			int ret;
			if (priv->hdr_subject == NULL) {
				/* no subject... add header */
				ret = smfi_chgheader(ctx, "Subject", 1, priv->subjectprefix);
			} else {
				size_t sz = strlen(priv->hdr_subject) + strlen(priv->subjectprefix) + 5;	/* 5 = whitespace + CR + LF + whitespace + '\0' */
				char *sbuf = (char*)malloc(sz);
				if (sbuf == NULL) {
					log_print(LOG_ERR, priv, "lcsam_eom: malloc(%zi) failed", sz);
					ret = MI_SUCCESS;
				} else {
					/* fold if longer than 998 chars; (9 = "Subject: ") */
					snprintf(sbuf, sz-1, "%s %s%s", priv->subjectprefix, sz + 9 < 998 ? "" : " \r\n ", priv->hdr_subject);
					sbuf[sz-1]='\0';
					ret = smfi_chgheader(ctx, "Subject", 1, sbuf);
					free(sbuf);
				}
			}
			if (ret != MI_SUCCESS) {
				/* header can't be modified.
				 * Warn, but continue as normal */
				log_print(LOG_WARNING, priv, "lcsam_eom: smfi_chgheader(subject) failed");
			}
		}

	}

	return(action);
}

/* ----------------------------------------------------------------------
 * lcsam_abort()
 * Callback function - called when processing of a message is aborted
 * API: https://www.milter.org/developers/api/xxfi_abort
 * ---------------------------------------------------------------------- */
static sfsistat lcsam_abort(SMFICTX *ctx) {
	struct lcsam_priv *priv;

	if ((priv = (struct lcsam_priv *)smfi_getpriv(ctx)) == NULL) {
		log_print(LOG_ERR, NULL, "lcsam_abort: smfi_getpriv");
		return(SMFIS_ACCEPT);
	}

	log_print(LOG_DEBUG, priv, "lcsam_abort()");

	if (priv->helo != NULL)			safe_free(priv->helo, 0L);
	if (priv->env_from != NULL)		safe_free(priv->env_from, 0L);
	if (priv->env_rcpt != NULL)		safe_free(priv->env_rcpt, 0L);
	if (priv->hdr_messageid != NULL)		safe_free(priv->hdr_messageid, 0L);
	if (priv->hdr_from != NULL)		safe_free(priv->hdr_from, 0L);
	if (priv->hdr_to != NULL)		safe_free(priv->hdr_to, 0L);
	if (priv->hdr_subject != NULL)	safe_free(priv->hdr_subject, 0L);
	if (priv->fd >= 0)				close(priv->fd);
	if (priv->sendbuf != NULL)		safe_free(priv->sendbuf, priv->sendbufsize);
	if (priv->report != NULL)		free(priv->report);
	memset(priv, 0, sizeof(struct lcsam_priv));
	priv->fd = -1;

	return (SMFIS_CONTINUE);
}

/* ----------------------------------------------------------------------
 * lcsam_close()
 * Callback function - called when a connection is closed (clean up)
 * ---------------------------------------------------------------------- */
static sfsistat lcsam_close(SMFICTX *ctx) {

	struct lcsam_priv *priv;

	priv = (struct lcsam_priv *)smfi_getpriv(ctx);
	log_print(LOG_DEBUG, priv, "lcsam_close()");
	if (priv != NULL) {
		smfi_setpriv(ctx, NULL);

		if (priv->helo != NULL)			safe_free(priv->helo, 0L);
		if (priv->env_from != NULL)		safe_free(priv->env_from, 0L);
		if (priv->env_rcpt != NULL)		safe_free(priv->env_rcpt, 0L);
		if (priv->hdr_messageid != NULL)		safe_free(priv->hdr_messageid, 0L);
		if (priv->hdr_from != NULL)		safe_free(priv->hdr_from, 0L);
		if (priv->hdr_to != NULL)		safe_free(priv->hdr_to, 0L);
		if (priv->hdr_subject != NULL)	safe_free(priv->hdr_subject, 0L);
		if (priv->fd >= 0)				close(priv->fd);
		if (priv->sendbuf != NULL)		safe_free(priv->sendbuf, priv->sendbufsize);
		if (priv->report != NULL)		free(priv->report);

		memset(priv, 0, sizeof(struct lcsam_priv));
		priv->fd = -1;
		free(priv);
	}

	/* continue processing */
	return(SMFIS_CONTINUE);
}

static const struct smfiDesc smfilter = {
	"lcsam",		/* filter name */
	SMFI_VERSION,	/* version code -- do not change */
	SMFIF_ADDHDRS | SMFIF_CHGHDRS,	/* flags: may add headers, may change headers */
	lcsam_connect,	/* connection info filter */
	lcsam_helo,		/* SMTP HELO command filter */
	lcsam_envfrom,	/* envelope sender filter */
	lcsam_envrcpt,	/* envelope recipient filter */
	lcsam_header,	/* header filter */
	lcsam_eoh,		/* end of header */
	lcsam_body,		/* body block */
	lcsam_eom,		/* end of message */
	lcsam_abort,	/* message aborted */
	lcsam_close,	/* connection cleanup */
#if (SMFI_PROT_VERSION >= 4)
	NULL,			/* any unrecognized or unimplemented command filter */
	NULL,			/* SMTP DATA command filter */
	NULL			/* negotiation callback */
#endif
};

int main(int argc, char* const* argv) {
	int ret = EX_OK;
	int i;

	switch (args_parse(argc, argv)) {
		case ARGS_OK:
			break;
		case ARGS_ERROR:
			return(EX_USAGE);
		case ARGS_HELP:
			print_help();
			return(EX_OK);
	}

	/* safe program initialization */
	if (safety_first() != 0) {
		return(EX_OSERR);
	}

	tzset();
	openlog("lcsam", LOG_PID | LOG_NDELAY, LOG_MAIL);

	if (args_debug) {
		printf("Running in debug mode (staying in foreground)\n");
	}

	if (smfi_setconn((char *)args_commsocket) != MI_SUCCESS) {
		fprintf(stderr, "smfi_setconn: %s: failed\n", args_commsocket);
		goto CLEANUP;
	}

	if (smfi_register(smfilter) != MI_SUCCESS) {
		fprintf(stderr, "smfi_register: failed\n");
		goto CLEANUP;
	}

	/* create PID file */
	if (pid_create(args_pidfile) != 0) {
		goto CLEANUP;
	}

	/* try to create socket */
	if (smfi_opensocket(1) != MI_SUCCESS) {
		log_print(LOG_ERR, NULL, "smfi_opensocket failed\n");
		goto CLEANUP;
	}

	/* eventually adjust owner of UNIX domain socket */
	if (strncmp(args_commsocket, "unix:", 5UL) == 0 || strncmp(args_commsocket, "local:", 6UL) == 0) {
		struct passwd *spw;
		struct group *sgr;
		const char *sockfile = strchr(args_commsocket, ':') + 1 /*lint --e(613) */;

		if ((spw = getpwnam(args_sock_user)) == NULL) {
			log_print(LOG_ERR, NULL, "can't get id of user '%s': %s (use option '-U'!)", args_sock_user, strerror(errno));
			goto CLEANUP;
		}
		if ((sgr = getgrnam(args_sock_group)) == NULL) {
			log_print(LOG_ERR, NULL, "can't get id of group '%s': %s (use option '-G'!)", args_sock_group, strerror(errno));
			goto CLEANUP;
		}

		if (chown(sockfile, spw->pw_uid, sgr->gr_gid) != 0) {
			log_print(LOG_ERR, NULL, "can't adjust owner of '%s' to '%s:%s': %s", sockfile, args_sock_user, args_sock_group, strerror(errno));
			goto CLEANUP;
		}
	}

	/* drop privileges / change user */
	if (getuid() == 0) {
		/* we're root :) */
		if (safety_user_change(0, args_user, args_group) != 0) {
			goto CLEANUP;
		}
	}

	if (args_debug == 0) {
		/* fork into background */

		void (*sigalrm_orig)(int);
		int i;

		/* systemd reads the PID file as soon as the parent process is terminated.
		 * But we write the "real" PID of the daemon process after fork(), so we force the parent
		 * process to wait some time (and wake it up with SIGALRM once the daemon is ready)
		 *
		 * The signal handler for SIGALRM must be installed *before* fork().
		 * Otherwise if the child process is "faster" sending a SIGALRM than the parent installing a handler,
		 * the process would die.
		 */
		sigalrm_orig = signal(SIGALRM, sigalrm_handler);
		if (sigalrm_orig == SIG_ERR) {
			log_print(LOG_ERR, NULL, "signal() failed: %s", strerror(errno));
			/* continue anyway... */
		}

		i = fork();

		if (i < 0) {
			/* fork() failed */
			log_print(LOG_ERR, NULL, "can't fork into background: %s", strerror(errno));
			goto CLEANUP;
		} else if (i > 0) {
			/* parent process */
			pid_close();

			/* sleep up to 5 seconds. Parent process will send us an SIGALRM once the PID file has been updated, so we can quit cleanly. */
			sleep(5);

			exit(EX_OK);
		}

		/* restore original SIGALRM handler in child process */
		signal(SIGALRM, sigalrm_orig);

		/* become session leader */
		setsid();

		/* change working directory */
		if (chdir("/") != 0) {
			log_print(LOG_WARNING, NULL, "chdir(/) failed: %s", strerror(errno));
		}

		/* now fork again */
		if (fork() > 0) {
			/* parent process */
			exit(EX_OK);
		}

		if (pid_update() != 0) {
			/* error while updating PID file - better abort... */
			goto CLEANUP;
		}

		/* try to re-open STDIN, STDOUT and STDERR with /dev/null */
		i = open(_PATH_DEVNULL, O_WRONLY | O_APPEND | O_CREAT, 0644);
		if (i >= 0) {
			dup2(i, STDIN_FILENO);
			dup2(i, STDOUT_FILENO);
			dup2(i, STDERR_FILENO);
			close(i);
		}

	}

	/* main loop */
	log_print(LOG_INFO, NULL, "LiveConfig SpamAssassin Milter (lcsam) started");
	i = smfi_main();
	if (i != MI_SUCCESS) {
		log_print(LOG_ERR, NULL, "smfi_main: terminating due to error");
		ret = 1;
	} else {
		log_print(LOG_INFO, NULL, "smfi_main: terminating without error");
	}

	/* close database, clean up handler */
	lookup_close();

CLEANUP:

	if (getuid() == 0) {
		/* restore root permissions to delete PID file */
		(void)safety_user_restore();
	}

	pid_remove(args_pidfile);

	closelog();

	return(ret);
}

/* <EOF> ------------------------------------------------------------------ */
