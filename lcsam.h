/*  _    _          ___           __ _     (R)
 * | |  (_)_ _____ / __|___ _ _  / _(_)__ _
 * | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
 * |____|_|\_/\___|\___\___/_||_|_| |_\__, |
 *                                    |___/
 * lcsam - LiveConfig SpamAssassin Milter
 */

#ifndef __LCSAM_H
#define __LCSAM_H

struct lcsam_priv {
	char		hostname[128];
	char		hostaddr[64];
	char		*helo;
	char		*env_rcpt;
	char		*hdr_from;
	char		*hdr_to;
	char		*hdr_messageid;
	char		*hdr_subject;
	int			fd;					/* file handle to SpamAssassin (-1 when closed or not initialized) */
	char		username[65];		/* part of path to user preferences (eg. "web100_23" for "/var/lib/spamassassin/%u/") */
	char		*sendbuf;
	size_t		sendbufsize;
	int			spam;				/* flag if this is a spam mail and should be rejected */
	char		subjectprefix[128];	/* subject prefix to be inserted when score >= warn */
	float		score, warn, reject;	/* actual score and warn/reject thresholds */
	char		*report;			/* SpamAssassin report (REPORT) or list of matched symbols (SYMBOLS) */
	size_t		report_len;			/* size of report buffer */
	int			state;
	char		auth_sender;		/* "1" if sender is SASL-authenticated, else "0" */
};

#endif /* __LCSAM_H */
