/*  _    _          ___           __ _     (R)
 * | |  (_)_ _____ / __|___ _ _  / _(_)__ _
 * | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
 * |____|_|\_/\___|\___\___/_||_|_| |_\__, |
 *                                    |___/
 * lcsam - LiveConfig SpamAssassin Milter
 */

#ifndef __LCSAM_LOOKUP_H
#define __LCSAM_LOOKUP_H

struct lookup_result {
	float	warn_score;
	float	reject_score;
	int		action;
	char	userid[65];
	char	subjectprefix[128];
};

int lookup_prefs(struct lcsam_priv *priv, const char *addr, struct lookup_result *res);
void lookup_close(void);

#endif /* __LCSAM_LOOKUP_H */
