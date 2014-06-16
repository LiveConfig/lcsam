/*  _    _          ___           __ _     (R)
 * | |  (_)_ _____ / __|___ _ _  / _(_)__ _
 * | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
 * |____|_|\_/\___|\___\___/_||_|_| |_\__, |
 *                                    |___/
 * lcsam - LiveConfig SpamAssassin Milter
 */

#ifndef __LCSAM_LOG_H
#define __LCSAM_LOG_H

void log_print(int priority, struct lcsam_priv *priv, const char *fmt, ...)
#if defined(__GNUC__) && __GNUC__ >= 4
			__attribute__ (( format( __printf__, 3, 4 )))
#endif
	;

#endif /* __LCSAM_LOG_H */
