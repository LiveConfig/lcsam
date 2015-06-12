/*  _    _          ___           __ _     (R)
 * | |  (_)_ _____ / __|___ _ _  / _(_)__ _
 * | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
 * |____|_|\_/\___|\___\___/_||_|_| |_\__, |
 *                                    |___/
 * lcsam - LiveConfig SpamAssassin Milter
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>

#include "lcsam.h"
#include "args.h"
#include "log.h"

/* ----------------------------------------------------------------------
 * log()
 * write log message to either syslog or to console (when in debug mode)
 * ---------------------------------------------------------------------- */
void log_print(int priority, struct lcsam_priv *priv, const char *fmt, ...) {
	va_list ap;
	char msg[4096];

	/* discard all LOG_DEBUG messages unless we're running in debug mode */
	if (priority >= LOG_DEBUG && !args_debug) return;

	va_start(ap, fmt);
	if (priv != NULL) {
		snprintf(msg, sizeof(msg), "%s: ", priv->hostaddr);
	} else {
		msg[0] = 0;
	}
	vsnprintf(msg + strlen(msg), sizeof(msg) - strlen(msg), fmt, ap);
	if (args_debug) {
		printf("syslog: %s\n", msg);
	} else {
		syslog(priority, "%s", msg);
	}
	va_end(ap);
}

/* <EOF> ------------------------------------------------------------------ */
