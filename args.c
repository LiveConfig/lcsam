/*  _    _          ___           __ _     (R)
 * | |  (_)_ _____ / __|___ _ _  / _(_)__ _
 * | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
 * |____|_|\_/\___|\___\___/_||_|_| |_\__, |
 *                                    |___/
 * lcsam - LiveConfig SpamAssassin Milter
 */

/* PC-Lint options */
/*lint -e793 / ANSI/ISO limit of 31 'significant characters in an external identifier' */
/*lint -esym(459, args_debug, args_commsocket, args_spamdsocket) */

#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>

#include "args.h"

/* flag to set debug mode (run in foreground, show debug messages to STDOUT) */
int args_debug = 0;

/* also scan (outgoing) mails from SASL authenticated users */
int args_scan_auth = 0;

/* name of unix pipe or address of socket to accept incoming connections at */
const char *args_commsocket = "unix:/var/run/lcsam.sock";

/* location of PID file */
const char *args_pidfile = "/var/run/lcsam.pid";

/* address of SpamAssassin 'spamd' socket to connect to */
const char *args_spamdsocket = "/var/run/spamd.sock";

/* database file containing the per-user spamassassin preferences */
const char *args_usermap = "/etc/postfix/spamassassin.db";

/* user to run lcsam as */
const char *args_user = "nobody";

/* group to run lcsam as */
const char *args_group = "nogroup";

/* owner (user) of the UNIX domain socket */
const char *args_sock_user = "mail";

/* owner (group) of the UNIX domain socket */
const char *args_sock_group = "mail";

/* ----------------------------------------------------------------------
 * args_parse()
 * parse command-line arguments
 * ---------------------------------------------------------------------- */
args_t args_parse(int argc, char* const* argv) {
	int c;

	while ((c = getopt(argc, argv, "ac:dg:G:hm:p:s:u:U:")) != -1) {
		switch(c) {
			case 'a':
				args_scan_auth = 1;
				break;
			case 'c':
				args_commsocket = optarg;
				break;
			case 'd':
				args_debug = 1;
				break;
			case 'g':
				args_group = optarg;
				break;
			case 'G':
				args_sock_group = optarg;
				break;
			case 'h':
				return ARGS_HELP;
			case 'm':
				args_usermap = optarg;
				break;
			case 'p':
				args_pidfile = optarg;
				break;
			case 's':
				if (optarg[0] != '/' && strchr(optarg, ':') == NULL) {
					fprintf(stderr, "Option '-s' requires a socket filename (eg. '-s /var/run/spamd.sock') or an ip address / hostname and port (eg. '-s 127.0.0.1:783')\n");
					return(ARGS_ERROR);
				}
				args_spamdsocket = optarg;
				break;
			case 'u':
				args_user = optarg;
				break;
			case 'U':
				args_sock_user = optarg;
				break;
			case '?':
				switch(optopt) {
					case 'c':
						fprintf(stderr, "Option '-%c' needs an argument.\n", optopt);
						break;
					default:
						if (isprint(optopt)) {
							fprintf(stderr, "Unknown option '-%c'.\n", optopt);
						} else {
							fprintf(stderr, "Unknown option character '\\x%x'.\n", optopt);
						}
				}
				return(ARGS_ERROR);
			default:
				if (isprint(optopt)) {
					fprintf(stderr, "Unknown option '-%c'.\n", c);
				} else {
					fprintf(stderr, "Unknown option character '\\x%x'.\n", c);
				}
				return(ARGS_ERROR);
		}
	}

	return(ARGS_OK);
} /* args_parse(); */

/* <EOF> ------------------------------------------------------------------ */
