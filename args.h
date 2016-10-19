/*  _    _          ___           __ _     (R)
 * | |  (_)_ _____ / __|___ _ _  / _(_)__ _
 * | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
 * |____|_|\_/\___|\___\___/_||_|_| |_\__, |
 *                                    |___/
 * lcsam - LiveConfig SpamAssassin Milter
 */

#ifndef __LCSAM_ARGS_H
#define __LCSAM_ARGS_H

typedef enum {
	ARGS_OK,
	ARGS_ERROR,
	ARGS_HELP
} args_t;

extern int args_debug;
extern int args_scan_auth;
extern const char *args_commsocket;
extern const char *args_pidfile;
extern const char *args_spamdsocket;
extern const char *args_usermap;
extern const char *args_user;
extern const char *args_group;
extern const char *args_sock_user;
extern const char *args_sock_group;

args_t args_parse(int argc, char* const* argv);

#endif /* __LCSAM_ARGS_H */
