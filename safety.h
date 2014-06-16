/*  _    _          ___           __ _     (R)
 * | |  (_)_ _____ / __|___ _ _  / _(_)__ _
 * | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
 * |____|_|\_/\___|\___\___/_||_|_| |_\__, |
 *                                    |___/
 * lcsam - LiveConfig SpamAssassin Milter
 */

/* based on the excellent book "Secure Programming Cookbook for C and C++"
 * by John Viega and Matt Messier (O'Reilly 2003) */

#ifndef __LCSAM_SAFETY_H
#define __LCSAM_SAFETY_H

/* run first safety checks */
int safety_first(void);

/* change privileges to a certain user/group: */
int safety_user_change(int permanent, const char *new_user, const char *new_group);

/* restore root privileges */
int safety_user_restore(void);

#endif /* __LCSAM_SAFETY_H */
