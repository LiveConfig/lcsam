/*  _    _          ___           __ _     (R)
 * | |  (_)_ _____ / __|___ _ _  / _(_)__ _
 * | |__| \ V / -_) (__/ _ \ ' \|  _| / _` |
 * |____|_|\_/\___|\___\___/_||_|_| |_\__, |
 *                                    |___/
 * lcsam - LiveConfig SpamAssassin Milter
 */

#ifndef __LCSAM_PID_H
#define __LCSAM_PID_H

int pid_create(const char *filename);
int pid_update(void);
void pid_release(const char *filename);

#endif /* __LCSAM_PID_H */
