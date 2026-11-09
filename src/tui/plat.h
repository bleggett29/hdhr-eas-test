/*
 * Copyright (C) 2026 Brian Scott - HDHR EAS Test.
 * plat.h - small portability layer (Linux/Unix and Windows) for HDHR EAS Test.
 * GPLv3.
 */
#ifndef HDHR_EAS_PLAT_H
#define HDHR_EAS_PLAT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#ifdef _WIN32
#  ifndef _WIN32_WINNT
#    define _WIN32_WINNT 0x0601
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
typedef SOCKET plat_sock_t;
#  define PLAT_BAD_SOCK INVALID_SOCKET
#  ifndef MSG_NOSIGNAL
#    define MSG_NOSIGNAL 0
#  endif
#  define PLAT_EXE_SUFFIX ".exe"
#else
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
typedef int plat_sock_t;
#  define PLAT_BAD_SOCK (-1)
#  define PLAT_EXE_SUFFIX ""
#endif

typedef long plat_pid_t;

void plat_init(void);                       /* sockets etc.; call once at startup */

/* --- paths --- */
const char *plat_home(void);                /* $HOME or %USERPROFILE%                 */
const char *plat_config_base(void);         /* ~/.config or %APPDATA%                  */
void plat_expand_home(const char *in, char *out, size_t n);   /* "~/x" -> home/x       */
int  plat_mkdir_p(const char *path);
int  plat_exe_path(char *out, size_t n);
int  plat_exe_dir(char *out, size_t n);
bool plat_is_file(const char *path);
bool plat_is_dir(const char *path);
bool plat_exists(const char *path);
int  plat_rename_replace(const char *from, const char *to);
double plat_free_bytes(const char *path);   /* -1 if unknown; walks up to an existing dir */
long long plat_file_size(const char *path); /* -1 if missing */

/* --- time --- */
void plat_sleep_ms(int ms);
void plat_localtime(time_t t, struct tm *out);

/* --- network --- */
int  plat_lan_ip(char *out, size_t n);       /* best local IPv4 address for links         */
int  plat_local_ip_towards(const char *ip, char *out, size_t n);
plat_sock_t plat_tcp_connect(const char *ip, int port, int timeout_ms, char *err, size_t errlen);
void plat_sock_close(plat_sock_t s);
int  plat_sock_set_nonblock(plat_sock_t s);
int  plat_wait_readable(plat_sock_t s, int timeout_ms);   /* >0 ready, 0 timeout, <0 error */
bool plat_sock_would_block(void);            /* after recv/send returned <0            */
const char *plat_sock_error(void);

/* --- processes --- */
plat_pid_t plat_getpid(void);
bool plat_pid_alive(plat_pid_t pid);
/* argv[0] is the program (path or name found on PATH). Output goes to logfile
 * (NULL = discard). detached: new session/no console, survives the parent. */
plat_pid_t plat_spawn_ex(const char *const argv[], const char *logfile, bool append, bool detached, bool show);
plat_pid_t plat_spawn(const char *const argv[], const char *logfile, bool append, bool detached);
/* Wait for a non-detached child. timeout_ms: -1 forever, 0 just check.
 * Returns exit code (>=0), -2 still running, -1 error. */
int  plat_wait(plat_pid_t pid, int timeout_ms);
int  plat_terminate(plat_pid_t pid);
/* Run a shell command and capture its output (first n-1 bytes). Returns exit status or -1. */
int  plat_run_capture(const char *cmd, char *out, size_t n);
bool plat_find_program(const char *name, char *out, size_t n);   /* search PATH */

/* --- desktop --- */
int  plat_open_uri(const char *path_or_url);  /* browser / file manager / default app    */
void plat_keep_awake(bool on);                /* stop the PC sleeping during a run        */

/* --- string helpers missing on some platforms --- */
char *plat_strcasestr(const char *h, const char *n);

#endif
