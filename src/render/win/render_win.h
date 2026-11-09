/*
 * Copyright (C) 2026 Brian Scott - HDHR EAS Test.
 * render_win.h - what RENDER needs on Windows (MinGW/MSYS2) that Linux headers
 * normally provide. Used through the stub headers in this folder. GPLv3.
 */
#ifndef RENDER_WIN_H
#define RENDER_WIN_H
#ifdef _WIN32

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOCRYPT
#define NOCRYPT   /* keep wincrypt.h X509_NAME etc. away from OpenSSL */
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef X509_NAME
#undef X509_NAME
#endif
/* mkstemps(): template must end in XXXXXX followed by suffixlen chars */
static inline int render_mkstemps(char *tmpl, int suffixlen) {
    size_t n = strlen(tmpl);
    if ((int)n < 6 + suffixlen) return -1;
    char *x = tmpl + n - suffixlen - 6;
    static unsigned seq = 0;
    for (int tries = 0; tries < 100; tries++) {
        unsigned v = (unsigned)GetTickCount() ^ ((unsigned)GetCurrentProcessId() << 8) ^ (++seq * 2654435761u);
        for (int i = 0; i < 6; i++) { x[i] = "abcdefghijklmnopqrstuvwxyz0123456789"[v % 36]; v /= 36; }
        int fd = _open(tmpl, _O_CREAT | _O_EXCL | _O_RDWR | _O_BINARY, _S_IREAD | _S_IWRITE);
        if (fd >= 0) return fd;
    }
    return -1;
}
#define mkstemps render_mkstemps

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/types.h>
#include <pthread_time.h>   /* clock_gettime (winpthreads) */

#ifndef _SSIZE_T_DEFINED
typedef long long ssize_t;
#define _SSIZE_T_DEFINED
#endif
typedef unsigned char u_char_t;

/* BSD-style network headers (as glibc names them) */
struct ether_header {
    uint8_t ether_dhost[6];
    uint8_t ether_shost[6];
    uint16_t ether_type;
};

struct ip {
    uint8_t ip_hl:4, ip_v:4;      /* little-endian bitfields */
    uint8_t ip_tos;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_off;
    uint8_t ip_ttl;
    uint8_t ip_p;
    uint16_t ip_sum;
    struct in_addr ip_src, ip_dst;
};

struct udphdr {
    uint16_t uh_sport;
    uint16_t uh_dport;
    uint16_t uh_ulen;
    uint16_t uh_sum;
};

/* GNU/POSIX string and time helpers MinGW lacks */
static inline void *render_memmem(const void *h, size_t hl, const void *n, size_t nl) {
    if (nl == 0) return (void *)h;
    if (hl < nl) return NULL;
    const unsigned char *p = (const unsigned char *)h, *end = p + hl - nl;
    for (; p <= end; p++) if (*p == *(const unsigned char *)n && memcmp(p, n, nl) == 0) return (void *)p;
    return NULL;
}
#define memmem render_memmem

static inline char *render_strcasestr(const char *h, const char *n) {
    size_t L = strlen(n);
    if (!L) return (char *)h;
    for (; *h; h++) if (_strnicmp(h, n, L) == 0) return (char *)h;
    return NULL;
}
#define strcasestr render_strcasestr

static inline char *render_strndup(const char *s, size_t n) {
    size_t L = 0;
    while (L < n && s[L]) L++;
    char *d = (char *)malloc(L + 1);
    if (!d) return NULL;
    memcpy(d, s, L);
    d[L] = '\0';
    return d;
}
#define strndup render_strndup

static inline ssize_t render_getline(char **lineptr, size_t *n, FILE *f) {
    if (!lineptr || !n || !f) return -1;
    if (!*lineptr || *n == 0) { *n = 256; *lineptr = (char *)malloc(*n); if (!*lineptr) return -1; }
    size_t len = 0;
    int c;
    while ((c = fgetc(f)) != EOF) {
        if (len + 2 > *n) { size_t nn = *n * 2; char *p = (char *)realloc(*lineptr, nn); if (!p) return -1; *lineptr = p; *n = nn; }
        (*lineptr)[len++] = (char)c;
        if (c == '\n') break;
    }
    if (len == 0 && c == EOF) return -1;
    (*lineptr)[len] = '\0';
    return (ssize_t)len;
}
#define getline render_getline

static inline struct tm *render_localtime_r(const time_t *t, struct tm *out) {
    return localtime_s(out, t) == 0 ? out : NULL;
}
#define localtime_r render_localtime_r

static inline struct tm *render_gmtime_r(const time_t *t, struct tm *out) {
    return gmtime_s(out, t) == 0 ? out : NULL;
}
#define gmtime_r render_gmtime_r

#endif /* _WIN32 */
#endif
