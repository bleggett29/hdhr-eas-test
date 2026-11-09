/*
 * Copyright (C) 2026 Brian Scott - HDHR EAS Test.
 * eas_capture.c - long-running, segmented, multi-tuner capture engine.
 *
 * Built for the nationwide EAS test: every tuner records one station for the
 * whole test window, rolling into wall-clock-aligned segment files that
 * RENDER (ATSC 3.0) or a video player (ATSC 1.0) can open individually.
 *
 *   ATSC 3.0 -> ALP-PCAP (default) or HDHomeRun debug, plus a .txt details
 *               file per segment (same pairing the TUI's 'a'/'z' keys make).
 *   ATSC 1.0 -> full MPEG transport stream (.ts).
 *
 * Each job runs two threads:
 *   rx  - holds the HTTP stream from the tuner and writes segment files.
 *         It never talks to the control port, so it never stalls.
 *   aux - uses the control port: signal status, BSID/TSID lookup, and the
 *         per-segment ATSC 3.0 details .txt.
 *
 * Part of the EAS edition of HDHomeRun TUI. GPLv3, same as the TUI.
 */
#include "eas_capture.h"
#include "plat.h"

#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "hdhomerun.h"
#include "hdhomerun_device.h"
#include "l1_detail_parser.h"

#define RX_CHUNK            (256 * 1024)
#define PREOPEN_MAX_BYTES   (64u * 1024u * 1024u)  /* buffer while waiting for BSID/TSID */
#define PREOPEN_MAX_WAIT_S  5
#define MAX_PCAP_RECORD     (1024 * 1024)
#define CONNECT_TIMEOUT_MS  5000
#define HEADER_TIMEOUT_MS   20000
#define STALL_TIMEOUT_S     20
#define LONG_REQUEST_S      3600

/* The details parser uses static buffers - one caller at a time. */
static pthread_mutex_t g_details_mutex = PTHREAD_MUTEX_INITIALIZER;
void eas_details_lock(void) { pthread_mutex_lock(&g_details_mutex); }
void eas_details_unlock(void) { pthread_mutex_unlock(&g_details_mutex); }

/* ------------------------------------------------------------------ */
/* Logging                                                             */
/* ------------------------------------------------------------------ */
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static FILE *g_log = NULL;
static bool g_log_echo = false;

void eas_set_log_echo(bool echo) { g_log_echo = echo; }

void eas_log_open(const char *outdir) {
    pthread_mutex_lock(&g_log_mutex);
    if (!g_log) {
        char path[700];
        snprintf(path, sizeof(path), "%s/eas_capture.log", outdir);
        g_log = fopen(path, "a");
    }
    pthread_mutex_unlock(&g_log_mutex);
}

void eas_log_close(void) {
    pthread_mutex_lock(&g_log_mutex);
    if (g_log) { fclose(g_log); g_log = NULL; }
    pthread_mutex_unlock(&g_log_mutex);
}

void eas_logf(const char *fmt, ...) {
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tmv;
    plat_localtime((time_t)tv.tv_sec, &tmv);
    char ts[40];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);

    pthread_mutex_lock(&g_log_mutex);
    if (g_log) { fprintf(g_log, "%s.%03ld %s\n", ts, (long)(tv.tv_usec / 1000), msg); fflush(g_log); }
    if (g_log_echo) { printf("%s %s\n", ts, msg); fflush(stdout); }
    pthread_mutex_unlock(&g_log_mutex);
}

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */
const char *eas_fmt_name(eas_fmt_t fmt) {
    switch (fmt) {
        case EAS_FMT_TS: return "ts";
        case EAS_FMT_PCAP: return "alp-pcap";
        case EAS_FMT_DBG: return "dbg";
    }
    return "?";
}

static const char *fmt_ext(eas_fmt_t fmt) {
    switch (fmt) {
        case EAS_FMT_TS: return ".ts";
        case EAS_FMT_PCAP: return ".pcap";
        case EAS_FMT_DBG: return ".dbg";
    }
    return ".bin";
}

static void set_msg(eas_job_t *job, const char *fmt, ...) {
    char msg[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    pthread_mutex_lock(&job->lock);
    snprintf(job->last_msg, sizeof(job->last_msg), "%s", msg);
    pthread_mutex_unlock(&job->lock);
}

static void set_state(eas_job_t *job, const char *state) {
    pthread_mutex_lock(&job->lock);
    snprintf(job->state, sizeof(job->state), "%s", state);
    pthread_mutex_unlock(&job->lock);
}

static bool should_stop(eas_job_t *job) {
    if (job->stop_requested) return true;
    if (job->stop_time && time(NULL) >= job->stop_time) return true;
    return false;
}

/* Sleep up to `seconds`, waking early if the job is stopping. */
static void nap(eas_job_t *job, int seconds) {
    for (int i = 0; i < seconds * 10 && !should_stop(job); i++) plat_sleep_ms(100);
}

/* "key=value" lookup in an HDHomeRun status string; accepts 0x hex. */
static long status_value(const char *s, const char *key) {
    if (!s) return -1;
    const char *p = strstr(s, key);
    if (!p) return -1;
    p += strlen(key);
    char *end;
    long v = strtol(p, &end, 0);
    return (end == p) ? -1 : v;
}

static long next_boundary(time_t now, int seg) {
    return ((long)now / seg + 1) * seg;
}

/* ------------------------------------------------------------------ */
/* Releasing a tuner held by another program                           */
/* ------------------------------------------------------------------ */
int eas_release_tuner(const char *ip, int tuner, char *msg, size_t msglen) {
    struct hdhomerun_device_t *hd = hdhomerun_device_create_from_str(ip, NULL);
    if (!hd) { snprintf(msg, msglen, "cannot reach %s", ip); return -1; }
    if (hdhomerun_device_set_tuner(hd, tuner) <= 0) {
        hdhomerun_device_destroy(hd);
        snprintf(msg, msglen, "%s has no tuner%d", ip, tuner);
        return -1;
    }
    int a = hdhomerun_device_tuner_lockkey_force(hd);
    int b = hdhomerun_device_set_tuner_target(hd, "none");
    int c = hdhomerun_device_set_tuner_channel(hd, "none");
    hdhomerun_device_destroy(hd);
    if (a <= 0 && b <= 0 && c <= 0) { snprintf(msg, msglen, "%s tuner%d did not answer", ip, tuner); return -1; }
    snprintf(msg, msglen, "%s tuner%d released (lock %s, target %s, channel %s)", ip, tuner,
             a > 0 ? "cleared" : "n/a", b > 0 ? "cleared" : "n/a", c > 0 ? "none" : "n/a");
    return 0;
}

int eas_tuner_target(const char *ip, int tuner, char *out, size_t n) {
    snprintf(out, n, "none");
    struct hdhomerun_device_t *hd = hdhomerun_device_create_from_str(ip, NULL);
    if (!hd) return -1;
    char path[48], *v = NULL;
    snprintf(path, sizeof(path), "/tuner%d/target", tuner);
    int r = hdhomerun_device_get_var(hd, path, &v, NULL);
    if (r > 0 && v) {
        snprintf(out, n, "%s", v[0] ? v : "none");
        out[strcspn(out, "\r\n")] = '\0';
    }
    hdhomerun_device_destroy(hd);
    return r > 0 ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Channel spec                                                        */
/* ------------------------------------------------------------------ */
void eas_job_init(eas_job_t *job) {
    memset(job, 0, sizeof(*job));
    pthread_mutex_init(&job->lock, NULL);
    pthread_cond_init(&job->cond, NULL);
    job->tuner = -1;
    job->fmt = EAS_FMT_TS;
    job->seg_seconds = 60;
    job->id_val = -1;
    snprintf(job->state, sizeof(job->state), "idle");
}

void eas_job_destroy(eas_job_t *job) {
    pthread_mutex_destroy(&job->lock);
    pthread_cond_destroy(&job->cond);
}

int eas_parse_channel_spec(const char *spec, eas_job_t *job, char *err, size_t errlen) {
    const char *p = spec;
    /* Accept device-style prefixes: "atsc3:27:0+16", "8vsb:33", "auto:33". */
    if (strncasecmp(p, "atsc3:", 6) == 0) { p += 6; job->atsc3 = true; }
    else if (strncasecmp(p, "8vsb:", 5) == 0 || strncasecmp(p, "auto:", 5) == 0) p += 5;

    if (!isdigit((unsigned char)*p)) {
        snprintf(err, errlen, "channel '%s': expected an RF channel number", spec);
        return -1;
    }
    char *end;
    unsigned long rf = strtoul(p, &end, 10);
    if (rf == 0 || rf > 999) {
        snprintf(err, errlen, "channel '%s': RF channel out of range", spec);
        return -1;
    }
    job->rf = (unsigned)rf;
    job->plps[0] = '\0';
    p = end;

    if (*p == ':' ) {           /* 27:0+16 */
        job->atsc3 = true;
        p++;
        while (*p) {
            if (!isdigit((unsigned char)*p)) { snprintf(err, errlen, "channel '%s': bad PLP list", spec); return -1; }
            long plp = strtol(p, &end, 10);
            if (plp < 0 || plp > 63) { snprintf(err, errlen, "channel '%s': PLP out of range", spec); return -1; }
            size_t n = strlen(job->plps);
            snprintf(job->plps + n, sizeof(job->plps) - n, "p%ld", plp);
            p = end;
            if (*p == '+' || *p == ',') p++;
            else if (*p) { snprintf(err, errlen, "channel '%s': bad PLP list", spec); return -1; }
        }
    } else if (*p == 'p' || *p == 'P') {   /* 27p0p16 */
        job->atsc3 = true;
        while (*p == 'p' || *p == 'P') {
            p++;
            if (!isdigit((unsigned char)*p)) { snprintf(err, errlen, "channel '%s': bad PLP list", spec); return -1; }
            long plp = strtol(p, &end, 10);
            if (plp < 0 || plp > 63) { snprintf(err, errlen, "channel '%s': PLP out of range", spec); return -1; }
            size_t n = strlen(job->plps);
            snprintf(job->plps + n, sizeof(job->plps) - n, "p%ld", plp);
            p = end;
        }
        if (*p) { snprintf(err, errlen, "channel '%s': unexpected '%s'", spec, p); return -1; }
    } else if (*p) {
        snprintf(err, errlen, "channel '%s': unexpected '%s'", spec, p);
        return -1;
    }

    if (job->atsc3 && job->plps[0] == '\0') snprintf(job->plps, sizeof(job->plps), "p0");
    if (!job->atsc3) job->fmt = EAS_FMT_TS;
    else if (job->fmt == EAS_FMT_TS) job->fmt = EAS_FMT_PCAP;
    return 0;
}

/* ------------------------------------------------------------------ */
/* HTTP                                                                */
/* ------------------------------------------------------------------ */
/* Opens the stream and reads the response headers. Any body bytes that
 * arrived with the headers are appended to *buf. Returns the socket, or -1. */
static plat_sock_t http_open(eas_job_t *job, eas_fmt_t fmt, int duration_s,
                     uint8_t **buf, size_t *len, size_t *cap, int *status_out) {
    *status_out = 0;
    char path[256];
    switch (fmt) {
        case EAS_FMT_TS:
            snprintf(path, sizeof(path), "/tuner%d/ch%u", job->tuner, job->rf);
            break;
        case EAS_FMT_PCAP:
            snprintf(path, sizeof(path), "/tuner%d/ch%u%s?format=alp-pcap&duration=%d",
                     job->tuner, job->rf, job->plps, duration_s);
            break;
        case EAS_FMT_DBG:
            snprintf(path, sizeof(path), "/tuner%d/ch%u%s?format=dbg&duration=%d",
                     job->tuner, job->rf, job->plps, duration_s);
            break;
    }

    char cerr[200];
    plat_sock_t sock = plat_tcp_connect(job->ip, 5004, CONNECT_TIMEOUT_MS, cerr, sizeof(cerr));
    if (sock == PLAT_BAD_SOCK) { set_msg(job, "%s", cerr); return PLAT_BAD_SOCK; }

    char req[512];
    int rl = snprintf(req, sizeof(req),
                      "GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: hdhomerun_tui-eas\r\nConnection: close\r\n\r\n",
                      path, job->ip);
    if (send(sock, req, rl, MSG_NOSIGNAL) != rl) {
        set_msg(job, "send: %s", plat_sock_error());
        plat_sock_close(sock);
        return PLAT_BAD_SOCK;
    }
    eas_logf("tuner%d rf%u: GET http://%s:5004%s", job->tuner, job->rf, job->ip, path);

    /* Read headers */
    char hdr[8192];
    size_t hl = 0;
    struct timeval t0, t1;
    gettimeofday(&t0, NULL);
    for (;;) {
        if (should_stop(job)) { plat_sock_close(sock); return PLAT_BAD_SOCK; }
        plat_wait_readable(sock, 200);
        int n = recv(sock, hdr + hl, (int)(sizeof(hdr) - 1 - hl), 0);
        if (n > 0) {
            hl += (size_t)n;
            hdr[hl] = '\0';
            char *eoh = strstr(hdr, "\r\n\r\n");
            if (eoh) {
                int code = 0;
                if (sscanf(hdr, "HTTP/%*d.%*d %d", &code) != 1) code = -1;
                *status_out = code;
                if (code != 200) {
                    char *eol = strstr(hdr, "\r\n");
                    if (eol) *eol = '\0';
                    set_msg(job, "device answered: %s", hdr);
                    eas_logf("tuner%d rf%u: device answered: %s", job->tuner, job->rf, hdr);
                    plat_sock_close(sock);
                    return PLAT_BAD_SOCK;
                }
                size_t body = hl - (size_t)(eoh + 4 - hdr);
                if (body) {
                    if (*len + body > *cap) {
                        *cap = *len + body + RX_CHUNK;
                        *buf = realloc(*buf, *cap);
                    }
                    memcpy(*buf + *len, eoh + 4, body);
                    *len += body;
                }
                return sock;
            }
            if (hl >= sizeof(hdr) - 1) { set_msg(job, "response headers too long"); plat_sock_close(sock); return PLAT_BAD_SOCK; }
        } else if (n == 0) {
            set_msg(job, "device closed the connection before answering");
            plat_sock_close(sock);
            return PLAT_BAD_SOCK;
        } else if (!plat_sock_would_block()) {
            set_msg(job, "recv: %s", plat_sock_error());
            plat_sock_close(sock);
            return PLAT_BAD_SOCK;
        }
        gettimeofday(&t1, NULL);
        long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_usec - t0.tv_usec) / 1000;
        if (ms > HEADER_TIMEOUT_MS) { set_msg(job, "no answer from device (timeout)"); plat_sock_close(sock); return PLAT_BAD_SOCK; }
    }
}

/* ------------------------------------------------------------------ */
/* Segment files                                                       */
/* ------------------------------------------------------------------ */
typedef struct {
    FILE *f;
    char name[700];
    unsigned long long bytes;
    time_t opened;
    long rotate_at;
    char *iobuf;
} segment_t;

static void segment_close(eas_job_t *job, segment_t *seg) {
    if (!seg->f) return;
    fclose(seg->f);
    seg->f = NULL;
    free(seg->iobuf);
    seg->iobuf = NULL;
    char sig[160];
    pthread_mutex_lock(&job->lock);
    snprintf(sig, sizeof(sig), "%s", job->signal);
    pthread_mutex_unlock(&job->lock);
    eas_logf("tuner%d rf%u: closed %s (%.1f MB, %lds) %s", job->tuner, job->rf, seg->name,
             seg->bytes / 1048576.0, (long)(time(NULL) - seg->opened), sig);
}

static int segment_open(eas_job_t *job, segment_t *seg, eas_fmt_t fmt,
                        const uint8_t *pcap_hdr, size_t pcap_hdr_len) {
    time_t now = time(NULL);
    struct tm tmv;
    plat_localtime(now, &tmv);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y%m%d-%H%M%S", &tmv);

    long id;
    pthread_mutex_lock(&job->lock);
    id = job->id_val < 0 ? 0 : job->id_val;
    pthread_mutex_unlock(&job->lock);

    char base[400];
    if (job->atsc3)
        snprintf(base, sizeof(base), "rf%u-bsid%ld-%s-%s%s", job->rf, id, job->plps, ts, fmt_ext(fmt));
    else
        snprintf(base, sizeof(base), "rf%u-tsid%ld-%s%s", job->rf, id, ts, fmt_ext(fmt));
    snprintf(seg->name, sizeof(seg->name), "%s/%s", job->outdir, base);

    seg->f = fopen(seg->name, "wb");
    if (!seg->f) {
        set_msg(job, "cannot write %s: %s", seg->name, strerror(errno));
        eas_logf("tuner%d rf%u: cannot write %s: %s", job->tuner, job->rf, seg->name, strerror(errno));
        return -1;
    }
    seg->iobuf = malloc(1 << 20);
    if (seg->iobuf) setvbuf(seg->f, seg->iobuf, _IOFBF, 1 << 20);
    seg->bytes = 0;
    seg->opened = now;
    seg->rotate_at = next_boundary(now, job->seg_seconds);
    if (pcap_hdr_len) {
        fwrite(pcap_hdr, 1, pcap_hdr_len, seg->f);
        seg->bytes += pcap_hdr_len;
    }

    pthread_mutex_lock(&job->lock);
    snprintf(job->cur_file, sizeof(job->cur_file), "%s", seg->name);
    job->segments++;
    job->bytes_seg = seg->bytes;
    if (job->atsc3) {
        /* Hand the details .txt to the aux thread so rx never blocks. */
        snprintf(job->details_pending, sizeof(job->details_pending), "%s", seg->name);
        pthread_cond_signal(&job->cond);
    }
    pthread_mutex_unlock(&job->lock);
    eas_logf("tuner%d rf%u: opened %s", job->tuner, job->rf, seg->name);
    return 0;
}

static int segment_write(eas_job_t *job, segment_t *seg, const uint8_t *data, size_t n) {
    if (n == 0) return 0;
    if (fwrite(data, 1, n, seg->f) != n) {
        set_msg(job, "write error on %s: %s", seg->name, strerror(errno));
        eas_logf("tuner%d rf%u: write error on %s: %s", job->tuner, job->rf, seg->name, strerror(errno));
        return -1;
    }
    seg->bytes += n;
    pthread_mutex_lock(&job->lock);
    job->bytes_total += n;
    job->bytes_seg = seg->bytes;
    pthread_mutex_unlock(&job->lock);
    return 0;
}

/* Wait (while still reading) until the aux thread knows the BSID/TSID, so
 * the first file gets a proper name. Gives up after PREOPEN_MAX_WAIT_S. */
static bool id_ready(eas_job_t *job, time_t first_data) {
    pthread_mutex_lock(&job->lock);
    bool known = job->id_val >= 0;
    pthread_mutex_unlock(&job->lock);
    return known || (time(NULL) - first_data) >= PREOPEN_MAX_WAIT_S;
}

/* ------------------------------------------------------------------ */
/* Receive loops                                                       */
/* ------------------------------------------------------------------ */
typedef enum { RX_OK, RX_STOPPED, RX_EOF, RX_ERROR, RX_FATAL } rx_result_t;

/* Pulls whatever is available into buf. */
static rx_result_t rx_fill(eas_job_t *job, plat_sock_t sock, uint8_t **buf, size_t *len, size_t *cap,
                           time_t *last_data) {
    int pr = plat_wait_readable(sock, 250);
    if (pr < 0) { set_msg(job, "connection error"); return RX_ERROR; }
    if (*len + RX_CHUNK > *cap) {
        *cap = *len + RX_CHUNK * 4;
        uint8_t *nb = realloc(*buf, *cap);
        if (!nb) return RX_FATAL;
        *buf = nb;
    }
    if (pr == 0) {
        if (time(NULL) - *last_data > STALL_TIMEOUT_S) {
            set_msg(job, "no data for %ds", STALL_TIMEOUT_S);
            return RX_ERROR;
        }
        return RX_OK;
    }
    int n = recv(sock, (char *)*buf + *len, (int)(*cap - *len), 0);
    if (n > 0) {
        *len += (size_t)n;
        *last_data = time(NULL);
        return RX_OK;
    }
    if (n == 0) return RX_EOF;
    if (plat_sock_would_block()) {
        if (time(NULL) - *last_data > STALL_TIMEOUT_S) {
            set_msg(job, "no data for %ds", STALL_TIMEOUT_S);
            return RX_ERROR;
        }
        return RX_OK;
    }
    set_msg(job, "recv: %s", plat_sock_error());
    return RX_ERROR;
}

/* MPEG-TS: write whole 188-byte packets; rotate on packet boundaries. A
 * reconnect keeps appending to the open segment. */
static rx_result_t rx_ts(eas_job_t *job, plat_sock_t sock, segment_t *seg,
                         uint8_t **buf, size_t *len, size_t *cap) {
    time_t last_data = time(NULL), first_data = 0;
    for (;;) {
        if (should_stop(job)) return RX_STOPPED;
        rx_result_t r = rx_fill(job, sock, buf, len, cap, &last_data);
        if (r != RX_OK) return r;
        if (*len && !first_data) first_data = time(NULL);

        /* Resync if the stream doesn't start on 0x47 */
        size_t off = 0;
        while (off < *len && (*buf)[off] != 0x47) off++;
        if (off) { memmove(*buf, *buf + off, *len - off); *len -= off; }

        size_t whole = (*len / 188) * 188;
        if (!whole) continue;

        if (!seg->f) {
            if (!id_ready(job, first_data) && *len < PREOPEN_MAX_BYTES) continue;
            if (segment_open(job, seg, EAS_FMT_TS, NULL, 0) < 0) return RX_FATAL;
        } else if (time(NULL) >= seg->rotate_at) {
            segment_close(job, seg);
            if (segment_open(job, seg, EAS_FMT_TS, NULL, 0) < 0) return RX_FATAL;
        }
        if (segment_write(job, seg, *buf, whole) < 0) return RX_FATAL;
        memmove(*buf, *buf + whole, *len - whole);
        *len -= whole;
    }
}

/* ALP-PCAP: keep the 24-byte global header, write whole records only,
 * rotate on record boundaries. On reconnect the new global header is
 * dropped and records keep flowing into the open segment. */
static rx_result_t rx_pcap(eas_job_t *job, plat_sock_t sock, segment_t *seg,
                           uint8_t *gh, bool *have_gh,
                           uint8_t **buf, size_t *len, size_t *cap) {
    time_t last_data = time(NULL), first_data = 0;
    bool header_this_conn = false;
    bool big_endian = false;

    if (*have_gh) {
        uint32_t m; memcpy(&m, gh, 4);
        big_endian = (m == 0xd4c3b2a1u || m == 0x4d3cb2a1u);
    }

    for (;;) {
        if (should_stop(job)) return RX_STOPPED;
        rx_result_t r = rx_fill(job, sock, buf, len, cap, &last_data);
        if (r != RX_OK) return r;
        if (*len && !first_data) first_data = time(NULL);

        if (!header_this_conn) {
            if (*len < 24) continue;
            uint32_t m; memcpy(&m, *buf, 4);
            if (m != 0xa1b2c3d4u && m != 0xa1b23c4du && m != 0xd4c3b2a1u && m != 0x4d3cb2a1u) {
                set_msg(job, "stream is not PCAP (magic %08x)", m);
                eas_logf("tuner%d rf%u: stream is not PCAP (magic %08x)", job->tuner, job->rf, m);
                return RX_FATAL;
            }
            if (*have_gh && memcmp(gh + 20, *buf + 20, 4) != 0 && seg->f) {
                /* Link type changed - start a fresh file to keep it valid */
                segment_close(job, seg);
            }
            memcpy(gh, *buf, 24);
            *have_gh = true;
            big_endian = (m == 0xd4c3b2a1u || m == 0x4d3cb2a1u);
            memmove(*buf, *buf + 24, *len - 24);
            *len -= 24;
            header_this_conn = true;
        }

        /* Walk complete records */
        size_t off = 0;
        while (*len - off >= 16) {
            uint32_t incl;
            memcpy(&incl, *buf + off + 8, 4);
            if (big_endian) incl = __builtin_bswap32(incl);
            if (incl > MAX_PCAP_RECORD) {
                set_msg(job, "corrupt PCAP record (len %u), reconnecting", incl);
                eas_logf("tuner%d rf%u: corrupt PCAP record (len %u)", job->tuner, job->rf, incl);
                *len = 0;
                return RX_ERROR;
            }
            if (*len - off < 16 + (size_t)incl) break;

            if (!seg->f) {
                if (!id_ready(job, first_data) && *len < PREOPEN_MAX_BYTES) break;
                if (segment_open(job, seg, EAS_FMT_PCAP, gh, 24) < 0) return RX_FATAL;
            } else if (time(NULL) >= seg->rotate_at) {
                segment_close(job, seg);
                if (segment_open(job, seg, EAS_FMT_PCAP, gh, 24) < 0) return RX_FATAL;
            }
            if (segment_write(job, seg, *buf + off, 16 + incl) < 0) return RX_FATAL;
            off += 16 + incl;
        }
        if (off) { memmove(*buf, *buf + off, *len - off); *len -= off; }
    }
}

/* Debug format: one request per segment (the device ends it on the
 * boundary via duration=). Each segment is its own file. */
static rx_result_t rx_dbg(eas_job_t *job, plat_sock_t sock, segment_t *seg,
                          uint8_t **buf, size_t *len, size_t *cap) {
    time_t last_data = time(NULL), first_data = 0;
    for (;;) {
        if (should_stop(job)) return RX_STOPPED;
        rx_result_t r = rx_fill(job, sock, buf, len, cap, &last_data);
        if (r == RX_EOF) {
            if (seg->f && *len) segment_write(job, seg, *buf, *len);
            *len = 0;
            return RX_EOF;
        }
        if (r != RX_OK) return r;
        if (*len && !first_data) first_data = time(NULL);
        if (!*len) continue;
        if (!seg->f) {
            if (!id_ready(job, first_data) && *len < PREOPEN_MAX_BYTES) continue;
            if (segment_open(job, seg, EAS_FMT_DBG, NULL, 0) < 0) return RX_FATAL;
        }
        if (segment_write(job, seg, *buf, *len) < 0) return RX_FATAL;
        *len = 0;
    }
}

static int request_duration(eas_job_t *job, eas_fmt_t fmt) {
    time_t now = time(NULL);
    if (fmt == EAS_FMT_DBG) {
        long d = next_boundary(now, job->seg_seconds) - now;
        if (d < 5) d += job->seg_seconds;   /* don't make a sliver of a file */
        return (int)d;
    }
    if (job->stop_time) {
        long d = (long)(job->stop_time - now) + 10;
        if (d < 10) d = 10;
        if (d > LONG_REQUEST_S) d = LONG_REQUEST_S;
        return (int)d;
    }
    return LONG_REQUEST_S;
}

static void *rx_thread_main(void *arg) {
    eas_job_t *job = arg;
    eas_fmt_t fmt = job->fmt;
    bool fell_back = false;
    segment_t seg = {0};
    uint8_t gh[24];
    bool have_gh = false;
    size_t cap = RX_CHUNK * 4, len = 0;
    uint8_t *buf = malloc(cap);

    set_state(job, "connecting");
    while (buf && !should_stop(job)) {
        int status = 0;
        len = 0;
        plat_sock_t sock = http_open(job, fmt, request_duration(job, fmt), &buf, &len, &cap, &status);
        if (sock == PLAT_BAD_SOCK) {
            if (should_stop(job)) break;
            if (status == 503) {
                /* Tuner busy: something else (a scanner, a logger, a DVR, live TV) holds it. */
                char rmsg[200], target[160];
                eas_tuner_target(job->ip, job->tuner, target, sizeof(target));
                bool streaming = strcmp(target, "none") != 0;
                if (job->force_release || !streaming) {
                    eas_logf("tuner%d rf%u: tuner busy (HTTP 503%s) - releasing it and retrying", job->tuner, job->rf,
                             streaming ? "" : ", stale lock");
                    eas_release_tuner(job->ip, job->tuner, rmsg, sizeof(rmsg));
                    eas_logf("tuner%d rf%u: %s", job->tuner, job->rf, rmsg);
                    set_msg(job, "tuner was busy (503) - released, retrying");
                } else {
                    eas_logf("tuner%d rf%u: tuner in use by something else (streaming to %s) - "
                             "free it (DVR, live viewing, scanner); retrying", job->tuner, job->rf, target);
                    set_msg(job, "IN USE elsewhere (%s) - free this tuner", target);
                    nap(job, 3);
                }
                pthread_mutex_lock(&job->lock);
                job->reconnects++;
                pthread_mutex_unlock(&job->lock);
                nap(job, 2);
                continue;
            }
            if (fmt == EAS_FMT_PCAP && !fell_back && status >= 400 && status < 500) {
                /* Older firmware / models without ALP-PCAP: fall back to debug. */
                eas_logf("tuner%d rf%u: ALP-PCAP refused (HTTP %d), falling back to debug format",
                         job->tuner, job->rf, status);
                set_msg(job, "ALP-PCAP refused (HTTP %d) - using debug format", status);
                fmt = EAS_FMT_DBG;
                fell_back = true;
                pthread_mutex_lock(&job->lock);
                job->fmt = fmt;
                pthread_mutex_unlock(&job->lock);
                continue;
            }
            pthread_mutex_lock(&job->lock);
            job->reconnects++;
            pthread_mutex_unlock(&job->lock);
            set_state(job, "retrying");
            nap(job, 3);
            continue;
        }
        set_state(job, "recording");

        rx_result_t r;
        if (fmt == EAS_FMT_TS) r = rx_ts(job, sock, &seg, &buf, &len, &cap);
        else if (fmt == EAS_FMT_PCAP) r = rx_pcap(job, sock, &seg, gh, &have_gh, &buf, &len, &cap);
        else r = rx_dbg(job, sock, &seg, &buf, &len, &cap);
        plat_sock_close(sock);

        if (fmt == EAS_FMT_DBG) segment_close(job, &seg);   /* one file per request */
        if (r == RX_FATAL) break;
        if (r == RX_STOPPED) break;
        if (should_stop(job)) break;

        if (r == RX_EOF && fmt == EAS_FMT_DBG) continue;    /* normal end of a dbg segment */

        eas_logf("tuner%d rf%u: stream %s, reconnecting", job->tuner, job->rf,
                 r == RX_EOF ? "ended" : "error");
        pthread_mutex_lock(&job->lock);
        job->reconnects++;
        pthread_mutex_unlock(&job->lock);
        set_state(job, "reconnecting");
        nap(job, 1);
    }

    segment_close(job, &seg);
    free(buf);

    pthread_mutex_lock(&job->lock);
    job->running = false;
    snprintf(job->state, sizeof(job->state), "%s", "finished");
    pthread_cond_signal(&job->cond);
    pthread_mutex_unlock(&job->lock);
    eas_logf("tuner%d rf%u: finished (%d segments, %.1f MB, %d reconnects)", job->tuner, job->rf,
             job->segments, job->bytes_total / 1048576.0, job->reconnects);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Aux thread: control-port work                                       */
/* ------------------------------------------------------------------ */
static void *aux_thread_main(void *arg) {
    eas_job_t *job = arg;
    struct hdhomerun_device_t *hd = hdhomerun_device_create_from_str(job->ip, NULL);
    if (hd) hdhomerun_device_set_tuner(hd, job->tuner);
    else eas_logf("tuner%d rf%u: control connection to %s failed (no signal/details logging)",
                  job->tuner, job->rf, job->ip);

    time_t last_status = 0;
    for (;;) {
        char pending[700] = "";
        bool running;
        pthread_mutex_lock(&job->lock);
        if (!job->details_pending[0] && job->running) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += (job->id_val < 0) ? 0 : 1;
            ts.tv_nsec += 500000000L;
            if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
            pthread_cond_timedwait(&job->cond, &job->lock, &ts);
        }
        running = job->running;
        if (job->details_pending[0]) {
            snprintf(pending, sizeof(pending), "%s", job->details_pending);
            job->details_pending[0] = '\0';
        }
        pthread_mutex_unlock(&job->lock);

        if (!hd) { if (!running) break; continue; }

        time_t now = time(NULL);
        if (now - last_status >= 5 || pending[0]) {
            last_status = now;
            struct hdhomerun_tuner_status_t st;
            char *raw = NULL;
            char sigbuf[160] = "";
            if (hdhomerun_device_get_tuner_status(hd, &raw, &st) > 0) {
                snprintf(sigbuf, sizeof(sigbuf), "lock=%s ss=%u snq=%u seq=%u",
                         st.lock_str, st.signal_strength, st.signal_to_noise_quality,
                         st.symbol_error_quality);
                pthread_mutex_lock(&job->lock);
                snprintf(job->signal, sizeof(job->signal), "%s", sigbuf);
                pthread_mutex_unlock(&job->lock);
            }
            pthread_mutex_lock(&job->lock);
            bool need_id = job->id_val < 0;
            pthread_mutex_unlock(&job->lock);
            if (need_id) {
                long id = -1;
                char *info = NULL;
                if (job->atsc3) {
                    if (hdhomerun_device_get_tuner_plpinfo(hd, &info) > 0) id = status_value(info, "bsid=");
                } else {
                    if (hdhomerun_device_get_tuner_streaminfo(hd, &info) > 0) id = status_value(info, "tsid=");
                }
                if (id >= 0) {
                    pthread_mutex_lock(&job->lock);
                    job->id_val = id;
                    pthread_mutex_unlock(&job->lock);
                    eas_logf("tuner%d rf%u: %s=%ld %s", job->tuner, job->rf,
                             job->atsc3 ? "bsid" : "tsid", id, sigbuf);
                }
            }
        }

        if (pending[0] && job->atsc3) {
            pthread_mutex_lock(&g_details_mutex);
            int r = save_atsc3_details_auto(hd, job->tuner, pending);
            pthread_mutex_unlock(&g_details_mutex);
            if (r != 0) eas_logf("tuner%d rf%u: could not save details for %s", job->tuner, job->rf, pending);
        }

        if (!running) break;
    }
    if (hd) hdhomerun_device_destroy(hd);
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Job control                                                         */
/* ------------------------------------------------------------------ */
int eas_job_start(eas_job_t *job) {
    if (job->tuner < 0 || job->rf == 0 || !job->ip[0] || job->seg_seconds < 10) return -1;
    job->stop_requested = 0;
    job->running = true;
    snprintf(job->state, sizeof(job->state), "starting");
    eas_logf("tuner%d rf%u: start %s%s, %ds segments -> %s", job->tuner, job->rf,
             job->atsc3 ? "ATSC 3.0 " : "ATSC 1.0", job->atsc3 ? job->plps : "",
             job->seg_seconds, job->outdir);
    if (pthread_create(&job->rx_thread, NULL, rx_thread_main, job) != 0) {
        job->running = false;
        return -1;
    }
    if (pthread_create(&job->aux_thread, NULL, aux_thread_main, job) != 0) {
        job->stop_requested = 1;
        pthread_join(job->rx_thread, NULL);
        return -1;
    }
    job->threads_started = true;
    return 0;
}

void eas_job_request_stop(eas_job_t *job) {
    job->stop_requested = 1;
    pthread_mutex_lock(&job->lock);
    pthread_cond_signal(&job->cond);
    pthread_mutex_unlock(&job->lock);
}

void eas_job_join(eas_job_t *job) {
    if (!job->threads_started) return;
    pthread_join(job->rx_thread, NULL);
    pthread_mutex_lock(&job->lock);
    pthread_cond_signal(&job->cond);
    pthread_mutex_unlock(&job->lock);
    pthread_join(job->aux_thread, NULL);
    job->threads_started = false;
}

void eas_job_status(eas_job_t *job, eas_status_t *o) {
    pthread_mutex_lock(&job->lock);
    o->running = job->running;
    snprintf(o->state, sizeof(o->state), "%s", job->state);
    snprintf(o->cur_file, sizeof(o->cur_file), "%s", job->cur_file);
    o->segments = job->segments;
    o->reconnects = job->reconnects;
    o->bytes_total = job->bytes_total;
    o->bytes_seg = job->bytes_seg;
    snprintf(o->last_msg, sizeof(o->last_msg), "%s", job->last_msg);
    snprintf(o->signal, sizeof(o->signal), "%s", job->signal);
    o->id_val = job->id_val;
    o->fmt = job->fmt;
    pthread_mutex_unlock(&job->lock);
}

