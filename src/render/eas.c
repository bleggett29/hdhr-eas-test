/*
 * Copyright (C) 2026 Brian Scott - HDHR EAS Test.
 * eas.c - EAS / AEAT timeline support for RENDER (EAS edition).
 * See eas.h. GPLv3, same as RENDER.
 */
#define _GNU_SOURCE
#include "eas.h"

#include <ctype.h>
#include <dirent.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#define EAS_MAX_ALERTS 256
#define EAS_MAX_OSN    32
#define EAS_XML_KEEP   8192

/* ------------------------------------------------------------------ */
/* Per-capture state                                                   */
/* ------------------------------------------------------------------ */
typedef struct {
    AeaEntry a;           /* copied fields (media list not kept)   */
    char media[512];      /* "type url; ..." summary                */
    double first, last;   /* packet time (see timing)               */
    long count;
    char *xml;            /* raw AEAT XML from first sighting       */
} EasAlert;

typedef struct {
    char *xml;
    double first, last;
    long count;
} EasOsn;

static struct timeval g_cur_ts;
static int g_have_ts = 0;

static EasAlert g_alerts[EAS_MAX_ALERTS];
static int g_alert_count = 0;
static long g_aeat_seen = 0, g_aeat_empty = 0;
static double g_aeat_first = NAN, g_aeat_last = NAN;
static char *g_pending_aeat_xml = NULL;

static EasOsn g_osn[EAS_MAX_OSN];
static int g_osn_count = 0;

static char g_bsid[32] = "";
static char g_services[1024] = "";
static char g_eas_services[512] = "";

static char g_input[1024] = "";
static eas_timing_t g_timing = EAS_TIMING_NONE;
static double g_cap_first = NAN, g_cap_last = NAN;
static double g_duration_hint = 0;
static time_t g_file_start = 0;     /* from the capture's file name */
static unsigned g_rf = 0;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */
static double tv_d(const struct timeval *tv) { return tv->tv_sec + tv->tv_usec / 1e6; }

static void copy_str(char *dst, size_t n, const char *src) {
    if (!src) { dst[0] = '\0'; return; }
    snprintf(dst, n, "%s", src);
}

static const char *base_name(const char *p) {
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

/* "rf27-bsid1234-p0-20261117-122000.pcap" -> rf, start time */
static void parse_capture_name(const char *path, unsigned *rf, time_t *start, long *id, char *idkind) {
    const char *b = base_name(path);
    if (rf) *rf = 0;
    if (start) *start = 0;
    if (id) *id = -1;
    if (idkind) idkind[0] = '\0';
    if (rf && strncmp(b, "rf", 2) == 0 && isdigit((unsigned char)b[2])) *rf = (unsigned)strtoul(b + 2, NULL, 10);
    const char *k = strstr(b, "-bsid");
    if (!k) k = strstr(b, "-tsid");
    if (k && id) {
        *id = strtol(k + 5, NULL, 10);
        if (idkind) { memcpy(idkind, k + 1, 4); idkind[4] = '\0'; }
    }
    if (start) {
        size_t L = strlen(b);
        for (size_t i = 0; i + 15 <= L; i++) {
            int ok = 1;
            for (int j = 0; j < 15 && ok; j++) {
                char c = b[i + j];
                ok = (j == 8) ? (c == '-') : isdigit((unsigned char)c);
            }
            if (!ok) continue;
            if (i + 15 < L && isdigit((unsigned char)b[i + 15])) continue;
            struct tm tmv;
            memset(&tmv, 0, sizeof(tmv));
            if (sscanf(b + i, "%4d%2d%2d-%2d%2d%2d", &tmv.tm_year, &tmv.tm_mon, &tmv.tm_mday,
                       &tmv.tm_hour, &tmv.tm_min, &tmv.tm_sec) == 6) {
                tmv.tm_year -= 1900;
                tmv.tm_mon -= 1;
                tmv.tm_isdst = -1;
                *start = mktime(&tmv);
            }
        }
    }
}

/* Packet time -> wall-clock epoch, or NAN if unknown. */
static double wall(double t) {
    if (isnan(t)) return NAN;
    switch (g_timing) {
        case EAS_TIMING_ABSOLUTE: return t;
        case EAS_TIMING_RELATIVE: return g_file_start ? (double)g_file_start + t : NAN;
        default: return NAN;
    }
}

static void fmt_wall(double epoch, char *out, size_t n) {
    if (isnan(epoch)) { snprintf(out, n, "&mdash;"); return; }
    time_t s = (time_t)epoch;
    struct tm tmv;
    localtime_r(&s, &tmv);
    char a[48], z[16];
    strftime(a, sizeof(a), "%Y-%m-%d %H:%M:%S", &tmv);
    strftime(z, sizeof(z), "%Z", &tmv);
    snprintf(out, n, "%s.%d %s", a, (int)((epoch - floor(epoch)) * 10), z);
}

static void html_esc(FILE *f, const char *s) {
    for (; s && *s; s++) {
        switch (*s) {
            case '<': fputs("&lt;", f); break;
            case '>': fputs("&gt;", f); break;
            case '&': fputs("&amp;", f); break;
            case '"': fputs("&quot;", f); break;
            default: fputc(*s, f);
        }
    }
}

/* TSV-safe: tabs/newlines become spaces. */
static void tsv(FILE *f, const char *s) {
    for (; s && *s; s++) fputc((*s == '\t' || *s == '\n' || *s == '\r') ? ' ' : *s, f);
}

static void tsv_num(FILE *f, double v) {
    if (!isnan(v)) fprintf(f, "%.3f", v);
}

static int is_national_test(const AeaEntry *a) {
    return strcasecmp(a->eventCode, "NPT") == 0 ||
           strcasestr(a->eventDesc, "nationwide test") != NULL ||
           strcasestr(a->eventDesc, "national periodic test") != NULL ||
           strcasestr(a->aeaText, "nationwide test of the emergency alert system") != NULL;
}

static const char *event_name(const char *code) {
    static const struct { const char *c, *n; } t[] = {
        {"NPT", "National Periodic Test"}, {"EAN", "Emergency Action Notification"},
        {"RMT", "Required Monthly Test"}, {"RWT", "Required Weekly Test"},
        {"DMO", "Practice/Demo Warning"}, {"ADR", "Administrative Message"},
        {"TOR", "Tornado Warning"}, {"SVR", "Severe Thunderstorm Warning"},
        {"FFW", "Flash Flood Warning"}, {"CAE", "Child Abduction Emergency"},
        {"CEM", "Civil Emergency Message"}, {NULL, NULL}
    };
    for (int i = 0; t[i].c; i++) if (strcasecmp(code, t[i].c) == 0) return t[i].n;
    return "";
}

/* ------------------------------------------------------------------ */
/* Recording                                                           */
/* ------------------------------------------------------------------ */
void eas_note_packet(const struct timeval *ts) {
    if (ts) { g_cur_ts = *ts; g_have_ts = 1; }
}

static double now_pkt(void) { return g_have_ts ? tv_d(&g_cur_ts) : NAN; }

void eas_note_xml(const char *root_name, const char *xml, int len) {
    if (!root_name || !xml || len <= 0) return;
    if (strcmp(root_name, "AEAT") == 0) {
        free(g_pending_aeat_xml);
        int n = len < EAS_XML_KEEP ? len : EAS_XML_KEEP;
        g_pending_aeat_xml = strndup(xml, n);
        return;
    }
    if (strcmp(root_name, "OnscreenMessageNotification") == 0) {
        int n = len < 2048 ? len : 2048;
        double t = now_pkt();
        for (int i = 0; i < g_osn_count; i++) {
            if ((int)strlen(g_osn[i].xml) == n && strncmp(g_osn[i].xml, xml, n) == 0) {
                g_osn[i].last = t;
                g_osn[i].count++;
                return;
            }
        }
        if (g_osn_count < EAS_MAX_OSN) {
            EasOsn *o = &g_osn[g_osn_count++];
            o->xml = strndup(xml, n);
            o->first = o->last = t;
            o->count = 1;
        }
    }
}

void eas_note_aeat(const AeatData *aeat) {
    double t = now_pkt();
    g_aeat_seen++;
    if (isnan(g_aeat_first)) g_aeat_first = t;
    g_aeat_last = t;
    if (!aeat || aeat->aea_count == 0 || !aeat->head_aea) {
        g_aeat_empty++;
        free(g_pending_aeat_xml);
        g_pending_aeat_xml = NULL;
        return;
    }
    for (const AeaEntry *e = aeat->head_aea; e; e = e->next) {
        EasAlert *hit = NULL;
        for (int i = 0; i < g_alert_count; i++) {
            const AeaEntry *k = &g_alerts[i].a;
            if (strcmp(k->aeaId, e->aeaId) == 0 && strcmp(k->aeaType, e->aeaType) == 0 &&
                strcmp(k->eventCode, e->eventCode) == 0 && strcmp(k->effective, e->effective) == 0 &&
                strcmp(k->aeaText, e->aeaText) == 0) {
                hit = &g_alerts[i];
                break;
            }
        }
        if (hit) {
            hit->last = t;
            hit->count++;
            continue;
        }
        if (g_alert_count >= EAS_MAX_ALERTS) continue;
        EasAlert *n = &g_alerts[g_alert_count++];
        memset(n, 0, sizeof(*n));
        n->a = *e;
        n->a.head_media = NULL;
        n->a.next = NULL;
        size_t used = 0;
        for (const AeatMedia *m = e->head_media; m && used < sizeof(n->media) - 1; m = m->next) {
            used += snprintf(n->media + used, sizeof(n->media) - used, "%s%s %s",
                             used ? "; " : "", m->mediaType[0] ? m->mediaType : m->contentType, m->url);
        }
        n->first = n->last = t;
        n->count = 1;
        n->xml = g_pending_aeat_xml ? strdup(g_pending_aeat_xml) : NULL;
    }
    free(g_pending_aeat_xml);
    g_pending_aeat_xml = NULL;
}

void eas_set_station(const char *bsid, const char *services, const char *eas_services) {
    copy_str(g_bsid, sizeof(g_bsid), bsid);
    copy_str(g_services, sizeof(g_services), services);
    copy_str(g_eas_services, sizeof(g_eas_services), eas_services);
}

void eas_set_capture(const char *input_path, eas_timing_t timing,
                     const struct timeval *first, const struct timeval *last,
                     double duration_hint_s) {
    copy_str(g_input, sizeof(g_input), input_path);
    g_timing = timing;
    g_cap_first = first ? tv_d(first) : NAN;
    g_cap_last = last ? tv_d(last) : NAN;
    g_duration_hint = duration_hint_s;
    parse_capture_name(input_path, &g_rf, &g_file_start, NULL, NULL);
}

/* ------------------------------------------------------------------ */
/* HTML section in the normal report                                   */
/* ------------------------------------------------------------------ */
static const char *timing_label(void) {
    switch (g_timing) {
        case EAS_TIMING_ABSOLUTE: return "packet timestamps (capture host clock)";
        case EAS_TIMING_RELATIVE: return g_file_start ? "estimated from -t, anchored to the file-name start time"
                                                       : "estimated from -t (no start time in file name)";
        default: return "none (debug capture without -t: only the segment start is known)";
    }
}

static void fmt_offset(double t, char *out, size_t n) {
    if (isnan(t) || isnan(g_cap_first) || g_timing == EAS_TIMING_NONE) { out[0] = 0; (void)n; return; }
    double base = (g_timing == EAS_TIMING_RELATIVE) ? 0.0 : g_cap_first;
    snprintf(out, n, " (+%.1fs)", t - base);
}

void eas_write_html_section(FILE *f) {
    char a[96], b[96], off[48];
    int any_npt = 0;
    for (int i = 0; i < g_alert_count; i++) any_npt |= is_national_test(&g_alerts[i].a);

    fprintf(f, "<style>\n"
               ".eas-box{border:2px solid #dc3545;border-radius:8px;padding:1em;margin:1em 0;background:#fff8f8}\n"
               ".eas-box h2{margin-top:0;color:#b02a37;border-bottom-color:#f1aeb5}\n"
               ".eas-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.85em;font-weight:600;margin-left:6px}\n"
               ".eas-npt{background:#b02a37;color:#fff}.eas-none{background:#6c757d;color:#fff}.eas-some{background:#fd7e14;color:#fff}\n"
               ".eas-kv td:first-child{width:220px;font-weight:600}.eas-nw{white-space:nowrap}\n"
               "</style>\n");
    fprintf(f, "<div class='eas-box' id='eas'>\n<h2>&#x1F6A8; EAS / Alert Timeline");
    if (any_npt) fprintf(f, "<span class='eas-badge eas-npt'>NATIONWIDE TEST SEEN</span>");
    else if (g_alert_count) fprintf(f, "<span class='eas-badge eas-some'>%d alert%s</span>", g_alert_count, g_alert_count == 1 ? "" : "s");
    else fprintf(f, "<span class='eas-badge eas-none'>no AEAT alerts in this capture</span>");
    fprintf(f, "</h2>\n<table class='eas-kv'>\n");

    double ws = wall(g_timing == EAS_TIMING_RELATIVE ? 0.0 : g_cap_first);
    double we = wall(g_timing == EAS_TIMING_RELATIVE ? (isnan(g_cap_last) ? NAN : g_cap_last) : g_cap_last);
    if (g_timing == EAS_TIMING_NONE && g_file_start) ws = (double)g_file_start;
    fmt_wall(ws, a, sizeof(a));
    fmt_wall(we, b, sizeof(b));
    fprintf(f, "<tr><td>Capture window</td><td>%s &ndash; %s</td></tr>\n", a, b);
    fprintf(f, "<tr><td>Timing source</td><td>%s</td></tr>\n", timing_label());
    fprintf(f, "<tr><td>Station</td><td>%s%u%s BSID %s</td></tr>\n", g_rf ? "RF " : "", g_rf, g_rf ? "," : "",
            g_bsid[0] ? g_bsid : "unknown");
    fprintf(f, "<tr><td>Services (SLT)</td><td>");
    html_esc(f, g_services[0] ? g_services : "none found");
    fprintf(f, "</td></tr>\n<tr><td>EAS-category services</td><td>");
    html_esc(f, g_eas_services[0] ? g_eas_services : "none");
    fprintf(f, "</td></tr>\n");

    if (g_aeat_seen) {
        fmt_wall(wall(g_aeat_first), a, sizeof(a));
        fmt_wall(wall(g_aeat_last), b, sizeof(b));
        fprintf(f, "<tr><td>AEAT carried</td><td>%ld time%s (%ld empty), first %s, last %s</td></tr>\n",
                g_aeat_seen, g_aeat_seen == 1 ? "" : "s", g_aeat_empty, a, b);
    } else {
        fprintf(f, "<tr><td>AEAT carried</td><td>not seen in this capture</td></tr>\n");
    }
    fprintf(f, "<tr><td>On-screen message notices</td><td>%d distinct</td></tr>\n</table>\n", g_osn_count);

    if (g_alert_count) {
        fprintf(f, "<h3>Alerts</h3>\n<table>\n<tr><th>First seen</th><th>Last seen</th><th>#</th><th>Type</th>"
                   "<th>Event</th><th>Issuer / Priority / Wakeup</th><th>Effective &ndash; Expires</th>"
                   "<th>Location</th><th>Text</th></tr>\n");
        for (int i = 0; i < g_alert_count; i++) {
            const EasAlert *e = &g_alerts[i];
            fmt_wall(wall(e->first), a, sizeof(a));
            fmt_offset(e->first, off, sizeof(off));
            fprintf(f, "<tr><td>%s%s</td>", a, off);
            fmt_wall(wall(e->last), b, sizeof(b));
            fprintf(f, "<td>%s</td><td class='eas-nw'>%ld</td><td class='eas-nw'>", b, e->count);
            html_esc(f, e->a.aeaType);
            fprintf(f, "<br><small>id ");
            html_esc(f, e->a.aeaId);
            fprintf(f, "</small></td><td><strong>");
            html_esc(f, e->a.eventCode);
            fprintf(f, "</strong> ");
            html_esc(f, e->a.eventDesc[0] ? e->a.eventDesc : event_name(e->a.eventCode));
            if (is_national_test(&e->a)) fprintf(f, "<span class='eas-badge eas-npt'>NPT</span>");
            fprintf(f, "</td><td>");
            html_esc(f, e->a.issuer);
            fprintf(f, " / %s / %s</td><td>", e->a.priority[0] ? e->a.priority : "-", e->a.wakeup[0] ? e->a.wakeup : "-");
            html_esc(f, e->a.effective);
            fprintf(f, " &ndash; ");
            html_esc(f, e->a.expires);
            fprintf(f, "</td><td>");
            html_esc(f, e->a.locationType);
            fprintf(f, " ");
            html_esc(f, e->a.location);
            fprintf(f, "</td><td>");
            html_esc(f, e->a.aeaText);
            if (e->media[0]) { fprintf(f, "<br><small>Media: "); html_esc(f, e->media); fprintf(f, "</small>"); }
            fprintf(f, "</td></tr>\n");
        }
        fprintf(f, "</table>\n");
        for (int i = 0; i < g_alert_count; i++) {
            if (!g_alerts[i].xml) continue;
            fprintf(f, "<details><summary>Raw AEAT XML &ndash; alert %d (", i + 1);
            html_esc(f, g_alerts[i].a.aeaId);
            fprintf(f, ")</summary><div class='details-content'><pre>");
            html_esc(f, g_alerts[i].xml);
            fprintf(f, "</pre></div></details>\n");
        }
    }

    if (g_osn_count) {
        fprintf(f, "<h3>On-Screen Message Notification (keep-screen-clear signalling)</h3>\n"
                   "<table><tr><th>First seen</th><th>Last seen</th><th>#</th><th>Content</th></tr>\n");
        for (int i = 0; i < g_osn_count; i++) {
            fmt_wall(wall(g_osn[i].first), a, sizeof(a));
            fmt_wall(wall(g_osn[i].last), b, sizeof(b));
            fprintf(f, "<tr><td>%s</td><td>%s</td><td>%ld</td><td><pre>", a, b, g_osn[i].count);
            html_esc(f, g_osn[i].xml);
            fprintf(f, "</pre></td></tr>\n");
        }
        fprintf(f, "</table>\n");
    }
    fprintf(f, "<p style='margin-bottom:0'><small>Note: on ATSC 3.0 the on-air EAS crawl and audio are carried in the "
               "program itself. The AEAT is extra signalling that a station may or may not send for a test, "
               "so \"no AEAT\" doesn't mean the station missed the test.</small></p>\n</div>\n");
}

/* ------------------------------------------------------------------ */
/* Sidecar                                                             */
/* ------------------------------------------------------------------ */
static void sidecar_path(const char *input_path, char *out, size_t n) {
    snprintf(out, n, "%s", input_path);
    char *dot = strrchr(out, '.');
    char *slash = strrchr(out, '/');
    if (dot && (!slash || dot > slash)) *dot = '\0';
    size_t L = strlen(out);
    snprintf(out + L, n - L, ".eas.tsv");
}

int eas_write_sidecar(const char *input_path) {
    char path[1100];
    sidecar_path(input_path, path, sizeof(path));
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    double ws = wall(g_timing == EAS_TIMING_RELATIVE ? 0.0 : g_cap_first);
    double we = wall(g_cap_last);
    fprintf(f, "#render-eas\t1\n");
    fprintf(f, "input\t"); tsv(f, base_name(input_path)); fputc('\n', f);
    fprintf(f, "rf\t%u\n", g_rf);
    fprintf(f, "bsid\t"); tsv(f, g_bsid); fputc('\n', f);
    fprintf(f, "services\t"); tsv(f, g_services); fputc('\n', f);
    fprintf(f, "eas_services\t"); tsv(f, g_eas_services); fputc('\n', f);
    fprintf(f, "timing\t%s\n", g_timing == EAS_TIMING_ABSOLUTE ? "absolute" : g_timing == EAS_TIMING_RELATIVE ? "relative" : "none");
    fprintf(f, "file_start\t"); if (g_file_start) fprintf(f, "%ld", (long)g_file_start); fputc('\n', f);
    fprintf(f, "capture_start\t"); tsv_num(f, ws); fputc('\n', f);
    fprintf(f, "capture_end\t"); tsv_num(f, we); fputc('\n', f);
    fprintf(f, "aeat_seen\t%ld\n", g_aeat_seen);
    fprintf(f, "aeat_empty\t%ld\n", g_aeat_empty);
    fprintf(f, "aeat_first\t"); tsv_num(f, wall(g_aeat_first)); fputc('\n', f);
    fprintf(f, "aeat_last\t"); tsv_num(f, wall(g_aeat_last)); fputc('\n', f);
    for (int i = 0; i < g_osn_count; i++) {
        fprintf(f, "osn\t"); tsv_num(f, wall(g_osn[i].first));
        fprintf(f, "\t"); tsv_num(f, wall(g_osn[i].last));
        fprintf(f, "\t%ld\t", g_osn[i].count); tsv(f, g_osn[i].xml); fputc('\n', f);
    }
    for (int i = 0; i < g_alert_count; i++) {
        const EasAlert *e = &g_alerts[i];
        fprintf(f, "alert\t"); tsv_num(f, wall(e->first));
        fprintf(f, "\t"); tsv_num(f, wall(e->last));
        fprintf(f, "\t%ld", e->count);
        const char *fields[] = { e->a.aeaId, e->a.aeaType, e->a.priority, e->a.wakeup, e->a.issuer,
                                 e->a.audience, e->a.category, e->a.eventCodeType, e->a.eventCode,
                                 e->a.eventDesc, e->a.effective, e->a.expires, e->a.locationType,
                                 e->a.location, e->a.aeaTextLang, e->a.aeaText, e->media };
        for (size_t k = 0; k < sizeof(fields) / sizeof(fields[0]); k++) { fputc('\t', f); tsv(f, fields[k]); }
        fputc('\n', f);
    }
    fclose(f);
    printf("Wrote EAS sidecar: %s\n", path);
    return 0;
}

/* ------------------------------------------------------------------ */
/* --eas-summary                                                       */
/* ------------------------------------------------------------------ */
#define F_ALERT_FIELDS 20

typedef struct {
    char path[1100];          /* sidecar path                         */
    char input[512];          /* capture base name                    */
    char dir[1024];
    unsigned rf;
    char bsid[32];
    char services[1024];
    char eas_services[512];
    char timing[16];
    double file_start, cap_start, cap_end, aeat_first, aeat_last;
    long aeat_seen, aeat_empty;
    int n_osn, n_alert;
    char **alerts;            /* raw "alert" lines (split later)     */
    char **osn;
} Sidecar;

typedef struct {
    char path[1100];
    char dir[1024];
    unsigned rf;
    long id;
    char kind[8];
    time_t start;
    long long size;
} Plain;   /* ATSC 1.0 .ts, or a 3.0 capture that hasn't been rendered */

static double num_or_nan(const char *s) {
    if (!s || !*s) return NAN;
    char *e;
    double v = strtod(s, &e);
    return e == s ? NAN : v;
}

static void chomp(char *s) {
    size_t L = strlen(s);
    while (L && (s[L - 1] == '\n' || s[L - 1] == '\r')) s[--L] = '\0';
}

static int load_sidecar(const char *path, Sidecar *sc) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    memset(sc, 0, sizeof(*sc));
    snprintf(sc->path, sizeof(sc->path), "%s", path);
    snprintf(sc->dir, sizeof(sc->dir), "%s", path);
    char *sl = strrchr(sc->dir, '/');
    if (sl) *sl = '\0'; else snprintf(sc->dir, sizeof(sc->dir), ".");
    sc->file_start = sc->cap_start = sc->cap_end = sc->aeat_first = sc->aeat_last = NAN;
    char *line = NULL;
    size_t cap = 0;
    int ok = 0;
    while (getline(&line, &cap, f) > 0) {
        chomp(line);
        char *tab = strchr(line, '\t');
        if (!tab) continue;
        *tab = '\0';
        char *v = tab + 1;
        if (strcmp(line, "#render-eas") == 0) ok = 1;
        else if (strcmp(line, "input") == 0) snprintf(sc->input, sizeof(sc->input), "%s", v);
        else if (strcmp(line, "rf") == 0) sc->rf = (unsigned)strtoul(v, NULL, 10);
        else if (strcmp(line, "bsid") == 0) snprintf(sc->bsid, sizeof(sc->bsid), "%s", v);
        else if (strcmp(line, "services") == 0) snprintf(sc->services, sizeof(sc->services), "%s", v);
        else if (strcmp(line, "eas_services") == 0) snprintf(sc->eas_services, sizeof(sc->eas_services), "%s", v);
        else if (strcmp(line, "timing") == 0) snprintf(sc->timing, sizeof(sc->timing), "%s", v);
        else if (strcmp(line, "file_start") == 0) sc->file_start = num_or_nan(v);
        else if (strcmp(line, "capture_start") == 0) sc->cap_start = num_or_nan(v);
        else if (strcmp(line, "capture_end") == 0) sc->cap_end = num_or_nan(v);
        else if (strcmp(line, "aeat_seen") == 0) sc->aeat_seen = atol(v);
        else if (strcmp(line, "aeat_empty") == 0) sc->aeat_empty = atol(v);
        else if (strcmp(line, "aeat_first") == 0) sc->aeat_first = num_or_nan(v);
        else if (strcmp(line, "aeat_last") == 0) sc->aeat_last = num_or_nan(v);
        else if (strcmp(line, "alert") == 0) {
            sc->alerts = realloc(sc->alerts, sizeof(char *) * (sc->n_alert + 1));
            sc->alerts[sc->n_alert++] = strdup(v);
        } else if (strcmp(line, "osn") == 0) {
            sc->osn = realloc(sc->osn, sizeof(char *) * (sc->n_osn + 1));
            sc->osn[sc->n_osn++] = strdup(v);
        }
    }
    free(line);
    fclose(f);
    if (!ok) return -1;
    if (isnan(sc->cap_start) && !isnan(sc->file_start)) sc->cap_start = sc->file_start;
    return 0;
}

/* Split a tab-separated line in place. */
static int split_tabs(char *s, char **out, int max) {
    int n = 0;
    out[n++] = s;
    for (char *p = s; *p && n < max; p++) {
        if (*p == '\t') { *p = '\0'; out[n++] = p + 1; }
    }
    return n;
}

typedef struct {
    const Sidecar *sc;
    double first, last;
    long count;
    char *f[F_ALERT_FIELDS];  /* after first/last/count */
    int nf;
} FlatAlert;

static int cmp_flat(const void *a, const void *b) {
    const FlatAlert *x = a, *y = b;
    double fx = isnan(x->first) ? 1e18 : x->first, fy = isnan(y->first) ? 1e18 : y->first;
    return fx < fy ? -1 : fx > fy;
}

static int cmp_sc(const void *a, const void *b) {
    const Sidecar *x = a, *y = b;
    if (x->rf != y->rf) return x->rf < y->rf ? -1 : 1;
    int c = strcmp(x->bsid, y->bsid);
    if (c) return c;
    double sx = isnan(x->cap_start) ? 0 : x->cap_start, sy = isnan(y->cap_start) ? 0 : y->cap_start;
    if (sx != sy) return sx < sy ? -1 : 1;
    return strcmp(x->input, y->input);
}

static int cmp_plain(const void *a, const void *b) {
    const Plain *x = a, *y = b;
    if (x->rf != y->rf) return x->rf < y->rf ? -1 : 1;
    return x->start < y->start ? -1 : x->start > y->start;
}

static void link_to(FILE *f, const char *out_dir, const char *dir, const char *name, const char *text) {
    char target[2200];
    if (strcmp(out_dir, dir) == 0) snprintf(target, sizeof(target), "%s", name);
    else snprintf(target, sizeof(target), "%s/%s", dir, name);
    fprintf(f, "<a href='");
    html_esc(f, target);
    fprintf(f, "'>");
    html_esc(f, text);
    fprintf(f, "</a>");
}

static int file_exists(const char *dir, const char *name) {
    char p[2200];
    snprintf(p, sizeof(p), "%s/%s", dir, name);
    struct stat st;
    return stat(p, &st) == 0;
}

static void swap_ext(const char *name, const char *ext, char *out, size_t n) {
    snprintf(out, n, "%s", name);
    char *dot = strrchr(out, '.');
    if (dot) *dot = '\0';
    size_t L = strlen(out);
    snprintf(out + L, n - L, "%s", ext);
}

static int ends_with(const char *s, const char *suf) {
    size_t a = strlen(s), b = strlen(suf);
    return a >= b && strcasecmp(s + a - b, suf) == 0;
}

int eas_summary_main(int argc, char **argv) {
    /* argv: render --eas-summary out.html paths... */
    int ai = 1;
    while (ai < argc && strcmp(argv[ai], "--eas-summary") != 0) ai++;
    if (ai + 2 >= argc) {
        fprintf(stderr, "Usage: %s --eas-summary <out.html> <capture-dir | file.eas.tsv>...\n", argv[0]);
        return 1;
    }
    const char *out_path = argv[ai + 1];
    char out_dir[1024];
    snprintf(out_dir, sizeof(out_dir), "%s", out_path);
    char *sl = strrchr(out_dir, '/');
    if (sl) *sl = '\0'; else snprintf(out_dir, sizeof(out_dir), ".");

    Sidecar *scs = NULL; int nsc = 0;
    Plain *plain = NULL; int nplain = 0;      /* ATSC 1.0 .ts */
    Plain *todo = NULL; int ntodo = 0;        /* 3.0 captures without sidecar */

    for (int i = ai + 2; i < argc; i++) {
        struct stat st;
        if (stat(argv[i], &st) != 0) { fprintf(stderr, "Skipping %s (not found)\n", argv[i]); continue; }
        char **names = NULL; int nn = 0;
        char dir[1024];
        if (S_ISDIR(st.st_mode)) {
            snprintf(dir, sizeof(dir), "%s", argv[i]);
            size_t L = strlen(dir);
            while (L > 1 && dir[L - 1] == '/') dir[--L] = '\0';
            DIR *d = opendir(dir);
            if (!d) continue;
            struct dirent *de;
            while ((de = readdir(d))) {
                names = realloc(names, sizeof(char *) * (nn + 1));
                names[nn++] = strdup(de->d_name);
            }
            closedir(d);
        } else {
            snprintf(dir, sizeof(dir), "%s", argv[i]);
            char *s2 = strrchr(dir, '/');
            if (s2) *s2 = '\0'; else snprintf(dir, sizeof(dir), ".");
            names = malloc(sizeof(char *));
            names[nn++] = strdup(base_name(argv[i]));
        }
        for (int k = 0; k < nn; k++) {
            const char *nm = names[k];
            char full[2200];
            snprintf(full, sizeof(full), "%s/%s", dir, nm);
            if (ends_with(nm, ".eas.tsv")) {
                scs = realloc(scs, sizeof(Sidecar) * (nsc + 1));
                if (load_sidecar(full, &scs[nsc]) == 0) nsc++;
            } else if (ends_with(nm, ".ts") || ends_with(nm, ".pcap") || ends_with(nm, ".dbg")) {
                int is_ts = ends_with(nm, ".ts");
                char side[1200];
                swap_ext(nm, ".eas.tsv", side, sizeof(side));
                if (!is_ts && file_exists(dir, side)) continue;
                Plain p;
                memset(&p, 0, sizeof(p));
                snprintf(p.path, sizeof(p.path), "%s", nm);
                snprintf(p.dir, sizeof(p.dir), "%s", dir);
                parse_capture_name(nm, &p.rf, &p.start, &p.id, p.kind);
                struct stat fs;
                if (stat(full, &fs) == 0) p.size = fs.st_size;
                if (is_ts) { plain = realloc(plain, sizeof(Plain) * (nplain + 1)); plain[nplain++] = p; }
                else { todo = realloc(todo, sizeof(Plain) * (ntodo + 1)); todo[ntodo++] = p; }
            }
            free(names[k]);
        }
        free(names);
    }

    if (nsc > 1) qsort(scs, nsc, sizeof(Sidecar), cmp_sc);
    if (nplain > 1) qsort(plain, nplain, sizeof(Plain), cmp_plain);
    if (ntodo > 1) qsort(todo, ntodo, sizeof(Plain), cmp_plain);

    /* Flatten alerts for the headline timeline */
    FlatAlert *fa = NULL; int nfa = 0;
    for (int i = 0; i < nsc; i++) {
        for (int k = 0; k < scs[i].n_alert; k++) {
            char *copy = strdup(scs[i].alerts[k]);
            char *parts[F_ALERT_FIELDS + 3];
            int np = split_tabs(copy, parts, F_ALERT_FIELDS + 3);
            if (np < 4) { free(copy); continue; }
            fa = realloc(fa, sizeof(FlatAlert) * (nfa + 1));
            FlatAlert *x = &fa[nfa++];
            x->sc = &scs[i];
            x->first = num_or_nan(parts[0]);
            x->last = num_or_nan(parts[1]);
            x->count = atol(parts[2]);
            x->nf = np - 3;
            for (int j = 0; j < F_ALERT_FIELDS; j++) x->f[j] = (j < x->nf) ? parts[j + 3] : "";
        }
    }
    if (nfa > 1) qsort(fa, nfa, sizeof(FlatAlert), cmp_flat);
    /* alert fields: 0 aeaId 1 aeaType 2 priority 3 wakeup 4 issuer 5 audience 6 category
                     7 eventCodeType 8 eventCode 9 eventDesc 10 effective 11 expires
                     12 locationType 13 location 14 lang 15 text 16 media */

    FILE *f = fopen(out_path, "w");
    if (!f) { perror(out_path); return 1; }
    char a[96], b[96];
    time_t gen = time(NULL);
    fmt_wall((double)gen, a, sizeof(a));

    fprintf(f, "<!DOCTYPE html>\n<html lang='en'><head><meta charset='UTF-8'>\n"
               "<meta name='viewport' content='width=device-width, initial-scale=1.0'>\n"
               "<title>HDHR EAS Test - EAS Summary</title>\n<style>\n"
               "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:14px;line-height:1.4;margin:1em;background:#f8f9fa;color:#212529}\n"
               ".container{background:#fff;padding:1.5em;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,.1);max-width:1300px;margin:auto}\n"
               "h1{font-size:1.8em;border-bottom:2px solid #dc3545;padding-bottom:.3em}h2{font-size:1.35em;border-bottom:1px solid #dee2e6;margin-top:1.4em}\n"
               "table{border-collapse:collapse;width:100%%;margin-top:.6em}th,td{border:1px solid #dee2e6;padding:5px 8px;text-align:left;vertical-align:top;word-break:break-word}\n"
               "th{background:#e9ecef}tr:nth-child(even){background:#f8f9fa}.muted{color:#6c757d}\n"
               ".b{display:inline-block;padding:1px 7px;border-radius:4px;font-size:.85em;font-weight:600;color:#fff}\n"
               ".npt{background:#b02a37}.yes{background:#fd7e14}.no{background:#adb5bd}.ok{background:#198754}\n"
               "pre{white-space:pre-wrap;margin:0;font-size:12px}.nw{white-space:nowrap}\n"
               "</style></head><body><div class='container'>\n");
    fprintf(f, "<h1>&#x1F6A8; HDHR EAS Test - EAS Summary</h1>\n<p class='muted'>Generated %s &middot; %d ATSC 3.0 capture%s analyzed",
            a, nsc, nsc == 1 ? "" : "s");
    if (nplain) fprintf(f, " &middot; %d ATSC 1.0 recording%s listed", nplain, nplain == 1 ? "" : "s");
    if (ntodo) fprintf(f, " &middot; <strong>%d ATSC 3.0 capture%s not yet rendered</strong>", ntodo, ntodo == 1 ? "" : "s");
    fprintf(f, "</p>\n<p class='muted'>Nov 17, 2026 nationwide EAS test: 2:20&ndash;2:50 p.m. ET "
               "(12:20&ndash;12:50 p.m. MST). This test is EAS only: TV/radio, no phone alerts.</p>\n");

    /* 1. Alert timeline */
    fprintf(f, "<h2>Alert timeline (all stations)</h2>\n");
    if (!nfa) {
        fprintf(f, "<p>No AEAT alerts were found in any capture. On ATSC 3.0 the EAS crawl/audio is in the program "
                   "itself; check the stations' video for the on-air test.</p>\n");
    } else {
        fprintf(f, "<table><tr><th>First seen</th><th>Last seen</th><th>Station</th><th>Event</th><th>Type</th>"
                   "<th>Issuer</th><th>Text</th><th>Seen in</th></tr>\n");
        for (int i = 0; i < nfa; i++) {
            FlatAlert *x = &fa[i];
            int npt = strcasecmp(x->f[8], "NPT") == 0 || strcasestr(x->f[9], "nationwide test") ||
                      strcasestr(x->f[15], "nationwide test of the emergency alert system");
            fmt_wall(x->first, a, sizeof(a));
            fmt_wall(x->last, b, sizeof(b));
            fprintf(f, "<tr><td>%s</td><td>%s</td><td>RF %u BSID ", a, b, x->sc->rf);
            html_esc(f, x->sc->bsid[0] ? x->sc->bsid : "?");
            fprintf(f, "<br><small>");
            html_esc(f, x->sc->services);
            fprintf(f, "</small></td><td><strong>");
            html_esc(f, x->f[8]);
            fprintf(f, "</strong> ");
            html_esc(f, x->f[9][0] ? x->f[9] : event_name(x->f[8]));
            if (npt) fprintf(f, " <span class='b npt'>NPT</span>");
            fprintf(f, "</td><td class='nw'>");
            html_esc(f, x->f[1]);
            fprintf(f, "</td><td class='nw'>");
            html_esc(f, x->f[4]);
            fprintf(f, "</td><td>");
            html_esc(f, x->f[15]);
            fprintf(f, "</td><td>");
            char html_name[600];
            swap_ext(x->sc->input, ".html", html_name, sizeof(html_name));
            if (file_exists(x->sc->dir, html_name)) link_to(f, out_dir, x->sc->dir, html_name, x->sc->input);
            else html_esc(f, x->sc->input);
            fprintf(f, " (%ld&times;)</td></tr>\n", x->count);
        }
        fprintf(f, "</table>\n");
    }

    /* 2. Per-station segments */
    fprintf(f, "<h2>ATSC 3.0 stations, segment by segment</h2>\n");
    if (!nsc) fprintf(f, "<p class='muted'>No rendered ATSC 3.0 captures found.</p>\n");
    for (int i = 0; i < nsc;) {
        int j = i;
        while (j < nsc && scs[j].rf == scs[i].rf && strcmp(scs[j].bsid, scs[i].bsid) == 0) j++;
        long alerts = 0, aeat = 0;
        for (int k = i; k < j; k++) { alerts += scs[k].n_alert; aeat += scs[k].aeat_seen; }
        fprintf(f, "<h3>RF %u &middot; BSID ", scs[i].rf);
        html_esc(f, scs[i].bsid[0] ? scs[i].bsid : "?");
        fprintf(f, " &middot; ");
        html_esc(f, scs[i].services[0] ? scs[i].services : "no SLT");
        fprintf(f, " %s</h3>\n", alerts ? "<span class='b yes'>alerts</span>" :
                                 aeat ? "<span class='b ok'>AEAT carried, no alerts</span>" :
                                        "<span class='b no'>no AEAT</span>");
        if (scs[i].eas_services[0]) { fprintf(f, "<p>EAS-category services: "); html_esc(f, scs[i].eas_services); fprintf(f, "</p>\n"); }
        fprintf(f, "<table><tr><th>Segment start</th><th>End</th><th>Capture</th><th>AEAT</th><th>Alerts</th><th>On-screen notices</th></tr>\n");
        for (int k = i; k < j; k++) {
            Sidecar *s = &scs[k];
            fmt_wall(s->cap_start, a, sizeof(a));
            fmt_wall(s->cap_end, b, sizeof(b));
            fprintf(f, "<tr><td>%s%s</td><td>%s</td><td>", a, strcmp(s->timing, "none") == 0 ? " <small class='muted'>(file name)</small>" : "", b);
            char html_name[600];
            swap_ext(s->input, ".html", html_name, sizeof(html_name));
            if (file_exists(s->dir, html_name)) link_to(f, out_dir, s->dir, html_name, s->input);
            else html_esc(f, s->input);
            fprintf(f, "</td><td>%ld%s</td><td>", s->aeat_seen, s->aeat_seen && s->aeat_empty == s->aeat_seen ? " (all empty)" : "");
            for (int m = 0; m < s->n_alert; m++) {
                char *copy = strdup(s->alerts[m]);
                char *p[F_ALERT_FIELDS + 3];
                int np = split_tabs(copy, p, F_ALERT_FIELDS + 3);
                if (np >= 12) {
                    fmt_wall(num_or_nan(p[0]), a, sizeof(a));
                    fprintf(f, "%s<strong>", m ? "<br>" : "");
                    html_esc(f, p[11]);
                    fprintf(f, "</strong> ");
                    html_esc(f, p[4]);
                    fprintf(f, " @ %s", a);
                }
                free(copy);
            }
            if (!s->n_alert) fprintf(f, "<span class='muted'>&mdash;</span>");
            fprintf(f, "</td><td>%d</td></tr>\n", s->n_osn);
        }
        fprintf(f, "</table>\n");
        i = j;
    }

    if (ntodo) {
        fprintf(f, "<h2>ATSC 3.0 captures not rendered yet</h2>\n<p>Run <code>./eas_batch.sh</code> on the folder (or "
                   "<code>./render &lt;file&gt;</code> on each) and rebuild this summary.</p>\n<ul>\n");
        for (int i = 0; i < ntodo; i++) { fprintf(f, "<li>"); html_esc(f, todo[i].path); fprintf(f, "</li>\n"); }
        fprintf(f, "</ul>\n");
    }

    /* 3. ATSC 1.0 recordings */
    if (nplain) {
        fprintf(f, "<h2>ATSC 1.0 recordings (not analyzed &ndash; watch these for the on-air test)</h2>\n"
                   "<p class='muted'>RENDER only analyzes ATSC 3.0. The EAS test on 1.0 stations is in the audio/video; "
                   "open the segments around 12:20&ndash;12:50 MST in VLC or mpv.</p>\n");
        for (int i = 0; i < nplain;) {
            int j = i;
            while (j < nplain && plain[j].rf == plain[i].rf) j++;
            fprintf(f, "<h3>RF %u", plain[i].rf);
            if (plain[i].id > 0) fprintf(f, " &middot; %s %ld (0x%lX)", plain[i].kind, plain[i].id, plain[i].id);
            fprintf(f, "</h3>\n<table><tr><th>Segment start</th><th>File</th><th>Size</th></tr>\n");
            for (int k = i; k < j; k++) {
                fmt_wall(plain[k].start ? (double)plain[k].start : NAN, a, sizeof(a));
                fprintf(f, "<tr><td>%s</td><td>", a);
                link_to(f, out_dir, plain[k].dir, plain[k].path, plain[k].path);
                fprintf(f, "</td><td>%.1f MB</td></tr>\n", plain[k].size / 1048576.0);
            }
            fprintf(f, "</table>\n");
            i = j;
        }
    }

    fprintf(f, "<p class='muted' style='margin-top:2em'>HDHR EAS Test v0.5 &middot; built on RENDER v0.4 by RabbitEars &middot; times shown in this computer's local time zone.</p>\n"
               "</div></body></html>\n");
    fclose(f);
    printf("Wrote EAS summary: %s (%d ATSC 3.0 captures, %d alerts, %d ATSC 1.0 recordings)\n",
           out_path, nsc, nfa, nplain);
    return 0;
}
