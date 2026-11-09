/*
 * Copyright (C) 2026 Brian Scott - HDHR EAS Test.
 * eas_run.c - EAS capture scheduling, saved setup, background runner,
 * pausing other tuner users, and auto-render with RENDER.
 *
 * The TUI's EAS screen saves its setup to ~/.config/hdhr_eas_test/eas.conf
 * and starts this runner in the background (Test Run / Arm). The runner is
 * the same program re-launched with an internal argument; it detaches from
 * the terminal so closing the TUI or an SSH session doesn't stop it. It
 * reports progress in ~/.config/hdhr_eas_test/eas_state for the TUI's
 * monitor screen.
 *
 * Part of the EAS edition of HDHomeRun TUI. GPLv3, same as the TUI.
 */
#include "eas_run.h"
#include "eas_capture.h"
#include "plat.h"
#include "zipw.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifndef _WIN32
#include <sys/wait.h>
#include <unistd.h>
#else
#include <io.h>
#endif

#include "hdhomerun.h"
#include "hdhomerun_device.h"

#define MAX_JOBS EAS_MAX_TUNERS
#define MAX_UNITS 16

/* ------------------------------------------------------------------ */
/* Paths                                                               */
/* ------------------------------------------------------------------ */
static const char *home_dir(void) { return plat_home(); }
static int mkdir_p(const char *path) { return plat_mkdir_p(path); }

const char *eas_config_dir(void) {
    static char dir[1024];
    if (!dir[0]) {
#ifdef _WIN32
        snprintf(dir, sizeof(dir), "%s/HDHR EAS Test", plat_config_base());
#else
        snprintf(dir, sizeof(dir), "%s/hdhr_eas_test", plat_config_base());
#endif
        bool fresh = !plat_is_dir(dir);
        mkdir_p(dir);
#ifndef _WIN32
        if (fresh) {   /* carry settings over from the earlier builds */
            char oldp[1100], newp[1100];
            snprintf(oldp, sizeof(oldp), "%s/.config/hdhomerun_tui/eas.conf", home_dir());
            snprintf(newp, sizeof(newp), "%s/eas.conf", dir);
            FILE *in = fopen(oldp, "r");
            if (in) {
                FILE *out = fopen(newp, "w");
                if (out) { char b[4096]; size_t n; while ((n = fread(b, 1, sizeof(b), in)) > 0) fwrite(b, 1, n, out); fclose(out); }
                fclose(in);
            }
        }
#else
        (void)fresh;
#endif
    }
    return dir;
}

static void cfg_path(const char *name, char *out, size_t n) {
    snprintf(out, n, "%s/%s", eas_config_dir(), name);
}

/* "~/x" -> home/x */
void eas_expand_home(const char *in, char *out, size_t n) { plat_expand_home(in, out, n); }
#define expand_home eas_expand_home

/* ------------------------------------------------------------------ */
/* Config                                                              */
/* ------------------------------------------------------------------ */
void eas_config_defaults(eas_config_t *c) {
    memset(c, 0, sizeof(*c));
    snprintf(c->start, sizeof(c->start), "2026-11-17 12:10");
    snprintf(c->stop, sizeof(c->stop), "2026-11-17 13:00");
    c->seg = 60;
    c->fmt3 = EAS_FMT_PCAP;
    snprintf(c->outdir, sizeof(c->outdir), "~/eas2026");
    c->pause_lead = 60;
    c->auto_render = 1;
    c->test_minutes = 2;
    c->test_seg = 30;
}

int eas_config_load(eas_config_t *c) {
    eas_config_defaults(c);
    char path[600];
    cfg_path("eas.conf", path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return 1;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '#' || !line[0]) continue;
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        const char *k = line, *v = eq + 1;
        if (!strcmp(k, "start")) snprintf(c->start, sizeof(c->start), "%s", v);
        else if (!strcmp(k, "stop")) snprintf(c->stop, sizeof(c->stop), "%s", v);
        else if (!strcmp(k, "seg")) c->seg = atoi(v);
        else if (!strcmp(k, "format")) c->fmt3 = strcmp(v, "dbg") == 0 ? EAS_FMT_DBG : EAS_FMT_PCAP;
        else if (!strcmp(k, "outdir")) snprintf(c->outdir, sizeof(c->outdir), "%s", v);
        else if (!strcmp(k, "pause_units")) snprintf(c->pause_units, sizeof(c->pause_units), "%s", v);
        else if (!strcmp(k, "pause_host")) snprintf(c->pause_ssh, sizeof(c->pause_ssh), "%s", v);
        else if (!strcmp(k, "pause_lead")) c->pause_lead = atoi(v);
        else if (!strcmp(k, "auto_render")) c->auto_render = atoi(v);
        else if (!strcmp(k, "test_minutes")) c->test_minutes = atoi(v);
        else if (!strcmp(k, "test_seg")) c->test_seg = atoi(v);
        else if (!strcmp(k, "tuner") && c->ntuners < EAS_MAX_TUNERS) {
            /* tuner=DEVID IP TUNER CHAN */
            eas_cfg_tuner_t *t = &c->tuners[c->ntuners];
            memset(t, 0, sizeof(*t));
            char chan[48] = "";
            int n = sscanf(v, "%15s %63s %d %47s", t->devid, t->ip, &t->tuner, chan);
            if (n >= 3) {
                if (n == 4 && strcmp(chan, "-") != 0) snprintf(t->chan, sizeof(t->chan), "%s", chan);
                c->ntuners++;
            }
        }
    }
    fclose(f);
    if (c->seg < 10) c->seg = 60;
    if (c->test_minutes < 1) c->test_minutes = 2;
    if (c->test_seg < 10) c->test_seg = 30;
    if (c->pause_lead < 0) c->pause_lead = 60;
    return 0;
}

int eas_config_save(const eas_config_t *c) {
    char path[600], tmp[620];
    cfg_path("eas.conf", path, sizeof(path));
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) return -1;
    fprintf(f, "# HDHR EAS Test v0.5 - setup (edited from the EAS screen)\n");
    fprintf(f, "start=%s\nstop=%s\nseg=%d\nformat=%s\noutdir=%s\n", c->start, c->stop, c->seg,
            c->fmt3 == EAS_FMT_DBG ? "dbg" : "pcap", c->outdir);
    fprintf(f, "pause_units=%s\npause_host=%s\npause_lead=%d\nauto_render=%d\n", c->pause_units,
            c->pause_ssh, c->pause_lead, c->auto_render);
    fprintf(f, "test_minutes=%d\ntest_seg=%d\n", c->test_minutes, c->test_seg);
    for (int i = 0; i < c->ntuners; i++) {
        const eas_cfg_tuner_t *t = &c->tuners[i];
        fprintf(f, "tuner=%s %s %d %s\n", t->devid[0] ? t->devid : "-", t->ip, t->tuner,
                t->chan[0] ? t->chan : "-");
    }
    fclose(f);
    if (plat_rename_replace(tmp, path) < 0) { remove(tmp); return -1; }   /* Windows rename() won't overwrite */
    return 0;
}

eas_cfg_tuner_t *eas_config_find(eas_config_t *c, const char *devid, const char *ip, int tuner) {
    for (int i = 0; i < c->ntuners; i++) {
        eas_cfg_tuner_t *t = &c->tuners[i];
        if (t->tuner != tuner) continue;
        if (devid && devid[0] && t->devid[0] && strcmp(t->devid, "-") != 0) {
            if (strcasecmp(t->devid, devid) == 0) return t;
        } else if (ip && strcmp(t->ip, ip) == 0) {
            return t;
        }
    }
    return NULL;
}

eas_cfg_tuner_t *eas_config_add(eas_config_t *c, const char *devid, const char *ip, int tuner) {
    eas_cfg_tuner_t *t = eas_config_find(c, devid, ip, tuner);
    if (t) {
        if (ip && ip[0]) snprintf(t->ip, sizeof(t->ip), "%s", ip);   /* keep IP current */
        return t;
    }
    if (c->ntuners >= EAS_MAX_TUNERS) return NULL;
    t = &c->tuners[c->ntuners++];
    memset(t, 0, sizeof(*t));
    snprintf(t->devid, sizeof(t->devid), "%s", devid && devid[0] ? devid : "-");
    snprintf(t->ip, sizeof(t->ip), "%s", ip ? ip : "");
    t->tuner = tuner;
    return t;
}

int eas_config_active_count(const eas_config_t *c) {
    int n = 0;
    for (int i = 0; i < c->ntuners; i++) if (c->tuners[i].chan[0]) n++;
    return n;
}

/* "now", "HH:MM[:SS]" (today), "YYYY-MM-DD HH:MM[:SS]" or "YYYY-MM-DDTHH:MM[:SS]". Local time. */
int eas_parse_when(const char *s, time_t *out) {
    if (strcasecmp(s, "now") == 0) { *out = time(NULL); return 0; }
    time_t now = time(NULL);
    struct tm tmv;
    plat_localtime(now, &tmv);
    int Y, M, D, h, m, sec = 0;
    char sep;
    if (sscanf(s, "%d-%d-%d%c%d:%d:%d", &Y, &M, &D, &sep, &h, &m, &sec) >= 6 && (sep == ' ' || sep == 'T')) {
        if (M < 1 || M > 12 || D < 1 || D > 31) return -1;
        tmv.tm_year = Y - 1900; tmv.tm_mon = M - 1; tmv.tm_mday = D;
    } else if (sscanf(s, "%d:%d:%d", &h, &m, &sec) >= 2) {
        /* today */
    } else {
        return -1;
    }
    if (h < 0 || h > 23 || m < 0 || m > 59 || sec < 0 || sec > 59) return -1;
    tmv.tm_hour = h; tmv.tm_min = m; tmv.tm_sec = sec;
    tmv.tm_isdst = -1;
    *out = mktime(&tmv);
    return *out == (time_t)-1 ? -1 : 0;
}

int eas_config_validate(const eas_config_t *c, bool test, char *err, size_t errlen) {
    if (eas_config_active_count(c) == 0) { snprintf(err, errlen, "No tuners have a channel set."); return -1; }
    for (int i = 0; i < c->ntuners; i++) {
        if (!c->tuners[i].chan[0]) continue;
        eas_job_t j;
        eas_job_init(&j);
        char e2[200];
        int r = eas_parse_channel_spec(c->tuners[i].chan, &j, e2, sizeof(e2));
        eas_job_destroy(&j);
        if (r < 0) { snprintf(err, errlen, "Tuner %s-%d: %s", c->tuners[i].devid, c->tuners[i].tuner, e2); return -1; }
        if (!c->tuners[i].ip[0]) { snprintf(err, errlen, "Tuner %s-%d has no IP address.", c->tuners[i].devid, c->tuners[i].tuner); return -1; }
    }
    if (!c->outdir[0]) { snprintf(err, errlen, "Output folder is empty."); return -1; }
    if (test) return 0;
    time_t a, b;
    if (eas_parse_when(c->start, &a)) { snprintf(err, errlen, "Start time '%s' isn't YYYY-MM-DD HH:MM.", c->start); return -1; }
    if (eas_parse_when(c->stop, &b)) { snprintf(err, errlen, "Stop time '%s' isn't YYYY-MM-DD HH:MM.", c->stop); return -1; }
    if (b <= a) { snprintf(err, errlen, "Stop time is not after start time."); return -1; }
    if (b <= time(NULL)) { snprintf(err, errlen, "Stop time is already in the past."); return -1; }
    return 0;
}

void eas_config_estimate(const eas_config_t *c, bool test, double *need_gb, double *free_gb) {
    double mbps = 0;
    for (int i = 0; i < c->ntuners; i++) {
        if (!c->tuners[i].chan[0]) continue;
        bool three = strpbrk(c->tuners[i].chan, "pP:") != NULL || strncasecmp(c->tuners[i].chan, "atsc3", 5) == 0;
        mbps += three ? 25.0 : 19.4;
    }
    double secs = 0;
    if (test) secs = c->test_minutes * 60.0;
    else {
        time_t a, b;
        if (!eas_parse_when(c->start, &a) && !eas_parse_when(c->stop, &b) && b > a) secs = (double)(b - a);
    }
    *need_gb = mbps / 8.0 * secs / 1024.0;
    double fb = plat_free_bytes(c->outdir);
    *free_gb = fb < 0 ? -1 : fb / (1024.0 * 1024 * 1024);
}

/* ------------------------------------------------------------------ */
/* Pausing other tuner users                                           */
/* ------------------------------------------------------------------ */
static char g_units[MAX_UNITS][96];
static bool g_unit_was_active[MAX_UNITS];
static int g_nunits = 0;
static char g_pause_ssh[128] = "";
static const char *g_pre_cmd = NULL;
static const char *g_post_cmd = NULL;
static bool g_paused = false;
static bool g_force_release = true;   /* false when the user frees tuners themselves */

static bool safe_token(const char *s) {
    if (!*s) return false;
    for (; *s; s++)
        if (!(isalnum((unsigned char)*s) || strchr("@._:-+", *s))) return false;
    return true;
}

static int add_units(const char *list, char *err, size_t errlen) {
    char buf[1024];
    snprintf(buf, sizeof(buf), "%s", list);
    for (char *save = NULL, *tok = strtok_r(buf, " ,", &save); tok; tok = strtok_r(NULL, " ,", &save)) {
        if (!safe_token(tok)) { snprintf(err, errlen, "Bad service name '%s'", tok); return -1; }
        if (g_nunits >= MAX_UNITS) { snprintf(err, errlen, "Too many services (max %d)", MAX_UNITS); return -1; }
        snprintf(g_units[g_nunits++], sizeof(g_units[0]), "%s", tok);
    }
    return 0;
}

static int run_logged(const char *what, const char *cmd) {
    char full[1400];
    snprintf(full, sizeof(full), "%s 2>&1", cmd);
    eas_logf("%s: %s", what, cmd);
    static char out[8192];
    int rc = plat_run_capture(full, out, sizeof(out));
    for (char *save = NULL, *ln = strtok_r(out, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save))
        if (ln[0]) eas_logf("  %s", ln);
    return rc;
}

static bool is_root(void) {
#ifdef _WIN32
    return false;
#else
    return geteuid() == 0;
#endif
}

static void systemctl_cmd(const char *verb, const char *unit, char *out, size_t n) {
    bool query = strcmp(verb, "is-active") == 0;
#ifdef _WIN32
    snprintf(out, n, "sc %s %s", query ? "query" : verb, unit);
#else
    if (g_pause_ssh[0])
        snprintf(out, n, "ssh -o BatchMode=yes -o ConnectTimeout=10 %s %ssystemctl %s %s%s",
                 g_pause_ssh, query ? "" : "sudo -n ", verb, query ? "--quiet " : "", unit);
    else
        snprintf(out, n, "%ssystemctl %s %s%s", (query || is_root()) ? "" : "sudo -n ",
                 verb, query ? "--quiet " : "", unit);
#endif
}

static void pause_others(void) {
    if (g_paused) return;
    g_paused = true;
#ifdef _WIN32
    g_nunits = 0;   /* pausing services is a Linux feature */
#endif
    char cmd[512];
    for (int i = 0; i < g_nunits; i++) {
        systemctl_cmd("is-active", g_units[i], cmd, sizeof(cmd));
        g_unit_was_active[i] = (plat_run_capture(cmd, NULL, 0) == 0);
        if (!g_unit_was_active[i]) {
            eas_logf("pause: %s is not running - leaving it alone (won't restart it later)", g_units[i]);
            continue;
        }
        systemctl_cmd("stop", g_units[i], cmd, sizeof(cmd));
        int rc = run_logged("pause", cmd);
        if (rc != 0) {
            eas_logf("pause: WARNING - could not stop %s (exit %d). If sudo wants a password, allow "
                     "passwordless sudo for systemctl.", g_units[i], rc);
            g_unit_was_active[i] = false;
        }
    }
    if (g_pre_cmd) {
        int rc = run_logged("pre-cmd", g_pre_cmd);
        if (rc != 0) eas_logf("pre-cmd: WARNING - exited with %d", rc);
    }
}

static void resume_others(void) {
    if (!g_paused) return;
    g_paused = false;
    char cmd[512];
    for (int i = 0; i < g_nunits; i++) {
        if (!g_unit_was_active[i]) continue;
        systemctl_cmd("start", g_units[i], cmd, sizeof(cmd));
        int rc = run_logged("resume", cmd);
        if (rc != 0) eas_logf("resume: WARNING - could not start %s (exit %d) - start it by hand", g_units[i], rc);
    }
    if (g_post_cmd) {
        int rc = run_logged("post-cmd", g_post_cmd);
        if (rc != 0) eas_logf("post-cmd: WARNING - exited with %d", rc);
    }
}

static void check_tuners_free(eas_job_t *jobs, int njobs) {
    for (int i = 0; i < njobs; i++) {
        struct hdhomerun_device_t *hd = hdhomerun_device_create_from_str(jobs[i].ip, NULL);
        if (!hd) { eas_logf("check: cannot reach %s", jobs[i].ip); continue; }
        hdhomerun_device_set_tuner(hd, jobs[i].tuner);
        /* libhdhomerun returns pointers into a reused buffer: copy each answer */
        char path[64], target[128] = "", lockkey[128] = "", *v = NULL;
        snprintf(path, sizeof(path), "/tuner%d/target", jobs[i].tuner);
        int r1 = hdhomerun_device_get_var(hd, path, &v, NULL);
        if (r1 > 0 && v) snprintf(target, sizeof(target), "%s", v);
        snprintf(path, sizeof(path), "/tuner%d/lockkey", jobs[i].tuner);
        int r2 = hdhomerun_device_get_var(hd, path, &v, NULL);
        if (r2 > 0 && v) snprintf(lockkey, sizeof(lockkey), "%s", v);
        target[strcspn(target, "\r\n")] = '\0';
        lockkey[strcspn(lockkey, "\r\n")] = '\0';
        bool busy_target = r1 > 0 && target[0] && strcmp(target, "none") != 0;
        bool busy_lock = r2 > 0 && lockkey[0] && strcmp(lockkey, "none") != 0;
        if (r1 <= 0 && r2 <= 0)
            eas_logf("check: %s tuner%d - no answer on the control port", jobs[i].ip, jobs[i].tuner);
        else if (busy_target || busy_lock)
            eas_logf("check: WARNING %s tuner%d still looks in use (target=%s lockkey=%s)",
                     jobs[i].ip, jobs[i].tuner, target, lockkey);
        else
            eas_logf("check: %s tuner%d is free", jobs[i].ip, jobs[i].tuner);
        hdhomerun_device_destroy(hd);
    }
}

/* After the other programs are stopped their tuners can still be held
 * (lock key, stream target, tuned channel) and the device answers 503.
 * Force them free. */
static void release_tuners(eas_job_t *jobs, int njobs) {
    for (int i = 0; i < njobs; i++) {
        char msg[200];
        if (!g_force_release) {
            /* User frees tuners themselves: only clear stale locks/tunes, never a live stream */
            char target[160];
            eas_tuner_target(jobs[i].ip, jobs[i].tuner, target, sizeof(target));
            if (strcmp(target, "none") != 0) {
                eas_logf("release: WARNING %s tuner%d is in use (streaming to %s) - free it before the "
                         "test (bandscan, DVR, live viewing...)", jobs[i].ip, jobs[i].tuner, target);
                continue;
            }
        }
        eas_release_tuner(jobs[i].ip, jobs[i].tuner, msg, sizeof(msg));
        eas_logf("release: %s", msg);
    }
}

/* Programs we just stopped (scanners, loggers) leave their tuners tuned to
 * the last channel. On the same devices, clear any tuner that we aren't
 * recording on and that isn't streaming anywhere. Tuners with an active
 * stream target belong to someone else and are left alone. */
static void release_idle_leftovers(eas_job_t *jobs, int njobs) {
    for (int i = 0; i < njobs; i++) {
        bool seen = false;
        for (int k = 0; k < i; k++) if (!strcmp(jobs[k].ip, jobs[i].ip)) seen = true;
        if (seen) continue;
        struct hdhomerun_device_t *hd = hdhomerun_device_create_from_str(jobs[i].ip, NULL);
        if (!hd) continue;
        for (int t = 0; t < 8; t++) {
            if (hdhomerun_device_set_tuner(hd, t) <= 0) break;
            struct hdhomerun_tuner_status_t st;
            char *raw;
            if (hdhomerun_device_get_tuner_status(hd, &raw, &st) <= 0) break;
            bool ours = false;
            for (int k = 0; k < njobs; k++) if (!strcmp(jobs[k].ip, jobs[i].ip) && jobs[k].tuner == t) ours = true;
            if (ours) continue;
            char channel[64];
            snprintf(channel, sizeof(channel), "%s", st.channel);
            if (!channel[0] || !strcmp(channel, "none")) continue;
            char path[48], target[160] = "", *v = NULL;
            snprintf(path, sizeof(path), "/tuner%d/target", t);
            if (hdhomerun_device_get_var(hd, path, &v, NULL) > 0 && v) snprintf(target, sizeof(target), "%s", v);
            target[strcspn(target, "\r\n")] = '\0';
            if (target[0] && strcmp(target, "none")) {
                eas_logf("release: %s tuner%d left alone - it is streaming (%s)", jobs[i].ip, t, target);
                continue;
            }
            char msg[200];
            eas_release_tuner(jobs[i].ip, t, msg, sizeof(msg));
            eas_logf("release: idle leftover on %s tuner%d (was %s): %s", jobs[i].ip, t, channel, msg);
        }
        hdhomerun_device_destroy(hd);
    }
}

int eas_detect_units(char *out, size_t n) {
    out[0] = '\0';
#ifdef _WIN32
    (void)n;
    return 0;
#else
    const char *script =
        "systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | "
        "awk '{print $1}' | while read u; do "
        "systemctl cat \"$u\" 2>/dev/null | grep -qiE 'hdhomerun|scan_tuner|tvdx|rf[0-9]+watch' && "
        "echo \"${u%.service}\"; done";
    static char buf[4096];
    if (plat_run_capture(script, buf, sizeof(buf)) < 0) return -1;
    int count = 0;
    for (char *save = NULL, *line = strtok_r(buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        line[strcspn(line, "\r")] = '\0';
        if (!line[0] || !safe_token(line)) continue;
        size_t L = strlen(out);
        snprintf(out + L, n - L, "%s%s", L ? " " : "", line);
        count++;
    }
    return count;
#endif
}

/* ------------------------------------------------------------------ */
/* State file (runner -> TUI monitor)                                  */
/* ------------------------------------------------------------------ */
static bool g_write_state = false;
static char g_mode[16] = "cli";
static char g_phase[32] = "starting";
static char g_message[256] = "";
static time_t g_start_t, g_stop_t;
static char g_outdir[512];
static char g_summary[600];
static char g_web[600];
static char g_web_base[600];
static eas_job_t *g_jobs;
static int g_njobs;
static char g_job_labels[MAX_JOBS][48];

static void write_state(void) {
    if (!g_write_state) return;
    char path[600], tmp[620];
    cfg_path("eas_state", path, sizeof(path));
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    fprintf(f, "pid=%d\nmode=%s\nphase=%s\nmessage=%s\nstart=%ld\nstop=%ld\nupdated=%ld\noutdir=%s\nsummary=%s\nweb=%s\n",
            (int)plat_getpid(), g_mode, g_phase, g_message, (long)g_start_t, (long)g_stop_t, (long)time(NULL),
            g_outdir, g_summary, g_web);
    for (int i = 0; i < g_njobs; i++) {
        eas_status_t st;
        eas_job_status(&g_jobs[i], &st);
        char chan[80];
        snprintf(chan, sizeof(chan), "RF %u %s", g_jobs[i].rf, g_jobs[i].atsc3 ? g_jobs[i].plps : "(1.0)");
        char msg[200];
        snprintf(msg, sizeof(msg), "%s", st.last_msg);
        for (char *q = msg; *q; q++) if (*q == '|' || *q == '\n') *q = ' ';
        fprintf(f, "tuner=%s|%s|%s|%d|%.1f|%s|%s\n", g_job_labels[i], chan, st.state, st.segments,
                st.bytes_total / 1048576.0, st.signal, msg);
    }
    fclose(f);
    plat_rename_replace(tmp, path);
}

static void set_phase(const char *phase, const char *fmt, ...) {
    snprintf(g_phase, sizeof(g_phase), "%s", phase);
    if (fmt) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(g_message, sizeof(g_message), fmt, ap);
        va_end(ap);
    } else {
        g_message[0] = '\0';
    }
    write_state();
}

static bool pid_alive(long pid) { return plat_pid_alive(pid); }

void eas_state_read(eas_state_t *st) {
    memset(st, 0, sizeof(*st));
    char path[600];
    cfg_path("eas_state", path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return;
    st->present = true;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        const char *k = line, *v = eq + 1;
        if (!strcmp(k, "pid")) st->pid = atol(v);
        else if (!strcmp(k, "mode")) snprintf(st->mode, sizeof(st->mode), "%s", v);
        else if (!strcmp(k, "phase")) snprintf(st->phase, sizeof(st->phase), "%s", v);
        else if (!strcmp(k, "message")) snprintf(st->message, sizeof(st->message), "%s", v);
        else if (!strcmp(k, "start")) st->start = (time_t)atol(v);
        else if (!strcmp(k, "stop")) st->stop = (time_t)atol(v);
        else if (!strcmp(k, "updated")) st->updated = (time_t)atol(v);
        else if (!strcmp(k, "outdir")) snprintf(st->outdir, sizeof(st->outdir), "%s", v);
        else if (!strcmp(k, "summary")) snprintf(st->summary, sizeof(st->summary), "%s", v);
        else if (!strcmp(k, "web")) snprintf(st->web, sizeof(st->web), "%s", v);
        else if (!strcmp(k, "tuner") && st->nrows < EAS_STATE_MAX_ROWS)
            snprintf(st->rows[st->nrows++], sizeof(st->rows[0]), "%s", v);
    }
    fclose(f);
    st->alive = pid_alive(st->pid);
}

/* Cancel works through a file the runner watches (works the same on Windows),
 * plus SIGINT on Unix so a waiting runner reacts at once. */
static void cancel_path(char *out, size_t n) { cfg_path("eas_cancel", out, n); }

int eas_cancel_running(void) {
    eas_state_t st;
    eas_state_read(&st);
    if (!st.alive) return -1;
    char p[1100];
    cancel_path(p, sizeof(p));
    FILE *f = fopen(p, "w");
    if (f) { fprintf(f, "%ld\n", st.pid); fclose(f); }
#ifndef _WIN32
    kill((pid_t)st.pid, SIGINT);
#endif
    return f ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* RENDER                                                              */
/* ------------------------------------------------------------------ */
int eas_find_render(char *out, size_t n) {
    char dir[1024];
    if (plat_exe_dir(dir, sizeof(dir)) == 0) {
        const char *cands[] = { "%s/render" PLAT_EXE_SUFFIX, "%s/../render/render" PLAT_EXE_SUFFIX,
                                "%s/src/render/render" PLAT_EXE_SUFFIX, "%s/../src/render/render" PLAT_EXE_SUFFIX };
        for (size_t i = 0; i < sizeof(cands) / sizeof(cands[0]); i++) {
            char p[1200];
            snprintf(p, sizeof(p), cands[i], dir);
            if (plat_is_file(p)) { snprintf(out, n, "%s", p); return 0; }
        }
    }
    return plat_find_program("render", out, n) ? 0 : -1;
}

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int sig) { (void)sig; g_stop = 1; }

/* True once a cancel was requested (signal or the cancel file). */
static bool stop_requested(void) {
    if (g_stop) return true;
    if (!g_write_state) return false;
    char p[1100];
    cancel_path(p, sizeof(p));
    if (plat_exists(p)) { remove(p); g_stop = 1; }
    return g_stop;
}

static int ends_with(const char *s, const char *suf) {
    size_t a = strlen(s), b = strlen(suf);
    return a >= b && strcmp(s + a - b, suf) == 0;
}

static int cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

static int cpu_count(void) {
#ifdef _WIN32
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (int)si.dwNumberOfProcessors;
#else
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (int)n : 1;
#endif
}

static void render_all(const char *outdir, int seg) {
    char render[1200];
    if (eas_find_render(render, sizeof(render)) < 0) {
        eas_logf("render: RENDER program not found next to this program - skipping reports");
        set_phase("done", "Capture finished. RENDER not found, so no reports were made.");
        return;
    }
    DIR *d = opendir(outdir);
    if (!d) return;
    char **files = NULL;
    int nf = 0;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (!ends_with(de->d_name, ".pcap") && !ends_with(de->d_name, ".dbg")) continue;
        char side[1200];
        snprintf(side, sizeof(side), "%s/%s", outdir, de->d_name);
        char *dot = strrchr(side, '.');
        snprintf(dot, sizeof(side) - (dot - side), ".eas.tsv");
        if (plat_exists(side)) continue;
        files = realloc(files, sizeof(char *) * (nf + 1));
        files[nf++] = strdup(de->d_name);
    }
    closedir(d);
    if (nf > 1) qsort(files, nf, sizeof(char *), cmp_str);

    eas_logf("render: %d capture(s) to render with %s", nf, render);
    int workers = cpu_count() >= 4 ? 2 : 1;
    plat_pid_t running[2] = {0, 0};
    int done = 0, next = 0;
    char segs[16];
    snprintf(segs, sizeof(segs), "%d", seg);

    set_phase("rendering", "Making reports: 0 of %d done", nf);
    while ((next < nf || running[0] || running[1]) && !stop_requested()) {
        for (int w = 0; w < workers; w++) {
            if (running[w] || next >= nf) continue;
            char in[1200], logf[1200];
            snprintf(in, sizeof(in), "%s/%s", outdir, files[next]);
            snprintf(logf, sizeof(logf), "%s", in);
            char *dot = strrchr(logf, '.');
            snprintf(dot, sizeof(logf) - (dot - logf), ".render.log");
            if (ends_with(files[next], ".dbg")) {
                const char *argv[] = { render, "-t", segs, in, NULL };
                running[w] = plat_spawn(argv, logf, false, false);
            } else {
                const char *argv[] = { render, in, NULL };
                running[w] = plat_spawn(argv, logf, false, false);
            }
            if (running[w] <= 0) { running[w] = 0; eas_logf("render: could not start %s", render); }
            next++;
        }
        bool any = false;
        for (int w = 0; w < 2; w++) {
            if (!running[w]) continue;
            int rc = plat_wait(running[w], 0);
            if (rc == -2) { any = true; continue; }
            running[w] = 0;
            done++;
            if (rc != 0) eas_logf("render: a report failed (see the .render.log next to the capture)");
            set_phase("rendering", "Making reports: %d of %d done", done, nf);
        }
        if (any) plat_sleep_ms(200);
    }
    if (g_stop) {
        for (int w = 0; w < 2; w++) if (running[w]) { plat_terminate(running[w]); plat_wait(running[w], -1); }
        eas_logf("render: cancelled");
    }
    for (int i = 0; i < nf; i++) free(files[i]);
    free(files);

    snprintf(g_summary, sizeof(g_summary), "%s/eas_summary.html", outdir);
    const char *argv[] = { render, "--eas-summary", g_summary, outdir, NULL };
    char logf[1100];
    snprintf(logf, sizeof(logf), "%s/eas_summary.log", outdir);
    plat_pid_t p = plat_spawn(argv, logf, false, false);
    if (p > 0) plat_wait(p, -1);
    eas_logf("render: summary %s", g_summary);
}

/* ------------------------------------------------------------------ */
/* Zipping a run folder                                                */
/* ------------------------------------------------------------------ */
static bool zip_wants(const char *name, const char *what) { return zipw_wants(name, what); }

long long eas_dir_bytes(const char *dir, const char *what) {
    DIR *d = opendir(dir);
    if (!d) return 0;
    long long total = 0;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (!zip_wants(de->d_name, what)) continue;
        char p[1300];
        snprintf(p, sizeof(p), "%s/%s", dir, de->d_name);
        long long sz = plat_is_file(p) ? plat_file_size(p) : -1;
        if (sz > 0) total += sz;
    }
    closedir(d);
    return total;
}

static void zip_name(const char *rundir, const char *what, char *out, size_t n) {
    const char *b = strrchr(rundir, '/');
    b = b ? b + 1 : rundir;
    snprintf(out, n, "%s/%s_%s.zip", rundir, b, !strcmp(what, "full") ? "full" : "reports");
}

int eas_zip_status(const char *rundir, const char *what, char *zip_path, size_t n, long long *size) {
    zip_name(rundir, what, zip_path, n);
    char part[1400];
    snprintf(part, sizeof(part), "%s.part", zip_path);
    long long sz;
    if ((sz = plat_file_size(part)) >= 0) { *size = sz; return 1; }
    if ((sz = plat_file_size(zip_path)) >= 0) { *size = sz; return 2; }
    *size = 0;
    return 0;
}

/* The zip is made by this same program running in the background, so a
 * multi-GB zip doesn't freeze the screen and survives closing it. */
int eas_zip_start(const char *rundir, const char *what, char *zip_path, size_t n, char *err, size_t errlen) {
    long long sz;
    int stt = eas_zip_status(rundir, what, zip_path, n, &sz);
    if (stt == 1) { snprintf(err, errlen, "That zip is already being made."); return -1; }
    if (stt == 2) remove(zip_path);
    char exe[1100], logp[1100];
    if (plat_exe_path(exe, sizeof(exe)) < 0) { snprintf(err, errlen, "Cannot find my own program path."); return -1; }
    cfg_path("eas_zip.log", logp, sizeof(logp));
    const char *argv[] = { exe, "--eas-zip", what, rundir, zip_path, NULL };
    if (plat_spawn(argv, logp, true, true) <= 0) { snprintf(err, errlen, "Could not start the zip."); return -1; }
    plat_sleep_ms(300);
    return 0;
}

int eas_zip_main(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: --eas-zip reports|full <dir> <zip>\n"); return 2; }
    char err[300];
    int rc = zipw_dir(argv[3], argv[2], argv[4], err, sizeof(err));
    if (rc != 0) fprintf(stderr, "zip failed: %s\n", err);
    return rc == 0 ? 0 : 1;
}

/* ------------------------------------------------------------------ */
/* Results web server                                                  */
/* ------------------------------------------------------------------ */
int eas_lan_ip(char *out, size_t n) { return plat_lan_ip(out, n); }

int eas_web_status(int *port, char *dir, size_t dirlen) {
    char path[1100];
    cfg_path("eas_web", path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    long pid = 0;
    int p = 0;
    char d[1024] = "";
    if (fscanf(f, "%ld %d %1023[^\n]", &pid, &p, d) < 2) pid = 0;
    fclose(f);
    if (pid <= 0 || !pid_alive(pid)) return 0;
    if (port) *port = p;
    if (dir) snprintf(dir, dirlen, "%s", d);
    return (int)pid;
}

void eas_web_stop(void) {
    int pid = eas_web_status(NULL, NULL, 0);
    if (pid > 0) plat_terminate(pid);
    char path[1100];
    cfg_path("eas_web", path, sizeof(path));
    remove(path);
}

#ifdef _WIN32
static bool win_python_ok(const char *exe, const char *arg) {
    char cmd[1400], out[64] = "";
    snprintf(cmd, sizeof(cmd), "\"\"%s\" %s -c \"import http.server;print(42)\" 2>NUL\"", exe, arg ? arg : "");
    if (plat_run_capture(cmd, out, sizeof(out)) < 0) return false;
    return strstr(out, "42") != NULL;
}
#endif

static int web_start(const char *dir, int *port_out, char *err, size_t errlen) {
    /* python3's built-in web server; on Windows Python may be "python" or "py" */
    char py[1100];
    const char *pre[3] = { NULL, NULL, NULL };
#ifdef _WIN32
    /* the Microsoft Store puts placeholder python.exe/python3.exe on PATH that only
       print "Python was not found" - try each candidate before trusting it */
    if (plat_find_program("py", py, sizeof(py)) && win_python_ok(py, "-3")) { pre[0] = py; pre[1] = "-3"; }
    else if (plat_find_program("python3", py, sizeof(py)) && win_python_ok(py, NULL)) { pre[0] = py; }
    else if (plat_find_program("python", py, sizeof(py)) && win_python_ok(py, NULL)) { pre[0] = py; }
#else
    if (plat_find_program("python3", py, sizeof(py))) { pre[0] = py; }
    else if (plat_find_program("python", py, sizeof(py))) { pre[0] = py; }
#endif
    else { snprintf(err, errlen, "Python 3 isn't installed, so the web server can't run (open the report file instead)"); return -1; }

    char path[1100], logp[1100];
    cfg_path("eas_web", path, sizeof(path));
    cfg_path("eas_web.log", logp, sizeof(logp));
    for (int port = 8000; port <= 8010; port++) {
        char ps[16];
        snprintf(ps, sizeof(ps), "%d", port);
        const char *argv[12];
        int a = 0;
        argv[a++] = pre[0];
        if (pre[1]) argv[a++] = pre[1];
        argv[a++] = "-m"; argv[a++] = "http.server"; argv[a++] = ps;
        argv[a++] = "--bind"; argv[a++] = "0.0.0.0"; argv[a++] = "--directory"; argv[a++] = dir;
        argv[a] = NULL;
        plat_pid_t pid = plat_spawn(argv, logp, true, true);
        if (pid <= 0) continue;
        plat_sleep_ms(1500);                /* did it bind, or exit because the port is busy? */
        if (!plat_pid_alive(pid)) continue;
        FILE *f = fopen(path, "w");
        if (f) { fprintf(f, "%ld %d %s\n", (long)pid, port, dir); fclose(f); }
        *port_out = port;
        return 0;
    }
    snprintf(err, errlen, "Could not start the web server on ports 8000-8010");
    return -1;
}

int eas_web_serve(const char *base_in, const char *summary, char *url, size_t n, char *err, size_t errlen) {
    char base[1100], dir[1100];
    expand_home(base_in, base, sizeof(base));
    size_t bl = strlen(base);
    while (bl > 1 && base[bl - 1] == '/') base[--bl] = '\0';
    snprintf(dir, sizeof(dir), "%s", base);
    const char *rel = "";
    if (summary && summary[0]) {
        if (!strncmp(summary, base, bl) && summary[bl] == '/') {
            rel = summary + bl + 1;
        } else {
            snprintf(dir, sizeof(dir), "%s", summary);
            char *sl = strrchr(dir, '/');
            if (sl) *sl = '\0';
            rel = strrchr(summary, '/') ? strrchr(summary, '/') + 1 : summary;
        }
    }
    if (!plat_is_dir(dir)) { snprintf(err, errlen, "Folder %s doesn't exist yet", dir); return -1; }

    int port = 0;
    char cur[1100] = "";
    int pid = eas_web_status(&port, cur, sizeof(cur));
    if (pid > 0 && strcmp(cur, dir) != 0) { eas_web_stop(); pid = 0; }
    if (pid <= 0 && web_start(dir, &port, err, errlen) < 0) return -1;
    char ip[64];
    eas_lan_ip(ip, sizeof(ip));
    snprintf(url, n, "http://%s:%d/%s", ip, port, rel);
    return 0;
}

/* ------------------------------------------------------------------ */
/* The run                                                             */
/* ------------------------------------------------------------------ */
static void fmt_time(time_t t, char *buf, size_t n) {
    struct tm tmv;
    plat_localtime(t, &tmv);
    strftime(buf, n, "%Y-%m-%d %H:%M:%S %Z", &tmv);
}

typedef struct {
    time_t start_t, stop_t;
    int seg;
    char outdir[512];
    int pause_lead;
    bool auto_render;
    bool echo;
} run_params_t;

static int eas_run(eas_job_t *jobs, int njobs, run_params_t *rp) {
    g_jobs = jobs;
    g_njobs = njobs;
    g_start_t = rp->start_t;
    g_stop_t = rp->stop_t;
    snprintf(g_outdir, sizeof(g_outdir), "%s", rp->outdir);
    g_summary[0] = '\0';
    g_web[0] = '\0';

    if (mkdir_p(rp->outdir) < 0) {
        set_phase("failed", "Cannot create %s: %s", rp->outdir, strerror(errno));
        if (rp->echo) fprintf(stderr, "Cannot create %s: %s\n", rp->outdir, strerror(errno));
        return 1;
    }
#ifndef _WIN32
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;          /* no SA_RESTART: a cancel interrupts waits */
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
#else
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
#endif
    plat_init();
    plat_keep_awake(true);
    eas_log_open(rp->outdir);
    eas_set_log_echo(rp->echo);

    char s1[64], s2[64];
    fmt_time(rp->start_t, s1, sizeof(s1));
    fmt_time(rp->stop_t, s2, sizeof(s2));
    eas_logf("=== HDHR EAS Test v0.5 - %s run: %d tuner(s), %s -> %s, %ds segments, output %s ===", g_mode, njobs, s1, s2,
             rp->seg, rp->outdir);
    for (int i = 0; i < njobs; i++)
        eas_logf("  %s tuner%d: RF %u %s %s", jobs[i].ip, jobs[i].tuner, jobs[i].rf,
                 jobs[i].atsc3 ? "ATSC 3.0" : "ATSC 1.0", jobs[i].atsc3 ? jobs[i].plps : "(full TS)");

    double mbps = 0;
    for (int i = 0; i < njobs; i++) mbps += jobs[i].atsc3 ? 25.0 : 19.4;
    double need_gb = mbps / 8.0 * (double)(rp->stop_t - rp->start_t) / 1024.0;
    double fb = plat_free_bytes(rp->outdir);
    if (fb >= 0) {
        double free_gb = fb / (1024.0 * 1024 * 1024);
        eas_logf("Estimated size up to ~%.1f GB; free space %.1f GB%s", need_gb, free_gb,
                 free_gb < need_gb ? "  <-- WARNING: may run out of space" : "");
    }

    bool want_pause = true;   /* pause services (if any), then release and check the tuners */
    if (g_nunits && !g_pause_ssh[0] && !is_root()) {
        for (int i = 0; i < g_nunits; i++) {
            char cmd[300];
            snprintf(cmd, sizeof(cmd), "sudo -n -l systemctl stop %s >/dev/null 2>&1 && "
                     "sudo -n -l systemctl start %s >/dev/null 2>&1", g_units[i], g_units[i]);
            if (plat_run_capture(cmd, NULL, 0) != 0)
                eas_logf("WARNING: sudo won't run 'systemctl stop/start %s' without a password - "
                         "add it to /etc/sudoers.d (see README)", g_units[i]);
        }
    }

    if (!g_force_release && !g_nunits)
        eas_logf("note: free each tuner this run uses (RabbitEars bandscan, DVR, live viewing, etc.). "
                 "Stale locks are cleared; tuners streaming elsewhere are left alone.");

    /* Wait for the start time */
    set_phase("waiting", "Waiting for %s", s1);
    time_t last_print = 0, last_state = 0;
    while (!stop_requested() && time(NULL) < rp->start_t) {
        if (want_pause && !g_paused && time(NULL) >= rp->start_t - rp->pause_lead) {
            set_phase("pausing", "Stopping other tuner users and releasing tuners");
            pause_others();
            plat_sleep_ms(2000);
            release_tuners(jobs, njobs);
            if (g_nunits && g_force_release) release_idle_leftovers(jobs, njobs);
            plat_sleep_ms(1000);
            check_tuners_free(jobs, njobs);
            set_phase("waiting", "Tuners freed, waiting for %s", s1);
        }
        time_t now = time(NULL);
        if (rp->echo && (now - last_print >= 60 || rp->start_t - now <= 10)) {
            long left = (long)(rp->start_t - now);
            printf("Waiting to start: %ldh %02ldm %02lds\n", left / 3600, (left / 60) % 60, left % 60);
            fflush(stdout);
            last_print = now;
        }
        if (now - last_state >= 5) { write_state(); last_state = now; }
        plat_sleep_ms(1000);
    }
    if (g_stop) {
        resume_others();
        eas_logf("=== Cancelled before start ===");
        set_phase("cancelled", "Cancelled before the start time");
        eas_log_close();
        return 0;
    }
    if (want_pause && !g_paused) {
        set_phase("pausing", "Stopping other tuner users and releasing tuners");
        pause_others();
        plat_sleep_ms(2000);
        release_tuners(jobs, njobs);
        if (g_nunits && g_force_release) release_idle_leftovers(jobs, njobs);
        plat_sleep_ms(1000);
        check_tuners_free(jobs, njobs);
    }

    eas_logf("=== Recording started, until %s ===", s2);
    int started = 0;
    for (int i = 0; i < njobs; i++) {
        jobs[i].stop_time = rp->stop_t;
        if (eas_job_start(&jobs[i]) == 0) started++;
        else eas_logf("tuner%d rf%u: failed to start", jobs[i].tuner, jobs[i].rf);
    }
    if (!started) {
        resume_others();
        set_phase("failed", "No tuner could start recording");
        eas_log_close();
        return 1;
    }
    set_phase("recording", "Recording until %s", s2);

    bool cancelled = false;
    time_t last_report = time(NULL);
    for (;;) {
        plat_sleep_ms(1000);
        if (stop_requested()) {
            eas_logf("Stop requested - closing files");
            for (int i = 0; i < njobs; i++) eas_job_request_stop(&jobs[i]);
            g_stop = 0;
            cancelled = true;
            set_phase("recording", "Stopping - closing files");
        }
        int alive = 0;
        for (int i = 0; i < njobs; i++) {
            eas_status_t st;
            eas_job_status(&jobs[i], &st);
            if (st.running) alive++;
        }
        write_state();
        if (!alive) break;
        if (rp->echo && time(NULL) - last_report >= 30) {
            last_report = time(NULL);
            for (int i = 0; i < njobs; i++) {
                eas_status_t st;
                eas_job_status(&jobs[i], &st);
                printf("  tuner%d rf%u [%s] seg %d, %.0f MB total, %s%s%s\n", jobs[i].tuner, jobs[i].rf,
                       st.state, st.segments, st.bytes_total / 1048576.0, st.signal,
                       st.last_msg[0] ? " | " : "", st.last_msg);
            }
            fflush(stdout);
        }
    }
    for (int i = 0; i < njobs; i++) eas_job_join(&jobs[i]);
    eas_logf("=== Recording finished%s ===", cancelled ? " (stopped early)" : "");
    resume_others();
    write_state();

    if (rp->auto_render) {
        render_all(rp->outdir, rp->seg);
        if (!g_stop && g_summary[0] && access(g_summary, F_OK) == 0) {
            char err[200];
            if (eas_web_serve(g_web_base[0] ? g_web_base : rp->outdir, g_summary, g_web, sizeof(g_web), err, sizeof(err)) == 0)
                eas_logf("web: report at %s", g_web);
            else
                eas_logf("web: %s", err);
        }
        if (g_stop) set_phase("cancelled", "Stopped while making reports");
        else if (strcmp(g_phase, "rendering") == 0 || strcmp(g_phase, "recording") == 0)
            set_phase("done", "%sDone. Report: %s", cancelled ? "Stopped early. " : "", g_web[0] ? g_web : g_summary);
    } else {
        set_phase("done", "%sRecording finished. Files are in %s", cancelled ? "Stopped early. " : "", rp->outdir);
    }
    if (rp->echo) printf("\n%s\n", g_message);
    plat_keep_awake(false);
    eas_log_close();
    return 0;
}

/* Build a job from a config tuner; finds the device by ID if its IP changed. */
static int job_from_cfg(eas_job_t *j, const eas_cfg_tuner_t *t, const eas_config_t *c, char *err, size_t errlen) {
    eas_job_init(j);
    snprintf(j->ip, sizeof(j->ip), "%s", t->ip);
    bool have_id = t->devid[0] && strcmp(t->devid, "-") != 0;
    bool ip_ok = false;
    if (t->ip[0]) {   /* prefer the saved IP if the same device still answers there */
        struct hdhomerun_device_t *hd = hdhomerun_device_create_from_str(t->ip, NULL);
        char *model = NULL;
        if (hd && hdhomerun_device_get_var(hd, "/sys/model", &model, NULL) > 0) {
            uint32_t id = hdhomerun_device_get_device_id(hd);
            ip_ok = !have_id || id == (uint32_t)strtoul(t->devid, NULL, 16);
        }
        if (hd) hdhomerun_device_destroy(hd);
    }
    if (!ip_ok && have_id) {
        eas_logf("%s-%d: not answering at %s, looking the device up by ID", t->devid, t->tuner, t->ip);
        struct hdhomerun_device_t *hd = hdhomerun_device_create_from_str(t->devid, NULL);
        if (hd) {
            uint32_t ip = hdhomerun_device_get_device_ip(hd);
            if (ip) snprintf(j->ip, sizeof(j->ip), "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
            hdhomerun_device_destroy(hd);
        }
    }
    j->tuner = t->tuner;
    j->fmt = EAS_FMT_TS;
    if (eas_parse_channel_spec(t->chan, j, err, errlen) < 0) return -1;
    if (j->atsc3) j->fmt = (eas_fmt_t)c->fmt3;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Background runner (launched by the TUI)                             */
/* ------------------------------------------------------------------ */
int eas_launch_background(const char *mode, bool pause_services, char *err, size_t errlen) {
    eas_state_t st;
    eas_state_read(&st);
    if (st.alive) {
        snprintf(err, errlen, "A %s run is already active (pid %ld). Cancel it first.",
                 !strcmp(st.mode, "test") ? "test" : "scheduled", st.pid);
        return -1;
    }
    char exe[1100];
    if (plat_exe_path(exe, sizeof(exe)) < 0) { snprintf(err, errlen, "Cannot find my own program path."); return -1; }

    /* Clear the old state and any stale cancel request */
    char path[1100];
    cfg_path("eas_state", path, sizeof(path));
    FILE *f = fopen(path, "w");
    if (f) { fprintf(f, "pid=0\nmode=%s\nphase=starting\nmessage=Starting...\nupdated=%ld\n", mode, (long)time(NULL)); fclose(f); }
    cancel_path(path, sizeof(path));
    remove(path);

    char outlog[1100];
    cfg_path("eas_runner.log", outlog, sizeof(outlog));
    const char *argv[] = { exe, "--eas-daemon", mode, pause_services ? "pause" : "nopause", NULL };
    if (plat_spawn(argv, outlog, true, true) <= 0) { snprintf(err, errlen, "Could not start the background runner."); return -1; }
    /* Wait briefly for the runner to report in */
    for (int i = 0; i < 30; i++) {
        plat_sleep_ms(100);
        eas_state_read(&st);
        if (st.alive) return 0;
        if (strcmp(st.phase, "failed") == 0) { snprintf(err, errlen, "%s", st.message); return -1; }
    }
    return 0;
}

int eas_daemon_main(int argc, char **argv) {
    const char *mode = argc > 2 ? argv[2] : "test";
    bool test = strcmp(mode, "armed") != 0;
    snprintf(g_mode, sizeof(g_mode), "%s", test ? "test" : "armed");
    g_write_state = true;
    plat_init();
#ifndef _WIN32
    signal(SIGHUP, SIG_IGN);
#endif

    eas_config_t c;
    eas_config_load(&c);
    char err[300];
    if (eas_config_validate(&c, test, err, sizeof(err)) < 0) { set_phase("failed", "%s", err); return 1; }

    run_params_t rp;
    memset(&rp, 0, sizeof(rp));
    char base[512];
    expand_home(c.outdir, base, sizeof(base));
    if (test) {
        rp.start_t = time(NULL);
        rp.stop_t = rp.start_t + (time_t)c.test_minutes * 60;
        rp.seg = c.test_seg;
        struct tm tmv;
        plat_localtime(rp.start_t, &tmv);
        char stamp[32];
        strftime(stamp, sizeof(stamp), "test_%Y%m%d-%H%M%S", &tmv);
        snprintf(rp.outdir, sizeof(rp.outdir), "%s/%s", base, stamp);
        rp.pause_lead = 0;
    } else {
        eas_parse_when(c.start, &rp.start_t);
        eas_parse_when(c.stop, &rp.stop_t);
        rp.seg = c.seg;
        snprintf(rp.outdir, sizeof(rp.outdir), "%s", base);
        rp.pause_lead = c.pause_lead;
    }
    rp.auto_render = c.auto_render != 0;
    rp.echo = true;   /* goes to eas_runner.log */
    snprintf(g_web_base, sizeof(g_web_base), "%s", base);

    bool pause_services = argc > 3 && !strcmp(argv[3], "pause");
    g_force_release = pause_services;
    g_nunits = 0;
    if (pause_services && c.pause_units[0] && add_units(c.pause_units, err, sizeof(err)) < 0) { set_phase("failed", "%s", err); return 1; }
    if (!pause_services) {
        c.pause_ssh[0] = '\0';
        eas_logf("note: services are not paused (TUI started without --pause-services)");
    }
    if (pause_services && c.pause_ssh[0]) {
        if (!safe_token(c.pause_ssh)) { set_phase("failed", "Bad pause host '%s'", c.pause_ssh); return 1; }
        snprintf(g_pause_ssh, sizeof(g_pause_ssh), "%s", c.pause_ssh);
    }

    g_start_t = rp.start_t;
    g_stop_t = rp.stop_t;
    snprintf(g_outdir, sizeof(g_outdir), "%s", rp.outdir);
    set_phase("starting", "Finding tuners");

    static eas_job_t jobs[MAX_JOBS];
    int njobs = 0;
    for (int i = 0; i < c.ntuners && njobs < MAX_JOBS; i++) {
        if (!c.tuners[i].chan[0]) continue;
        if (job_from_cfg(&jobs[njobs], &c.tuners[i], &c, err, sizeof(err)) < 0) { set_phase("failed", "%s", err); return 1; }
        jobs[njobs].seg_seconds = rp.seg;
        jobs[njobs].force_release = pause_services;
        snprintf(jobs[njobs].outdir, sizeof(jobs[njobs].outdir), "%s", rp.outdir);
        snprintf(g_job_labels[njobs], sizeof(g_job_labels[0]), "%s-%d",
                 strcmp(c.tuners[i].devid, "-") ? c.tuners[i].devid : c.tuners[i].ip, c.tuners[i].tuner);
        njobs++;
    }
    return eas_run(jobs, njobs, &rp);
}

/* ------------------------------------------------------------------ */
/* Command-line mode (optional; the TUI's EAS screen does all of this) */
/* ------------------------------------------------------------------ */
static void headless_usage(const char *prog) {
    printf("HDHR EAS Test v0.5 - EAS capture from the command line\n");
    printf("(Easier: use the GUI's EAS Test tab, or on Linux the TUI's EAS screen ('e').)\n\n");
    printf("Usage: %s --eas -i <ip> -c <tuner>=<channel> [-c ...] [options]\n\n", prog);
    printf("  -i <ip>              HDHomeRun IP address (default for every -c)\n");
    printf("  -c [ip/]<t>=<chan>   Record <chan> on tuner <t>: 33 (ATSC 1.0), 27p0, 27p0p1 (ATSC 3.0)\n");
    printf("  --start <when>       now | HH:MM[:SS] | YYYY-MM-DD HH:MM[:SS] (local time, default now)\n");
    printf("  --stop <when> | --minutes <n>\n");
    printf("  --seg <seconds>      segment length (default 60, min 10)\n");
    printf("  --fmt pcap|dbg       ATSC 3.0 capture format (default pcap)\n");
    printf("  -o <dir>             output directory (default ./eas_<date>)\n");
    printf("  --pause-units \"a b\"  systemd services to stop before and restart after\n");
    printf("  --pause-ssh <host>   ...on another machine over ssh\n");
    printf("  --pause-lead <sec>   pause this long before start (default 60)\n");
    printf("  --pre-cmd / --post-cmd <cmd>\n");
    printf("  --render             make RENDER reports + eas_summary.html afterwards\n");
}

int eas_headless_main(int argc, char **argv) {
    const char *default_ip = NULL;
    const char *specs[MAX_JOBS];
    int nspecs = 0;
    time_t start_t = 0, stop_t = 0;
    int minutes = 0, seg = 60;
    eas_fmt_t fmt3 = EAS_FMT_PCAP;
    char outdir[512] = "";
    int pause_lead = 60;
    bool do_render = false;
    char err[300];

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
        if (strcmp(a, "--eas") == 0) continue;
        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) { headless_usage(argv[0]); return 0; }
        if (strcmp(a, "--render") == 0) { do_render = true; continue; }
        if (!v) { fprintf(stderr, "Option %s needs a value\n", a); return 2; }
        if (strcmp(a, "-i") == 0) default_ip = v;
        else if (strcmp(a, "-c") == 0) {
            if (nspecs >= MAX_JOBS) { fprintf(stderr, "Too many -c options\n"); return 2; }
            specs[nspecs++] = v;
        }
        else if (strcmp(a, "--start") == 0) { if (eas_parse_when(v, &start_t)) { fprintf(stderr, "Bad --start '%s'\n", v); return 2; } }
        else if (strcmp(a, "--stop") == 0) { if (eas_parse_when(v, &stop_t)) { fprintf(stderr, "Bad --stop '%s'\n", v); return 2; } }
        else if (strcmp(a, "--minutes") == 0) { minutes = atoi(v); if (minutes <= 0) { fprintf(stderr, "Bad --minutes\n"); return 2; } }
        else if (strcmp(a, "--seg") == 0) { seg = atoi(v); if (seg < 10) { fprintf(stderr, "--seg must be >= 10\n"); return 2; } }
        else if (strcmp(a, "--fmt") == 0) {
            if (strcasecmp(v, "pcap") == 0) fmt3 = EAS_FMT_PCAP;
            else if (strcasecmp(v, "dbg") == 0) fmt3 = EAS_FMT_DBG;
            else { fprintf(stderr, "--fmt must be pcap or dbg\n"); return 2; }
        }
        else if (strcmp(a, "-o") == 0) snprintf(outdir, sizeof(outdir), "%s", v);
        else if (strcmp(a, "--pause-units") == 0) { if (add_units(v, err, sizeof(err)) < 0) { fprintf(stderr, "%s\n", err); return 2; } }
        else if (strcmp(a, "--pause-ssh") == 0) { if (!safe_token(v)) { fprintf(stderr, "Bad --pause-ssh host\n"); return 2; } snprintf(g_pause_ssh, sizeof(g_pause_ssh), "%s", v); }
        else if (strcmp(a, "--pause-lead") == 0) { pause_lead = atoi(v); if (pause_lead < 0) pause_lead = 0; }
        else if (strcmp(a, "--pre-cmd") == 0) g_pre_cmd = v;
        else if (strcmp(a, "--post-cmd") == 0) g_post_cmd = v;
        else { fprintf(stderr, "Unknown option %s (try --eas --help)\n", a); return 2; }
        i++;
    }

    if (nspecs == 0) { headless_usage(argv[0]); fprintf(stderr, "\nError: give at least one -c\n"); return 2; }
    if (!start_t) start_t = time(NULL);
    if (minutes) stop_t = start_t + (time_t)minutes * 60;
    if (!stop_t) { fprintf(stderr, "Error: give --stop or --minutes\n"); return 2; }
    if (stop_t <= start_t) { fprintf(stderr, "Error: stop time is not after start time\n"); return 2; }
    if (stop_t <= time(NULL)) { fprintf(stderr, "Error: stop time is already in the past\n"); return 2; }
    if (!outdir[0]) {
        struct tm tmv;
        plat_localtime(start_t, &tmv);
        strftime(outdir, sizeof(outdir), "eas_%Y%m%d", &tmv);
    }

    static eas_job_t jobs[MAX_JOBS];
    int njobs = 0;
    for (int i = 0; i < nspecs; i++) {
        eas_job_t *j = &jobs[njobs];
        eas_job_init(j);
        char spec[128];
        snprintf(spec, sizeof(spec), "%s", specs[i]);
        char *eq = strchr(spec, '=');
        if (!eq) { fprintf(stderr, "Error: -c '%s' should look like 1=27p0\n", specs[i]); return 2; }
        *eq = '\0';
        char *tun = spec;
        char *slash = strrchr(spec, '/');
        if (slash) { *slash = '\0'; snprintf(j->ip, sizeof(j->ip), "%s", spec); tun = slash + 1; }
        else if (default_ip) snprintf(j->ip, sizeof(j->ip), "%s", default_ip);
        else { fprintf(stderr, "Error: -c '%s' has no IP and no -i was given\n", specs[i]); return 2; }
        if (!isdigit((unsigned char)tun[0])) { fprintf(stderr, "Error: bad tuner in -c '%s'\n", specs[i]); return 2; }
        j->tuner = atoi(tun);
        if (eas_parse_channel_spec(eq + 1, j, err, sizeof(err)) < 0) { fprintf(stderr, "Error: %s\n", err); return 2; }
        if (j->atsc3) j->fmt = fmt3;
        j->seg_seconds = seg;
        j->force_release = true;
        snprintf(j->outdir, sizeof(j->outdir), "%s", outdir);
        for (int k = 0; k < njobs; k++)
            if (jobs[k].tuner == j->tuner && strcmp(jobs[k].ip, j->ip) == 0) {
                fprintf(stderr, "Error: tuner %d on %s is used twice\n", j->tuner, j->ip);
                return 2;
            }
        snprintf(g_job_labels[njobs], sizeof(g_job_labels[0]), "%s-%d", j->ip, j->tuner);
        njobs++;
    }

    run_params_t rp;
    memset(&rp, 0, sizeof(rp));
    rp.start_t = start_t;
    rp.stop_t = stop_t;
    rp.seg = seg;
    snprintf(rp.outdir, sizeof(rp.outdir), "%s", outdir);
    rp.pause_lead = pause_lead;
    rp.auto_render = do_render;
    rp.echo = true;
    return eas_run(jobs, njobs, &rp);
}
