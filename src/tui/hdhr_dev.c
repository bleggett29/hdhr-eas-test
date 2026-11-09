/*
 * Copyright (C) 2026 Brian Scott - HDHR EAS Test.
 * hdhr_dev.c - HDHomeRun device helpers shared by the GUI.
 * Logic follows HDHomeRun TUI v0.9 by Mark J. Colombo (RabbitEars). GPLv3.
 *
 * Note: libhdhomerun returns pointers into a buffer it reuses, so every
 * answer is copied before the next request.
 */
#include "hdhr_dev.h"
#include "player.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hdhomerun.h"
#include "hdhomerun_device.h"

/* ------------------------------------------------------------------ */
long hdhr_status_value(const char *s, const char *key) {
    const char *f = s ? strstr(s, key) : NULL;
    return f ? strtol(f + strlen(key), NULL, 0) : -999;
}

long hdhr_db_value(const char *s, const char *key) {
    const char *f = s ? strstr(s, key) : NULL;
    if (!f) return -999;
    const char *p = strchr(f, '(');
    const char *sp = strchr(f, ' ');
    if (!p || (sp && sp < p)) return -999;
    return strtol(p + 1, NULL, 10);
}

static int cmp_u(const void *a, const void *b) {
    unsigned x = *(const unsigned *)a, y = *(const unsigned *)b;
    return x < y ? -1 : x > y;
}

/* ------------------------------------------------------------------ */
int hdhr_discover(hdhr_tuner_t *out, int max) {
    plat_init();
    struct hdhomerun_discover_t *ds = hdhomerun_discover_create(NULL);
    if (!ds) return 0;
    uint32_t types[1] = { HDHOMERUN_DEVICE_TYPE_TUNER };
    if (hdhomerun_discover2_find_devices_broadcast(ds, HDHOMERUN_DISCOVER_FLAGS_IPV4_GENERAL, types, 1) < 0) {
        hdhomerun_discover_destroy(ds);
        return 0;
    }
    int n = 0;
    struct hdhomerun_discover2_device_t *dev = hdhomerun_discover2_iter_device_first(ds);
    while (dev && n < max) {
        uint32_t id = hdhomerun_discover2_device_get_device_id(dev);
        int tc = hdhomerun_discover2_device_get_tuner_count(dev);
        bool legacy = hdhomerun_discover2_device_is_legacy(dev);
        struct hdhomerun_discover2_device_if_t *dif = hdhomerun_discover2_iter_device_if_first(dev);
        struct sockaddr_storage addr;
        hdhomerun_discover2_device_if_get_ip_addr(dif, &addr);
        char ip[64];
        hdhomerun_sock_sockaddr_to_ip_str(ip, (struct sockaddr *)&addr, true);
        for (int i = 0; i < tc && n < max; i++) {
            out[n].device_id = id;
            snprintf(out[n].ip, sizeof(out[n].ip), "%s", ip);
            out[n].tuner = i;
            out[n].tuners_on_device = tc;
            out[n].legacy = legacy;
            n++;
        }
        dev = hdhomerun_discover2_iter_device_next(dev);
    }
    hdhomerun_discover_destroy(ds);
    return n;
}

int hdhr_add_by_ip(const char *ip, hdhr_tuner_t *list, int *count, int max) {
    plat_init();
    struct hdhomerun_device_t *hd = hdhomerun_device_create_from_str(ip, NULL);
    if (!hd) return 0;
    char *v;
    char model[64] = "";
    if (hdhomerun_device_get_var(hd, "/sys/model", &v, NULL) <= 0) { hdhomerun_device_destroy(hd); return 0; }
    snprintf(model, sizeof(model), "%s", v);
    uint32_t id = hdhomerun_device_get_device_id(hd);
    for (int i = 0; i < *count; i++) if (list[i].device_id == id) { hdhomerun_device_destroy(hd); return 0; }
    bool legacy = strstr(model, "hdhomerun3") || strstr(model, "hdhomerun_");
    int tc = 0;
    for (int i = 0; i < 8; i++) {
        if (hdhomerun_device_set_tuner(hd, i) < 0) break;
        struct hdhomerun_tuner_status_t st;
        char *raw;
        if (hdhomerun_device_get_tuner_status(hd, &raw, &st) <= 0) break;
        tc++;
    }
    hdhomerun_device_destroy(hd);
    int added = 0;
    for (int i = 0; i < tc && *count < max; i++) {
        hdhr_tuner_t *t = &list[(*count)++];
        t->device_id = id;
        snprintf(t->ip, sizeof(t->ip), "%s", ip);
        t->tuner = i;
        t->tuners_on_device = tc;
        t->legacy = legacy;
        added++;
    }
    return added;
}

/* ------------------------------------------------------------------ */
int hdhr_get_status(struct hdhomerun_device_t *hd, hdhr_status_t *st) {
    memset(st, 0, sizeof(*st));
    st->id = -1;
    st->ss_db = st->snq_db = -999;
    struct hdhomerun_tuner_status_t ts;
    char *raw;
    if (hdhomerun_device_get_tuner_status(hd, &raw, &ts) <= 0) return -1;
    char rawc[512];
    snprintf(rawc, sizeof(rawc), "%s", raw);
    st->ok = true;
    snprintf(st->channel, sizeof(st->channel), "%s", ts.channel);
    snprintf(st->lock, sizeof(st->lock), "%s", ts.lock_str);
    snprintf(st->channel_disp, sizeof(st->channel_disp), "%s", ts.channel);
    snprintf(st->lock_disp, sizeof(st->lock_disp), "%s", ts.lock_str);
    if (!strncmp(ts.channel, "atsc3:", 6)) {
        const char *c1 = strchr(ts.channel, ':');
        const char *c2 = c1 ? strchr(c1 + 1, ':') : NULL;
        if (c2) {
            snprintf(st->channel_disp, sizeof(st->channel_disp), "%.*s", (int)(c2 - ts.channel), ts.channel);
            snprintf(st->lock_disp, sizeof(st->lock_disp), "atsc3:%s", c2 + 1);
        }
    }
    st->atsc3 = strstr(ts.lock_str, "atsc3") != NULL;
    st->locked = strcmp(ts.lock_str, "none") != 0 && ts.lock_str[0];
    st->ss = (int)ts.signal_strength;
    st->snq = (int)ts.signal_to_noise_quality;
    st->seq = (int)ts.symbol_error_quality;
    st->ss_db = hdhr_db_value(rawc, "ss=");
    st->snq_db = hdhr_db_value(rawc, "snq=");
    long bps = hdhr_status_value(rawc, "bps=");
    long pps = hdhr_status_value(rawc, "pps=");
    st->mbps = (pps > 0 && bps != -999) ? bps / 1000000.0 : 0.0;
    snprintf(st->id_label, sizeof(st->id_label), "%s", st->atsc3 ? "BSID" : "TSID");

    char *v;
    char streaminfo[4096] = "";
    if (hdhomerun_device_get_tuner_streaminfo(hd, &v) > 0) snprintf(streaminfo, sizeof(streaminfo), "%s", v);
    long id = hdhr_status_value(streaminfo, "tsid=");
    char plpinfo[4096] = "";
    if (st->atsc3 && hdhomerun_device_get_tuner_plpinfo(hd, &v) > 0) {
        snprintf(plpinfo, sizeof(plpinfo), "%s", v);
        long b = hdhr_status_value(plpinfo, "bsid=");
        if (b != -999) id = b;
    }
    st->id = id == -999 ? -1 : id;

    if (hdhomerun_device_get_tuner_target(hd, &v) > 0) snprintf(st->target, sizeof(st->target), "%s", v);
    struct hdhomerun_tuner_vstatus_t vs;
    char *vraw;
    if (hdhomerun_device_get_tuner_vstatus(hd, &vraw, &vs) > 0 && vs.vchannel[0]) {
        snprintf(st->vchannel, sizeof(st->vchannel), "%s", vs.vchannel);
        snprintf(st->vname, sizeof(st->vname), "%s", vs.name);
    }

    char tmp[4096];
    snprintf(tmp, sizeof(tmp), "%s", streaminfo);
    for (char *save = NULL, *ln = strtok_r(tmp, "\n", &save); ln && st->nprog < HDHR_MAX_PROGS; ln = strtok_r(NULL, "\n", &save))
        if (strchr(ln, ':') || strstr(ln, "program="))
            snprintf(st->progs[st->nprog++], sizeof(st->progs[0]), "%s", ln);

    if (plpinfo[0]) {
        snprintf(tmp, sizeof(tmp), "%s", plpinfo);
        int ids[HDHR_MAX_PLPS];
        for (char *save = NULL, *ln = strtok_r(tmp, "\n", &save); ln && st->nplp < HDHR_MAX_PLPS; ln = strtok_r(NULL, "\n", &save)) {
            if (!strncmp(ln, "bsid=", 5)) continue;
            int id2 = 0;
            sscanf(ln, "%d:", &id2);
            ids[st->nplp] = id2;
            snprintf(st->plps[st->nplp++], sizeof(st->plps[0]), "%s", ln);
        }
        /* sort by PLP id */
        for (int i = 1; i < st->nplp; i++)
            for (int j = i; j > 0 && ids[j - 1] > ids[j]; j--) {
                int t = ids[j]; ids[j] = ids[j - 1]; ids[j - 1] = t;
                char b[220];
                memcpy(b, st->plps[j], sizeof(b));
                memcpy(st->plps[j], st->plps[j - 1], sizeof(b));
                memcpy(st->plps[j - 1], b, sizeof(b));
            }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
int hdhr_channel_list(struct hdhomerun_device_t *hd, unsigned *out, int max) {
    char *v;
    if (hdhomerun_device_get_tuner_channelmap(hd, &v) <= 0) return 0;
    char full[2048];
    snprintf(full, sizeof(full), "%s", v);
    int n = 0;
    /* Some firmware answers "map ch ch ch ..." - use that list like the TUI does */
    char tmp[2048];
    snprintf(tmp, sizeof(tmp), "%s", full);
    char *save = NULL;
    char *tok = strtok_r(tmp, " \r\n", &save);
    char map[64];
    snprintf(map, sizeof(map), "%s", tok ? tok : "");
    for (tok = strtok_r(NULL, " \r\n", &save); tok && n < max; tok = strtok_r(NULL, " \r\n", &save))
        if (isdigit((unsigned char)*tok)) out[n++] = (unsigned)strtoul(tok, NULL, 10);
    /* Otherwise the channels of that map from libhdhomerun's tables */
    struct hdhomerun_channel_list_t *cl = n ? NULL : hdhomerun_channel_list_create(map);
    if (cl) {
        struct hdhomerun_channel_entry_t *e = hdhomerun_channel_list_first(cl);
        while (e && n < max) {
            unsigned ch = (unsigned)hdhomerun_channel_entry_channel_number(e);
            bool dup = false;
            for (int i = 0; i < n; i++) if (out[i] == ch) dup = true;
            if (!dup) out[n++] = ch;
            e = hdhomerun_channel_list_next(cl, e);
        }
        hdhomerun_channel_list_destroy(cl);
    }
    if (n > 1) qsort(out, n, sizeof(unsigned), cmp_u);
    return n;
}

unsigned hdhr_current_rf(struct hdhomerun_device_t *hd) {
    struct hdhomerun_tuner_status_t st;
    char *raw;
    if (hdhomerun_device_get_tuner_status(hd, &raw, &st) <= 0) return 0;
    const char *p = strchr(st.channel, ':');
    p = p ? p + 1 : st.channel;
    return isdigit((unsigned char)*p) ? (unsigned)strtoul(p, NULL, 10) : 0;
}

int hdhr_tune(struct hdhomerun_device_t *hd, const char *what) {
    char s[100];
    snprintf(s, sizeof(s), "auto:%s", what);
    if (hdhomerun_device_set_tuner_channel(hd, s) <= 0) return -1;
    struct hdhomerun_tuner_status_t st;
    hdhomerun_device_wait_for_lock(hd, &st);
    return 0;
}

int hdhr_step_channel(struct hdhomerun_device_t *hd, int dir) {
    unsigned chans[HDHR_MAX_CHANS];
    int n = hdhr_channel_list(hd, chans, HDHR_MAX_CHANS);
    unsigned cur = hdhr_current_rf(hd), next = 0;
    if (n > 0) {
        int idx = -1;
        for (int i = 0; i < n; i++) if (chans[i] == cur) idx = i;
        if (idx < 0) idx = dir > 0 ? -1 : n;
        idx = (idx + dir + n) % n;
        next = chans[idx];
    } else {
        next = cur ? cur + dir : (dir > 0 ? 2 : 69);
        if (next > 69) next = 2;
        if (next < 2) next = 69;
    }
    char s[32];
    snprintf(s, sizeof(s), "auto:%u", next);
    return hdhomerun_device_set_tuner_channel(hd, s) > 0 ? (int)next : -1;
}

unsigned hdhr_seek(struct hdhomerun_device_t *hd, int dir,
                   bool (*progress)(unsigned ch, double left, void *user), void *user) {
    unsigned chans[HDHR_MAX_CHANS];
    int n = hdhr_channel_list(hd, chans, HDHR_MAX_CHANS);
    unsigned cur = hdhr_current_rf(hd);
    int idx = -1;
    for (int i = 0; i < n; i++) if (chans[i] == cur) idx = i;
    if (idx < 0 && n > 0) idx = dir > 0 ? -1 : n;
    const unsigned start = cur;
    bool first = true;
    for (;;) {
        unsigned ch;
        if (n > 0) { idx = (idx + dir + n) % n; ch = chans[idx]; }
        else {
            if (!cur) cur = dir > 0 ? 1 : 70;
            cur += dir;
            if (cur > 69) cur = 2;
            if (cur < 2) cur = 69;
            ch = cur;
        }
        if (!first && ch == start) return 0;
        first = false;
        char s[32];
        snprintf(s, sizeof(s), "auto:%u", ch);
        hdhomerun_device_set_tuner_channel(hd, s);
        for (int i = 0; i < 25; i++) {
            struct hdhomerun_tuner_status_t st;
            char *raw;
            if (hdhomerun_device_get_tuner_status(hd, &raw, &st) > 0 && st.signal_to_noise_quality > 0) return ch;
            if (progress && !progress(ch, (25 - i) / 10.0, user)) return 0;
            plat_sleep_ms(100);
        }
    }
}

int hdhr_channel_maps(struct hdhomerun_device_t *hd, char maps[][32], int max, char *current, size_t curlen) {
    char *v;
    if (current && curlen) current[0] = '\0';
    if (hdhomerun_device_get_tuner_channelmap(hd, &v) > 0 && current) {
        snprintf(current, curlen, "%s", v);
        current[strcspn(current, " \r\n")] = '\0';
    }
    if (hdhomerun_device_get_var(hd, "/sys/features", &v, NULL) <= 0) return 0;
    char feat[2048];
    snprintf(feat, sizeof(feat), "%s", v);
    char *line = strstr(feat, "channelmap:");
    if (!line) return 0;
    line[strcspn(line, "\n")] = '\0';
    int n = 0;
    for (char *save = NULL, *t = strtok_r(line, " ", &save); t && n < max; t = strtok_r(NULL, " ", &save))
        if (strcmp(t, "channelmap:")) snprintf(maps[n++], 32, "%s", t);
    return n;
}

int hdhr_set_channel_map(struct hdhomerun_device_t *hd, const char *map) {
    return hdhomerun_device_set_tuner_channelmap(hd, map) > 0 ? 0 : -1;
}

int hdhr_set_plps(struct hdhomerun_device_t *hd, const char *list, char *err, size_t errlen) {
    struct hdhomerun_tuner_status_t st;
    char *raw;
    if (hdhomerun_device_get_tuner_status(hd, &raw, &st) <= 0 || !strstr(st.lock_str, "atsc3")) {
        snprintf(err, errlen, "The tuner isn't locked to an ATSC 3.0 channel.");
        return -1;
    }
    char freq[24] = "";
    const char *p = strchr(st.channel, ':');
    if (p) {
        p++;
        int i = 0;
        while (isdigit((unsigned char)*p) && i < (int)sizeof(freq) - 1) freq[i++] = *p++;
        freq[i] = '\0';
    }
    if (!freq[0]) { snprintf(err, errlen, "Couldn't read the current channel."); return -1; }
    char out[64] = "";
    if (list && *list) {
        int j = 0;
        for (const char *c = list; *c && j < (int)sizeof(out) - 1; c++) {
            if (*c == ',' || *c == '+' || *c == ' ') { if (j && out[j - 1] != '+') out[j++] = '+'; }
            else if (isdigit((unsigned char)*c)) out[j++] = *c;
        }
        while (j && out[j - 1] == '+') j--;
        out[j] = '\0';
    } else {
        char *v;
        if (hdhomerun_device_get_tuner_plpinfo(hd, &v) > 0) {
            char info[4096];
            snprintf(info, sizeof(info), "%s", v);
            for (char *save = NULL, *ln = strtok_r(info, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
                int id;
                if (sscanf(ln, "%d:", &id) == 1) {
                    size_t L = strlen(out);
                    snprintf(out + L, sizeof(out) - L, "%s%d", L ? "+" : "", id);
                }
            }
        }
    }
    if (!out[0]) { snprintf(err, errlen, "No PLPs given or found."); return -1; }
    char tune[100];
    snprintf(tune, sizeof(tune), "atsc3:%s:%s", freq, out);
    if (hdhomerun_device_set_tuner_channel(hd, tune) <= 0) { snprintf(err, errlen, "The tuner refused %s.", tune); return -1; }
    hdhomerun_device_wait_for_lock(hd, &st);
    return 0;
}

int hdhr_programs(struct hdhomerun_device_t *hd, hdhr_program_t *out, int max) {
    char *v;
    if (hdhomerun_device_get_tuner_streaminfo(hd, &v) <= 0) return 0;
    char info[4096];
    snprintf(info, sizeof(info), "%s", v);
    int n = 0;
    for (char *save = NULL, *ln = strtok_r(info, "\n", &save); ln && n < max; ln = strtok_r(NULL, "\n", &save)) {
        while (isspace((unsigned char)*ln)) ln++;
        hdhr_program_t *p = &out[n];
        memset(p, 0, sizeof(*p));
        p->plp = -1;
        if (!strncmp(ln, "program=", 8)) {
            snprintf(p->display, sizeof(p->display), "%s", ln);
            sscanf(ln, "program=%15s", p->program);
            const char *pl = strstr(ln, "plp=");
            if (pl) sscanf(pl, "plp=%d", &p->plp);
            n++;
        } else if (!strncmp(ln, "program ", 8) || (isdigit((unsigned char)*ln) && strchr(ln, ':'))) {
            snprintf(p->display, sizeof(p->display), "%s", ln);
            if (!strncmp(ln, "program ", 8)) sscanf(ln, "program %15s", p->program);
            else sscanf(ln, "%15s", p->program);
            char *c = strchr(p->program, ':');
            if (c) *c = '\0';
            n++;
        }
    }
    return n;
}

/* ------------------------------------------------------------------ */
static int free_udp_port(void) {
    plat_sock_t s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == PLAT_BAD_SOCK) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = 0;
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) < 0) { plat_sock_close(s); return -1; }
    socklen_t L = sizeof(a);
    getsockname(s, (struct sockaddr *)&a, &L);
    plat_sock_close(s);
    return ntohs(a.sin_port);
}

int hdhr_free_udp_port(void) { return free_udp_port(); }

int hdhr_stream_to_me(struct hdhomerun_device_t *hd, const hdhr_tuner_t *t, const char *program, int port,
                      char *msg, size_t msglen) {
    char path[64];
    snprintf(path, sizeof(path), "/tuner%d/program", t->tuner);
    if (hdhomerun_device_set_var(hd, path, program, NULL, NULL) < 0) { snprintf(msg, msglen, "Failed to set program %s.", program); return -1; }
    char local[64];
    if (plat_local_ip_towards(t->ip, local, sizeof(local)) < 0) { snprintf(msg, msglen, "Couldn't find this computer's address towards %s.", t->ip); return -1; }
    char target[128];
    snprintf(target, sizeof(target), "udp://%s:%d", local, port);
    snprintf(path, sizeof(path), "/tuner%d/target", t->tuner);
    if (hdhomerun_device_set_var(hd, path, target, NULL, NULL) < 0) { snprintf(msg, msglen, "Failed to set the stream target."); return -1; }
    return 0;
}

int hdhr_play_start(struct hdhomerun_device_t *hd, const hdhr_tuner_t *t, const char *program,
                    plat_pid_t *pid, char *msg, size_t msglen) {
    char ffplay[1024];
    if (!player_find(ffplay, sizeof(ffplay))) {
        snprintf(msg, msglen, "ffplay not found. %s", player_hint());
        return -1;
    }
    int port = free_udp_port();
    if (port < 0) { snprintf(msg, msglen, "Couldn't find a free UDP port."); return -1; }
    if (hdhr_stream_to_me(hd, t, program, port, msg, msglen) < 0) return -1;
    char title[160];
    snprintf(title, sizeof(title), "HDHR EAS Test - %08X-%d program %s", (unsigned)t->device_id, t->tuner, program);
    *pid = player_spawn(ffplay, port, title, true);
    if (*pid <= 0) {
        hdhomerun_device_set_tuner_target(hd, "none");
        snprintf(msg, msglen, "Couldn't start ffplay (%s).", ffplay);
        return -1;
    }
    snprintf(msg, msglen, "Playing program %s in ffplay (port %d). Close the ffplay window or press q in it to stop.",
             program, port);
    return 0;
}

void hdhr_play_stop(struct hdhomerun_device_t *hd, plat_pid_t *pid) {
    if (*pid > 0 && plat_pid_alive(*pid)) plat_terminate(*pid);
    *pid = 0;
    if (hd) hdhomerun_device_set_tuner_target(hd, "none");
}
