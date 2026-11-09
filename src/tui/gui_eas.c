/*
 * Copyright (C) 2026 Brian Scott - HDHR EAS Test.
 * gui_eas.c - the EAS Test page of the GTK4 GUI: per-tuner channels,
 * schedule and options on the left; the run monitor, zips and reports on the
 * right. Same settings file and background runner as the TUI's EAS screen.
 * GPLv3.
 */
#include "gui.h"
#include "eas_capture.h"

#include <string.h>

#include "hdhomerun.h"
#include "hdhomerun_device.h"

#define MAX_ROWS 64

typedef struct {
    char devid[16], ip[64];
    int tuner;
    GtkWidget *now, *entry, *type;
} EasRow;

static EasRow R[MAX_ROWS];
static int NR = 0;
static gboolean loading = FALSE;   /* don't save while filling widgets */

static void save_cfg(void) {
    if (eas_config_save(&A.cfg) < 0) gui_msg("Couldn't save settings in %s", eas_config_dir());
}

static const char *chan_type(const char *c) {
    if (!c || !*c) return "";
    return (strpbrk(c, "pP:") || !g_ascii_strncasecmp(c, "atsc3", 5)) ? "ATSC 3.0" : "ATSC 1.0";
}

/* ------------------------------------------------------------------ */
/* Tuner rows                                                          */
/* ------------------------------------------------------------------ */
static void on_chan_changed(GtkEditable *e, gpointer u) {
    if (loading) return;
    EasRow *r = &R[GPOINTER_TO_INT(u)];
    const char *t = gtk_editable_get_text(e);
    char txt[64];
    snprintf(txt, sizeof(txt), "%s", t);
    g_strstrip(txt);
    eas_cfg_tuner_t *ct = eas_config_find(&A.cfg, r->devid, r->ip, r->tuner);
    if (!txt[0] || !strcmp(txt, "-")) {
        if (ct) ct->chan[0] = '\0';
        gtk_widget_remove_css_class(GTK_WIDGET(e), "error");
        gtk_label_set_text(GTK_LABEL(r->type), "");
        save_cfg();
        return;
    }
    eas_job_t j;
    eas_job_init(&j);
    char err[200];
    int rc = eas_parse_channel_spec(txt, &j, err, sizeof(err));
    eas_job_destroy(&j);
    if (rc < 0) {
        gtk_widget_add_css_class(GTK_WIDGET(e), "error");
        gtk_widget_set_tooltip_text(GTK_WIDGET(e), err);
        gtk_label_set_text(GTK_LABEL(r->type), "?");
        return;
    }
    gtk_widget_remove_css_class(GTK_WIDGET(e), "error");
    gtk_widget_set_tooltip_text(GTK_WIDGET(e), "27 = ATSC 1.0 RF 27;  31p0 or 31p0p1 = ATSC 3.0 RF 31 with PLPs");
    ct = eas_config_add(&A.cfg, r->devid, r->ip, r->tuner);
    if (ct) snprintf(ct->chan, sizeof(ct->chan), "%s", txt);
    gtk_label_set_text(GTK_LABEL(r->type), chan_type(txt));
    save_cfg();
}

static void on_clear(GtkWidget *w, gpointer u) {
    (void)w;
    gtk_editable_set_text(GTK_EDITABLE(R[GPOINTER_TO_INT(u)].entry), "");
}

/* "Use what it's tuned to now" needs the tuner's status - fetch off the UI thread */
typedef struct { int row; char ip[64]; int tuner; char spec[64]; char now[64]; char lock[32]; } UseCtx;

static gboolean idle_use(gpointer p) {
    UseCtx *u = p;
    if (u->row < NR) {
        if (u->spec[0]) {
            gtk_editable_set_text(GTK_EDITABLE(R[u->row].entry), u->spec);
            gui_msg("%s-%d will record %s (%s).", R[u->row].devid, u->tuner, u->spec, chan_type(u->spec));
        } else {
            gui_msg("%s-%d isn't tuned to anything right now.", R[u->row].devid, u->tuner);
        }
    }
    g_free(u);
    return G_SOURCE_REMOVE;
}

static void status_to_spec(const char *channel, const char *lock, char *out, size_t n) {
    out[0] = '\0';
    if (!channel[0] || !strcmp(channel, "none") || !lock[0] || strstr(lock, "none")) return;
    const char *p = strchr(channel, ':');
    p = p ? p + 1 : channel;
    unsigned rf = (unsigned)strtoul(p, NULL, 10);
    if (!strstr(lock, "atsc3")) { snprintf(out, n, "%u", rf); return; }
    char plps[48] = "";
    const char *c2 = strchr(p, ':');
    if (c2) {
        char tmp[48];
        snprintf(tmp, sizeof(tmp), "%s", c2 + 1);
        for (char *save = NULL, *tok = strtok_r(tmp, "+", &save); tok; tok = strtok_r(NULL, "+", &save)) {
            size_t L = strlen(plps);
            snprintf(plps + L, sizeof(plps) - L, "p%d", atoi(tok));
        }
    }
    snprintf(out, n, "%u%s", rf, plps[0] ? plps : "p0");
}

static gpointer use_thread(gpointer p) {
    UseCtx *u = p;
    struct hdhomerun_device_t *hd = hdhomerun_device_create_from_str(u->ip, NULL);
    if (hd && hdhomerun_device_set_tuner(hd, u->tuner) > 0) {
        struct hdhomerun_tuner_status_t st;
        char *raw;
        if (hdhomerun_device_get_tuner_status(hd, &raw, &st) > 0) status_to_spec(st.channel, st.lock_str, u->spec, sizeof(u->spec));
    }
    if (hd) hdhomerun_device_destroy(hd);
    g_idle_add(idle_use, u);
    return NULL;
}

static void on_use(GtkWidget *w, gpointer p) {
    (void)w;
    int row = GPOINTER_TO_INT(p);
    UseCtx *u = g_new0(UseCtx, 1);
    u->row = row;
    snprintf(u->ip, sizeof(u->ip), "%s", R[row].ip);
    u->tuner = R[row].tuner;
    g_thread_unref(g_thread_new("use", use_thread, u));
}

/* "Tuned to now" column for every row */
typedef struct { int n; char ip[MAX_ROWS][64]; int tuner[MAX_ROWS]; char now[MAX_ROWS][64]; } NowCtx;

static gboolean idle_now(gpointer p) {
    NowCtx *c = p;
    for (int i = 0; i < c->n && i < NR; i++) gtk_label_set_text(GTK_LABEL(R[i].now), c->now[i]);
    g_free(c);
    return G_SOURCE_REMOVE;
}

static gpointer now_thread(gpointer p) {
    NowCtx *c = p;
    struct hdhomerun_device_t *hd = NULL;
    char cur[64] = "";
    for (int i = 0; i < c->n; i++) {
        if (!c->ip[i][0]) { snprintf(c->now[i], sizeof(c->now[i]), "(not found)"); continue; }
        if (!hd || strcmp(cur, c->ip[i])) {
            if (hd) hdhomerun_device_destroy(hd);
            hd = hdhomerun_device_create_from_str(c->ip[i], NULL);
            snprintf(cur, sizeof(cur), "%s", c->ip[i]);
        }
        snprintf(c->now[i], sizeof(c->now[i]), "?");
        if (hd && hdhomerun_device_set_tuner(hd, c->tuner[i]) > 0) {
            struct hdhomerun_tuner_status_t st;
            char *raw;
            if (hdhomerun_device_get_tuner_status(hd, &raw, &st) > 0)
                snprintf(c->now[i], sizeof(c->now[i]), "%s", (st.lock_str[0] && strcmp(st.lock_str, "none")) ? st.channel : "idle");
        }
    }
    if (hd) hdhomerun_device_destroy(hd);
    g_idle_add(idle_now, c);
    return NULL;
}

static void refresh_now(void) {
    NowCtx *c = g_new0(NowCtx, 1);
    c->n = NR;
    for (int i = 0; i < NR; i++) {
        bool found = false;
        for (int k = 0; k < A.ntuners; k++)
            if (A.tuners[k].tuner == R[i].tuner && !strcmp(A.tuners[k].ip, R[i].ip)) found = true;
        snprintf(c->ip[i], sizeof(c->ip[i]), "%s", found ? R[i].ip : "");
        c->tuner[i] = R[i].tuner;
    }
    g_thread_unref(g_thread_new("now", now_thread, c));
}

static void on_refresh_now(GtkWidget *w, gpointer u) { (void)w; (void)u; refresh_now(); }

void eas_page_rebuild_tuners(void) {
    if (!A.eas_tuner_grid) return;
    GtkWidget *child;
    while ((child = gtk_widget_get_first_child(A.eas_tuner_grid))) gtk_grid_remove(GTK_GRID(A.eas_tuner_grid), child);
    const char *hdr[] = { "Tuner", "IP", "Tuned to now", "EAS channel", "Type" };
    for (int c = 0; c < 5; c++) {
        GtkWidget *l = gtk_label_new(NULL);
        char m[64];
        snprintf(m, sizeof(m), "<b>%s</b>", hdr[c]);
        gtk_label_set_markup(GTK_LABEL(l), m);
        gtk_label_set_xalign(GTK_LABEL(l), 0);
        gtk_grid_attach(GTK_GRID(A.eas_tuner_grid), l, c, 0, 1, 1);
    }
    loading = TRUE;
    NR = 0;
    /* tuners found now, then saved ones that weren't found */
    for (int i = 0; i < A.ntuners && NR < MAX_ROWS; i++) {
        EasRow *r = &R[NR];
        memset(r, 0, sizeof(*r));
        snprintf(r->devid, sizeof(r->devid), "%08X", A.tuners[i].device_id);
        snprintf(r->ip, sizeof(r->ip), "%s", A.tuners[i].ip);
        r->tuner = A.tuners[i].tuner;
        eas_cfg_tuner_t *t = eas_config_find(&A.cfg, r->devid, r->ip, r->tuner);
        if (t && strcmp(t->ip, r->ip)) { snprintf(t->ip, sizeof(t->ip), "%s", r->ip); save_cfg(); }
        NR++;
    }
    for (int i = 0; i < A.cfg.ntuners && NR < MAX_ROWS; i++) {
        eas_cfg_tuner_t *t = &A.cfg.tuners[i];
        if (!t->chan[0]) continue;
        bool seen = false;
        for (int k = 0; k < NR; k++)
            if (R[k].tuner == t->tuner && (!g_ascii_strcasecmp(R[k].devid, t->devid) || !strcmp(R[k].ip, t->ip))) seen = true;
        if (seen) continue;
        EasRow *r = &R[NR++];
        memset(r, 0, sizeof(*r));
        snprintf(r->devid, sizeof(r->devid), "%s", t->devid);
        snprintf(r->ip, sizeof(r->ip), "%s", t->ip);
        r->tuner = t->tuner;
    }
    for (int i = 0; i < NR; i++) {
        EasRow *r = &R[i];
        char lab[48];
        snprintf(lab, sizeof(lab), "%s-%d", r->devid, r->tuner);
        GtkWidget *l1 = gtk_label_new(lab);
        GtkWidget *l2 = gtk_label_new(r->ip);
        r->now = gtk_label_new("…");
        r->entry = gtk_entry_new();
        gtk_entry_set_placeholder_text(GTK_ENTRY(r->entry), "-");
        gtk_editable_set_width_chars(GTK_EDITABLE(r->entry), 9);
        gtk_editable_set_max_width_chars(GTK_EDITABLE(r->entry), 9);
        gtk_widget_set_tooltip_text(r->entry, "27 = ATSC 1.0 RF 27;  31p0 or 31p0p1 = ATSC 3.0 RF 31 with PLPs");
        eas_cfg_tuner_t *t = eas_config_find(&A.cfg, r->devid, r->ip, r->tuner);
        if (t && t->chan[0]) gtk_editable_set_text(GTK_EDITABLE(r->entry), t->chan);
        r->type = gtk_label_new(t ? chan_type(t->chan) : "");
        g_signal_connect(r->entry, "changed", G_CALLBACK(on_chan_changed), GINT_TO_POINTER(i));
        GtkWidget *bu = gtk_button_new_with_label("Use current");
        gtk_widget_add_css_class(bu, "flat");
        gtk_widget_set_tooltip_text(bu, "Record whatever this tuner is tuned to now (tune it on the Tuners page first)");
        g_signal_connect(bu, "clicked", G_CALLBACK(on_use), GINT_TO_POINTER(i));
        GtkWidget *bc = gtk_button_new_with_label("Clear");
        gtk_widget_add_css_class(bc, "flat");
        g_signal_connect(bc, "clicked", G_CALLBACK(on_clear), GINT_TO_POINTER(i));
        GtkWidget *ws[] = { l1, l2, r->now, r->entry, r->type, bu, bc };
        for (int c = 0; c < 7; c++) {
            if (GTK_IS_LABEL(ws[c])) gtk_label_set_xalign(GTK_LABEL(ws[c]), 0);
            gtk_grid_attach(GTK_GRID(A.eas_tuner_grid), ws[c], c, i + 1, 1, 1);
        }
    }
    if (!NR) {
        GtkWidget *l = gtk_label_new("No tuners yet - use Refresh or Add device… at the top.");
        gtk_grid_attach(GTK_GRID(A.eas_tuner_grid), l, 0, 1, 5, 1);
    }
    loading = FALSE;
    refresh_now();
}

/* ------------------------------------------------------------------ */
/* Schedule and options                                                */
/* ------------------------------------------------------------------ */
static void on_time_changed(GtkEditable *e, gpointer which) {
    if (loading) return;
    char *field = GPOINTER_TO_INT(which) ? A.cfg.stop : A.cfg.start;
    time_t t;
    const char *txt = gtk_editable_get_text(e);
    if (eas_parse_when(txt, &t) != 0) { gtk_widget_add_css_class(GTK_WIDGET(e), "error"); return; }
    gtk_widget_remove_css_class(GTK_WIDGET(e), "error");
    struct tm tm;
    plat_localtime(t, &tm);
    strftime(field, 32, "%Y-%m-%d %H:%M", &tm);
    save_cfg();
}

static void on_opt_changed(GtkWidget *w, gpointer u) {
    (void)w; (void)u;
    if (loading) return;
    A.cfg.seg = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(A.e_seg));
    A.cfg.fmt3 = gtk_drop_down_get_selected(GTK_DROP_DOWN(A.e_fmt)) == 1 ? EAS_FMT_DBG : EAS_FMT_PCAP;
    const char *o = gtk_editable_get_text(GTK_EDITABLE(A.e_outdir));
    if (o[0]) snprintf(A.cfg.outdir, sizeof(A.cfg.outdir), "%s", o);
    A.cfg.auto_render = gtk_check_button_get_active(GTK_CHECK_BUTTON(A.e_render));
    A.cfg.test_minutes = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(A.e_test_min));
    A.cfg.test_seg = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(A.e_test_seg));
    if (A.e_units) {
        snprintf(A.cfg.pause_units, sizeof(A.cfg.pause_units), "%s", gtk_editable_get_text(GTK_EDITABLE(A.e_units)));
        snprintf(A.cfg.pause_ssh, sizeof(A.cfg.pause_ssh), "%s", gtk_editable_get_text(GTK_EDITABLE(A.e_host)));
        A.cfg.pause_lead = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(A.e_lead));
    }
    save_cfg();
}

static void set_outdir_from_file(GFile *f) {
    if (!f) return;
    char *path = g_file_get_path(f);
    if (path) {
        for (char *p = path; *p; p++) if (*p == '\\') *p = '/';
        gtk_editable_set_text(GTK_EDITABLE(A.e_outdir), path);
        g_free(path);
    }
}

#if GTK_CHECK_VERSION(4, 10, 0)
static void folder_chosen(GObject *src, GAsyncResult *res, gpointer u) {
    (void)u;
    GFile *f = gtk_file_dialog_select_folder_finish(GTK_FILE_DIALOG(src), res, NULL);
    if (!f) return;
    set_outdir_from_file(f);
    g_object_unref(f);
}

static void on_browse(GtkWidget *w, gpointer u) {
    (void)w; (void)u;
    GtkFileDialog *d = gtk_file_dialog_new();
    gtk_file_dialog_set_title(d, "Output folder for the EAS test");
    gtk_file_dialog_select_folder(d, GTK_WINDOW(A.win), NULL, folder_chosen, NULL);
    g_object_unref(d);
}
#else
/* GTK 4.8 and older: GtkFileChooserNative */
static void folder_response(GtkNativeDialog *d, int resp, gpointer u) {
    (void)u;
    if (resp == GTK_RESPONSE_ACCEPT) {
        GFile *f = gtk_file_chooser_get_file(GTK_FILE_CHOOSER(d));
        set_outdir_from_file(f);
        if (f) g_object_unref(f);
    }
    g_object_unref(d);
}

static void on_browse(GtkWidget *w, gpointer u) {
    (void)w; (void)u;
    GtkFileChooserNative *d = gtk_file_chooser_native_new("Output folder for the EAS test",
        GTK_WINDOW(A.win), GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER, "Select", "Cancel");
    g_signal_connect(d, "response", G_CALLBACK(folder_response), NULL);
    gtk_native_dialog_show(GTK_NATIVE_DIALOG(d));
}
#endif

static gboolean idle_detected(gpointer p) {
    char *found = p;
    if (!found[0]) gui_msg("No running services that use an HDHomeRun were found.");
    else {
        gtk_editable_set_text(GTK_EDITABLE(A.e_units), found);
        gui_msg("Services to pause: %s", found);
    }
    g_free(found);
    return G_SOURCE_REMOVE;
}

static gpointer detect_thread(gpointer p) {
    (void)p;
    char *found = g_malloc0(512);
    eas_detect_units(found, 512);
    g_idle_add(idle_detected, found);
    return NULL;
}

static void on_detect(GtkWidget *w, gpointer u) { (void)w; (void)u; g_thread_unref(g_thread_new("detect", detect_thread, NULL)); }

/* ------------------------------------------------------------------ */
/* Test / Arm / Cancel                                                 */
/* ------------------------------------------------------------------ */
typedef struct { char mode[16]; char err[300]; int ok; } LaunchCtx;

static gboolean idle_launched(gpointer p) {
    LaunchCtx *l = p;
    if (l->ok) gui_msg("%s run started in the background - watch it on the right.", !strcmp(l->mode, "test") ? "Test" : "Scheduled");
    else gui_info("Couldn't start the run", l->err);
    g_free(l);
    return G_SOURCE_REMOVE;
}

static gpointer launch_thread(gpointer p) {
    LaunchCtx *l = p;
    l->ok = eas_launch_background(l->mode, A.pause_services, l->err, sizeof(l->err)) == 0;
    g_idle_add(idle_launched, l);
    return NULL;
}

static void launch(const char *mode) {
    LaunchCtx *l = g_new0(LaunchCtx, 1);
    snprintf(l->mode, sizeof(l->mode), "%s", mode);
    g_thread_unref(g_thread_new("launch", launch_thread, l));
}

static void test_confirmed(gboolean yes, gpointer u) { (void)u; if (yes) launch("test"); }
static void arm_confirmed(gboolean yes, gpointer u) { (void)u; if (yes) launch("armed"); }

static gboolean run_active(void) {
    eas_state_t st;
    eas_state_read(&st);
    if (st.alive) {
        gui_info("A run is already active", "Cancel it on the right first, or wait for it to finish.");
        return TRUE;
    }
    return FALSE;
}

static const char *free_note(void) {
    return "NOTE: Free each tuner you will use for the EAS test (RabbitEars bandscan, DVR, live viewing, etc.).";
}

static void on_test(GtkWidget *w, gpointer u) {
    (void)w; (void)u;
    on_opt_changed(NULL, NULL);
    if (run_active()) return;
    char err[300];
    if (eas_config_validate(&A.cfg, true, err, sizeof(err)) < 0) { gui_info("Can't start a test", err); return; }
    char t[200], d[400];
    snprintf(t, sizeof(t), "Start a %d-minute test now on %d tuner(s)?", A.cfg.test_minutes, eas_config_active_count(&A.cfg));
    snprintf(d, sizeof(d), "%s\n\nIt records, makes the reports, and saves them in a test_<date-time> folder under %s.",
             (A.pause_services && A.cfg.pause_units[0]) ? "Your services will be paused and restarted afterwards." : free_note(),
             A.cfg.outdir);
    gui_confirm(t, d, "Start test", test_confirmed, NULL);
}

static void on_arm(GtkWidget *w, gpointer u) {
    (void)w; (void)u;
    on_opt_changed(NULL, NULL);
    if (run_active()) return;
    char err[300];
    if (eas_config_validate(&A.cfg, false, err, sizeof(err)) < 0) { gui_info("Can't arm the run", err); return; }
    GString *g = g_string_new(NULL);
    char now[64];
    time_t tn = time(NULL);
    struct tm tm;
    plat_localtime(tn, &tm);
    strftime(now, sizeof(now), "%Y-%m-%d %H:%M:%S", &tm);
    g_string_append_printf(g, "Start: %s     Stop: %s\nThis computer's clock now: %s\n\n", A.cfg.start, A.cfg.stop, now);
    g_string_append_printf(g, "Segments %d s, ATSC 3.0 format %s\nOutput: %s\n\nTuners:\n", A.cfg.seg,
                           A.cfg.fmt3 == EAS_FMT_DBG ? "debug" : "ALP-PCAP", A.cfg.outdir);
    for (int i = 0; i < A.cfg.ntuners; i++)
        if (A.cfg.tuners[i].chan[0])
            g_string_append_printf(g, "   %s-%d (%s)  ->  %s  %s\n", A.cfg.tuners[i].devid, A.cfg.tuners[i].tuner,
                                   A.cfg.tuners[i].ip, A.cfg.tuners[i].chan, chan_type(A.cfg.tuners[i].chan));
    double need, freeg;
    eas_config_estimate(&A.cfg, false, &need, &freeg);
    if (freeg >= 0) g_string_append_printf(g, "\nDisk: needs up to ~%.1f GB, %.1f GB free%s\n", need, freeg, freeg < need ? "  <-- NOT ENOUGH" : "");
    if (A.pause_services && A.cfg.pause_units[0])
        g_string_append_printf(g, "\nPauses %s %d s before the start and restarts them after.\n", A.cfg.pause_units, A.cfg.pause_lead);
    else
        g_string_append_printf(g, "\n%s\n", free_note());
    g_string_append(g, "\nThe run happens in the background: you can close this window.\n"
#ifdef _WIN32
                       "Keep the PC on and stay signed in; it won't go to sleep during the run.\n"
#else
                       "Don't reboot or power off before it finishes.\n"
#endif
                    );
    gui_confirm("Arm the scheduled EAS capture?", g->str, "Arm", arm_confirmed, NULL);
    g_string_free(g, TRUE);
}

static void cancel_confirmed(gboolean yes, gpointer u) {
    (void)u;
    if (!yes) return;
    if (eas_cancel_running() == 0) gui_msg("Cancel sent - the run is closing its files%s.", A.pause_services ? " and restarting services" : "");
    else gui_msg("Nothing is running.");
}

static void on_cancel(GtkWidget *w, gpointer u) {
    (void)w; (void)u;
    eas_state_t st;
    eas_state_read(&st);
    if (!st.alive) { gui_msg("Nothing is running."); return; }
    gui_confirm(!strcmp(st.phase, "rendering") ? "Stop making reports?" : "Cancel this run?",
                A.pause_services ? "Paused services will be restarted." : NULL, "Cancel run", cancel_confirmed, NULL);
}

/* ------------------------------------------------------------------ */
/* Zips, reports, web                                                  */
/* ------------------------------------------------------------------ */
static void human(long long b, char *out, size_t n) {
    if (b >= 1024LL * 1024 * 1024) snprintf(out, n, "%.1f GB", b / 1073741824.0);
    else if (b >= 1024LL * 1024) snprintf(out, n, "%.1f MB", b / 1048576.0);
    else snprintf(out, n, "%lld KB", (b + 1023) / 1024);
}

static char zip_dir[1100];

static void full_confirmed(gboolean yes, gpointer u) {
    (void)u;
    if (!yes) { gui_msg("No zip made."); return; }
    char zp[1300], err[200];
    if (eas_zip_start(zip_dir, "full", zp, sizeof(zp), err, sizeof(err)) < 0) gui_msg("%s", err);
    else gui_msg("Making the full zip in the background...");
}

static void zip_choice(int r, gpointer u) {
    (void)u;
    if (r == 0) {
        char zp[1300], err[200];
        if (eas_zip_start(zip_dir, "reports", zp, sizeof(zp), err, sizeof(err)) < 0) gui_msg("%s", err);
        else gui_msg("Making the reports zip...");
    } else if (r == 1) {
        long long need = eas_dir_bytes(zip_dir, "full");
        double fb = plat_free_bytes(zip_dir);
        char a[32], b[32];
        human(need, a, sizeof(a));
        human(fb > 0 ? (long long)fb : 0, b, sizeof(b));
        if (fb >= 0 && fb < need + 512.0 * 1024 * 1024) {
            char d[300];
            snprintf(d, sizeof(d), "It needs %s more disk space and only %s is free.", a, b);
            gui_info("Not enough disk space for a full zip", d);
            return;
        }
        char d[400];
        snprintf(d, sizeof(d), "The full zip is %s: a second copy of every .pcap and .ts. "
                 "It uses that much more disk (%s free) and takes a long time to download.\n\n"
                 "Most people want the reports zip instead.", a, b);
        gui_confirm("CAUTION: the full zip is large", d, "Make full zip", full_confirmed, NULL);
    } else {
        gui_msg("No zip made. Use Zip results… later if you want one.");
    }
}

static void offer_zip(const char *rundir) {
    snprintf(zip_dir, sizeof(zip_dir), "%s", rundir);
    char a[32], b[32];
    human(eas_dir_bytes(rundir, "reports"), a, sizeof(a));
    human(eas_dir_bytes(rundir, "full"), b, sizeof(b));
    char l1[96], l2[96];
    snprintf(l1, sizeof(l1), "ATSC 3.0 reports + logs (%s)", a);
    snprintf(l2, sizeof(l2), "FULL test files, pcap + ts (%s - large!)", b);
    const char *buttons[] = { l1, l2, "No zip", NULL };
    gui_choose("Zip this run?", rundir, buttons, 2, 0, zip_choice, NULL);
}

static void on_zip(GtkWidget *w, gpointer u) {
    (void)w; (void)u;
    eas_state_t st;
    eas_state_read(&st);
    if (!st.present || st.alive || !st.outdir[0] || !plat_is_dir(st.outdir)) { gui_msg("Zips can be made once a run has finished."); return; }
    offer_zip(st.outdir);
}

static void on_open_report(GtkWidget *w, gpointer u) {
    (void)w; (void)u;
    eas_state_t st;
    eas_state_read(&st);
    if (st.summary[0] && plat_is_file(st.summary)) plat_open_uri(st.summary);
    else gui_msg("No summary report yet.");
}

static void on_open_folder(GtkWidget *w, gpointer u) {
    (void)w; (void)u;
    eas_state_t st;
    eas_state_read(&st);
    char d[1100];
    if (st.outdir[0] && plat_is_dir(st.outdir)) snprintf(d, sizeof(d), "%s", st.outdir);
    else plat_expand_home(A.cfg.outdir, d, sizeof(d));
    plat_mkdir_p(d);
    plat_open_uri(d);
}

static void on_web(GtkWidget *w, gpointer u) {
    (void)w; (void)u;
    if (eas_web_status(NULL, NULL, 0) > 0) { eas_web_stop(); gui_msg("Web server stopped."); return; }
    eas_state_t st;
    eas_state_read(&st);
    const char *sum = (st.summary[0] && plat_is_file(st.summary)) ? st.summary : "";
    char url[1200], err[300];
    if (eas_web_serve(A.cfg.outdir, sum, url, sizeof(url), err, sizeof(err)) == 0) gui_msg("On your network: %s", url);
    else gui_info("Web server", err);
}

static gboolean on_link(GtkLabel *l, const char *uri, gpointer u) {
    (void)l; (void)u;
    plat_open_uri(uri);
    return TRUE;
}

/* ------------------------------------------------------------------ */
/* Monitor (called every second)                                       */
/* ------------------------------------------------------------------ */
static void fmt_left(long secs, char *out, size_t n) {
    if (secs < 0) secs = 0;
    long d = secs / 86400, h = (secs / 3600) % 24, m = (secs / 60) % 60, s = secs % 60;
    if (d) snprintf(out, n, "%ldd %ldh %02ldm", d, h, m);
    else if (h) snprintf(out, n, "%ldh %02ldm %02lds", h, m, s);
    else snprintf(out, n, "%ldm %02lds", m, s);
}

static void tail_file(const char *path, int want, GString *out) {
    FILE *f = fopen(path, "rb");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    long from = sz > 16384 ? sz - 16384 : 0;
    fseek(f, from, SEEK_SET);
    char *buf = g_malloc(16385);
    size_t got = fread(buf, 1, 16384, f);
    fclose(f);
    buf[got] = '\0';
    char **lines = g_strsplit(buf, "\n", -1);
    int n = g_strv_length(lines);
    int start = n - want - 1;
    if (start < 0) start = 0;
    for (int i = start; i < n; i++) {
        if (!lines[i][0]) continue;
        g_string_append(out, strlen(lines[i]) > 24 ? lines[i] + 11 : lines[i]);
        g_string_append_c(out, '\n');
    }
    g_strfreev(lines);
    g_free(buf);
}

void eas_page_tick(void) {
    if (!A.m_runner) return;
    eas_state_t st;
    eas_state_read(&st);
    time_t now = time(NULL);
    char b[1400], left[48];

    /* estimate */
    double need, freeg;
    eas_config_estimate(&A.cfg, false, &need, &freeg);
    if (freeg >= 0) {
        snprintf(b, sizeof(b), "Scheduled run needs up to ~%.1f GB for %d tuner(s); %.1f GB free%s", need,
                 eas_config_active_count(&A.cfg), freeg, freeg < need ? "  - NOT ENOUGH" : "");
        gtk_label_set_text(GTK_LABEL(A.e_estimate), b);
        if (freeg < need) gtk_widget_add_css_class(A.e_estimate, "caution");
        else gtk_widget_remove_css_class(A.e_estimate, "caution");
    }

    if (!st.present || (!st.alive && !strcmp(st.phase, "starting"))) {
        gtk_label_set_text(GTK_LABEL(A.m_runner), "No run yet. Use Test run now, then Arm the real run.");
        return;
    }
    const char *mode = !strcmp(st.mode, "test") ? "Test" : "Scheduled";
    if (st.alive) {
        if (!strcmp(st.phase, "waiting") || !strcmp(st.phase, "pausing") || !strcmp(st.phase, "starting")) {
            fmt_left((long)(st.start - now), left, sizeof(left));
            snprintf(b, sizeof(b), "<b>%s run ARMED</b> - starts in %s", mode, left);
        } else if (!strcmp(st.phase, "recording")) {
            fmt_left((long)(st.stop - now), left, sizeof(left));
            snprintf(b, sizeof(b), "<b>%s run RECORDING</b> - %s left", mode, left);
        } else snprintf(b, sizeof(b), "<b>%s run %s</b>", mode, st.phase);
    } else {
        snprintf(b, sizeof(b), "Last %s run: <b>%s</b>", st.mode, st.phase);
    }
    gtk_label_set_markup(GTK_LABEL(A.m_runner), b);

    char a1[32] = "", a2[32] = "";
    struct tm tm;
    if (st.start) { plat_localtime(st.start, &tm); strftime(a1, sizeof(a1), "%Y-%m-%d %H:%M:%S", &tm); }
    if (st.stop) { plat_localtime(st.stop, &tm); strftime(a2, sizeof(a2), "%Y-%m-%d %H:%M:%S", &tm); }
    snprintf(b, sizeof(b), "%s  →  %s", a1, a2);
    gtk_label_set_text(GTK_LABEL(A.m_window), b);
    gtk_label_set_text(GTK_LABEL(A.m_out), st.outdir);
    gtk_label_set_text(GTK_LABEL(A.m_msg), st.message);

    if (st.web[0] && eas_web_status(NULL, NULL, 0) > 0) {
        char *e = g_markup_escape_text(st.web, -1);
        snprintf(b, sizeof(b), "<a href=\"%s\">%s</a>", e, e);
        g_free(e);
        gtk_label_set_markup(GTK_LABEL(A.m_web), b);
    } else {
        gtk_label_set_text(GTK_LABEL(A.m_web), eas_web_status(NULL, NULL, 0) > 0 ? "running" : "off");
    }
    gtk_button_set_label(GTK_BUTTON(A.b_web), eas_web_status(NULL, NULL, 0) > 0 ? "Web server off" : "Web server on");

    GString *g = g_string_new(NULL);
    if (st.nrows) g_string_append_printf(g, "%-14s %-14s %-11s %5s %9s  %s\n", "Tuner", "Channel", "State", "Segs", "MB", "Signal");
    for (int i = 0; i < st.nrows; i++) {
        char row[256];
        snprintf(row, sizeof(row), "%s", st.rows[i]);
        char *f[7] = { "", "", "", "", "", "", "" };
        int nf = 0;
        for (char *save = NULL, *t = strtok_r(row, "|", &save); t && nf < 7; t = strtok_r(NULL, "|", &save)) f[nf++] = t;
        g_string_append_printf(g, "%-14.14s %-14.14s %-11.11s %5s %9s  %s\n", f[0], f[1], f[2], f[3], f[4], f[5]);
        if (f[6][0]) g_string_append_printf(g, "    %s\n", f[6]);
    }
    gtk_label_set_text(GTK_LABEL(A.m_rows), g->str);
    g_string_free(g, TRUE);

    /* zips */
    gboolean finished = !st.alive && st.outdir[0] && (!strcmp(st.phase, "done") || !strcmp(st.phase, "cancelled"));
    g = g_string_new(NULL);
    if (finished) {
        const char *kinds[2] = { "reports", "full" };
        for (int k = 0; k < 2; k++) {
            char zp[1300];
            long long sz;
            int zs = eas_zip_status(st.outdir, kinds[k], zp, sizeof(zp), &sz);
            if (!zs) continue;
            char hs[32];
            human(sz, hs, sizeof(hs));
            const char *base = strrchr(zp, '/') ? strrchr(zp, '/') + 1 : zp;
            if (zs == 1) g_string_append_printf(g, "Zipping %s … %s so far\n", base, hs);
            else g_string_append_printf(g, "Zip ready (%s): %s\n", hs, zp);
        }
    }
    gtk_label_set_text(GTK_LABEL(A.m_zip), g->str);
    g_string_free(g, TRUE);

    /* log */
    g = g_string_new(NULL);
    char logp[1200];
    snprintf(logp, sizeof(logp), "%s/eas_capture.log", st.outdir);
    tail_file(logp, 14, g);
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(A.m_log)), g->str, -1);
    g_string_free(g, TRUE);

    gtk_widget_set_sensitive(A.b_cancel, st.alive);
    gtk_widget_set_sensitive(A.b_zip, finished);
    gtk_widget_set_sensitive(A.b_open, st.summary[0] && plat_is_file(st.summary));

    if (finished && strcmp(A.zip_offered_for, st.outdir)) {
        snprintf(A.zip_offered_for, sizeof(A.zip_offered_for), "%s", st.outdir);
        char zp[1300];
        long long sz;
        bool any = eas_zip_status(st.outdir, "reports", zp, sizeof(zp), &sz) || eas_zip_status(st.outdir, "full", zp, sizeof(zp), &sz);
        /* only offer for a run that finished while this window was open */
        if (!any && st.updated >= now - 120) offer_zip(st.outdir);
    }
}

/* ------------------------------------------------------------------ */
/* Page                                                                */
/* ------------------------------------------------------------------ */
static GtkWidget *section(const char *title) {
    GtkWidget *l = gtk_label_new(NULL);
    char m[128];
    snprintf(m, sizeof(m), "<b>%s</b>", title);
    gtk_label_set_markup(GTK_LABEL(l), m);
    gtk_label_set_xalign(GTK_LABEL(l), 0);
    gtk_widget_set_margin_top(l, 10);
    return l;
}

static GtkWidget *lab(const char *t) {
    GtkWidget *l = gtk_label_new(t);
    gtk_label_set_xalign(GTK_LABEL(l), 0);
    return l;
}

static GtkWidget *spin(int lo, int hi, int val) {
    GtkWidget *s = gtk_spin_button_new_with_range(lo, hi, 1);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(s), val);
    g_signal_connect(s, "value-changed", G_CALLBACK(on_opt_changed), NULL);
    return s;
}

GtkWidget *eas_page_new(void) {
    eas_config_load(&A.cfg);
    loading = TRUE;
    GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);

    /* ---- left: setup ---- */
    GtkWidget *left = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_set_margin_start(left, 12); gtk_widget_set_margin_end(left, 12);
    gtk_widget_set_margin_top(left, 6); gtk_widget_set_margin_bottom(left, 12);

    GtkWidget *hrow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_append(GTK_BOX(hrow), section("1. Pick a channel for each tuner"));
    GtkWidget *brn = gtk_button_new_with_label("Refresh");
    gtk_widget_set_tooltip_text(brn, "Update the \"Tuned to now\" column");
    gtk_widget_set_valign(brn, GTK_ALIGN_END);
    g_signal_connect(brn, "clicked", G_CALLBACK(on_refresh_now), NULL);
    gtk_box_append(GTK_BOX(hrow), brn);
    gtk_box_append(GTK_BOX(left), hrow);
    A.eas_tuner_grid = gtk_grid_new();
    gtk_grid_set_column_spacing(GTK_GRID(A.eas_tuner_grid), 10);
    gtk_grid_set_row_spacing(GTK_GRID(A.eas_tuner_grid), 4);
    gtk_box_append(GTK_BOX(left), A.eas_tuner_grid);

    gtk_box_append(GTK_BOX(left), section("2. Free your tuners"));
    if (A.pause_services) {
        GtkWidget *pg = gtk_grid_new();
        gtk_grid_set_column_spacing(GTK_GRID(pg), 8);
        gtk_grid_set_row_spacing(GTK_GRID(pg), 4);
        A.e_units = gtk_entry_new();
        gtk_editable_set_text(GTK_EDITABLE(A.e_units), A.cfg.pause_units);
        gtk_widget_set_hexpand(A.e_units, TRUE);
        g_signal_connect(A.e_units, "changed", G_CALLBACK(on_opt_changed), NULL);
        GtkWidget *bd = gtk_button_new_with_label("Detect");
        gtk_widget_set_tooltip_text(bd, "Find running services that use an HDHomeRun");
        g_signal_connect(bd, "clicked", G_CALLBACK(on_detect), NULL);
        A.e_host = gtk_entry_new();
        gtk_entry_set_placeholder_text(GTK_ENTRY(A.e_host), "this machine (or user@host over ssh)");
        gtk_editable_set_text(GTK_EDITABLE(A.e_host), A.cfg.pause_ssh);
        g_signal_connect(A.e_host, "changed", G_CALLBACK(on_opt_changed), NULL);
        A.e_lead = spin(0, 3600, A.cfg.pause_lead);
        gtk_grid_attach(GTK_GRID(pg), lab("Services to pause"), 0, 0, 1, 1);
        gtk_grid_attach(GTK_GRID(pg), A.e_units, 1, 0, 1, 1);
        gtk_grid_attach(GTK_GRID(pg), bd, 2, 0, 1, 1);
        gtk_grid_attach(GTK_GRID(pg), lab("On"), 0, 1, 1, 1);
        gtk_grid_attach(GTK_GRID(pg), A.e_host, 1, 1, 2, 1);
        gtk_grid_attach(GTK_GRID(pg), lab("Pause this long before (s)"), 0, 2, 1, 1);
        gtk_grid_attach(GTK_GRID(pg), A.e_lead, 1, 2, 1, 1);
        gtk_box_append(GTK_BOX(left), pg);
        GtkWidget *pl = lab("They're stopped before the run, their tuners are released, and they're restarted after.");
        gtk_label_set_wrap(GTK_LABEL(pl), TRUE);
        gtk_box_append(GTK_BOX(left), pl);
    } else {
        GtkWidget *n = gtk_label_new(free_note());
        gtk_label_set_wrap(GTK_LABEL(n), TRUE);
        gtk_label_set_xalign(GTK_LABEL(n), 0);
        gtk_widget_add_css_class(n, "note");
        gtk_box_append(GTK_BOX(left), n);
#ifndef _WIN32
        GtkWidget *pl = lab("(Start with --pause-services to have this program stop and restart services for you.)");
        gtk_label_set_wrap(GTK_LABEL(pl), TRUE);
        gtk_box_append(GTK_BOX(left), pl);
#endif
    }

    gtk_box_append(GTK_BOX(left), section("3. Schedule and options"));
    GtkWidget *og = gtk_grid_new();
    gtk_grid_set_column_spacing(GTK_GRID(og), 8);
    gtk_grid_set_row_spacing(GTK_GRID(og), 4);
    A.e_start = gtk_entry_new();
    gtk_editable_set_text(GTK_EDITABLE(A.e_start), A.cfg.start);
    g_signal_connect(A.e_start, "changed", G_CALLBACK(on_time_changed), GINT_TO_POINTER(0));
    A.e_stop = gtk_entry_new();
    gtk_editable_set_text(GTK_EDITABLE(A.e_stop), A.cfg.stop);
    g_signal_connect(A.e_stop, "changed", G_CALLBACK(on_time_changed), GINT_TO_POINTER(1));
    A.e_seg = spin(10, 3600, A.cfg.seg);
    const char *fmts[] = { "ALP-PCAP (best)", "Debug", NULL };
    A.e_fmt = gtk_drop_down_new_from_strings(fmts);
    gtk_drop_down_set_selected(GTK_DROP_DOWN(A.e_fmt), A.cfg.fmt3 == EAS_FMT_DBG ? 1 : 0);
    g_signal_connect(A.e_fmt, "notify::selected", G_CALLBACK(on_opt_changed), NULL);
    A.e_outdir = gtk_entry_new();
    gtk_editable_set_text(GTK_EDITABLE(A.e_outdir), A.cfg.outdir);
    gtk_widget_set_hexpand(A.e_outdir, TRUE);
    g_signal_connect(A.e_outdir, "changed", G_CALLBACK(on_opt_changed), NULL);
    GtkWidget *bb = gtk_button_new_with_label("Browse…");
    g_signal_connect(bb, "clicked", G_CALLBACK(on_browse), NULL);
    A.e_render = gtk_check_button_new_with_label("Make reports (RENDER) and the summary page afterwards");
    gtk_check_button_set_active(GTK_CHECK_BUTTON(A.e_render), A.cfg.auto_render);
    g_signal_connect(A.e_render, "toggled", G_CALLBACK(on_opt_changed), NULL);
    A.e_test_min = spin(1, 60, A.cfg.test_minutes);
    A.e_test_seg = spin(10, 600, A.cfg.test_seg);
    int r = 0;
    gtk_grid_attach(GTK_GRID(og), lab("Start (YYYY-MM-DD HH:MM)"), 0, r, 1, 1); gtk_grid_attach(GTK_GRID(og), A.e_start, 1, r++, 2, 1);
    gtk_grid_attach(GTK_GRID(og), lab("Stop"), 0, r, 1, 1); gtk_grid_attach(GTK_GRID(og), A.e_stop, 1, r++, 2, 1);
    gtk_grid_attach(GTK_GRID(og), lab("Segment length (s)"), 0, r, 1, 1); gtk_grid_attach(GTK_GRID(og), A.e_seg, 1, r++, 1, 1);
    gtk_grid_attach(GTK_GRID(og), lab("ATSC 3.0 format"), 0, r, 1, 1); gtk_grid_attach(GTK_GRID(og), A.e_fmt, 1, r++, 1, 1);
    gtk_grid_attach(GTK_GRID(og), lab("Output folder"), 0, r, 1, 1); gtk_grid_attach(GTK_GRID(og), A.e_outdir, 1, r, 1, 1);
    gtk_grid_attach(GTK_GRID(og), bb, 2, r++, 1, 1);
    gtk_grid_attach(GTK_GRID(og), A.e_render, 0, r++, 3, 1);
    gtk_grid_attach(GTK_GRID(og), lab("Test run length (min)"), 0, r, 1, 1); gtk_grid_attach(GTK_GRID(og), A.e_test_min, 1, r++, 1, 1);
    gtk_grid_attach(GTK_GRID(og), lab("Test segment length (s)"), 0, r, 1, 1); gtk_grid_attach(GTK_GRID(og), A.e_test_seg, 1, r++, 1, 1);
    gtk_box_append(GTK_BOX(left), og);
    GtkWidget *tl = lab("The nationwide test: Tue Nov 17 2026, 2:20 p.m. ET (1:20 CT, 12:20 MT, 11:20 PT). Times here are this computer's clock.");
    gtk_label_set_wrap(GTK_LABEL(tl), TRUE);
    gtk_box_append(GTK_BOX(left), tl);
    A.e_estimate = lab("");
    gtk_label_set_wrap(GTK_LABEL(A.e_estimate), TRUE);
    gtk_box_append(GTK_BOX(left), A.e_estimate);

    gtk_box_append(GTK_BOX(left), section("4. Test, then arm"));
    GtkWidget *brow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *bt = gtk_button_new_with_label("Test run now");
    gtk_widget_add_css_class(bt, "suggested-action");
    g_signal_connect(bt, "clicked", G_CALLBACK(on_test), NULL);
    GtkWidget *ba = gtk_button_new_with_label("Arm scheduled run…");
    g_signal_connect(ba, "clicked", G_CALLBACK(on_arm), NULL);
    gtk_box_append(GTK_BOX(brow), bt);
    gtk_box_append(GTK_BOX(brow), ba);
    gtk_box_append(GTK_BOX(left), brow);

    GtkWidget *lsw = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(lsw), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(lsw), left);
    gtk_paned_set_start_child(GTK_PANED(paned), lsw);

    /* ---- right: monitor ---- */
    GtkWidget *right = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_set_margin_start(right, 12); gtk_widget_set_margin_end(right, 12);
    gtk_widget_set_margin_top(right, 6); gtk_widget_set_margin_bottom(right, 12);
    gtk_box_append(GTK_BOX(right), section("Run"));
    A.m_runner = lab("");
    gtk_label_set_wrap(GTK_LABEL(A.m_runner), TRUE);
    gtk_box_append(GTK_BOX(right), A.m_runner);
    GtkWidget *mg = gtk_grid_new();
    gtk_grid_set_column_spacing(GTK_GRID(mg), 10);
    gtk_grid_set_row_spacing(GTK_GRID(mg), 3);
    A.m_window = lab("");
    A.m_out = lab("");
    gtk_label_set_selectable(GTK_LABEL(A.m_out), TRUE);
    gtk_label_set_wrap(GTK_LABEL(A.m_out), TRUE);
    gtk_label_set_wrap_mode(GTK_LABEL(A.m_out), PANGO_WRAP_CHAR);
    A.m_web = lab("off");
    gtk_label_set_wrap(GTK_LABEL(A.m_web), TRUE);
    gtk_label_set_wrap_mode(GTK_LABEL(A.m_web), PANGO_WRAP_CHAR);
    g_signal_connect(A.m_web, "activate-link", G_CALLBACK(on_link), NULL);
    A.m_msg = lab("");
    gtk_label_set_wrap(GTK_LABEL(A.m_msg), TRUE);
    gtk_label_set_wrap_mode(GTK_LABEL(A.m_msg), PANGO_WRAP_WORD_CHAR);
    gtk_label_set_selectable(GTK_LABEL(A.m_msg), TRUE);
    gtk_grid_attach(GTK_GRID(mg), lab("Window"), 0, 0, 1, 1); gtk_grid_attach(GTK_GRID(mg), A.m_window, 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(mg), lab("Output"), 0, 1, 1, 1); gtk_grid_attach(GTK_GRID(mg), A.m_out, 1, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(mg), lab("Report on the web"), 0, 2, 1, 1); gtk_grid_attach(GTK_GRID(mg), A.m_web, 1, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(mg), lab("Status"), 0, 3, 1, 1); gtk_grid_attach(GTK_GRID(mg), A.m_msg, 1, 3, 1, 1);
    gtk_box_append(GTK_BOX(right), mg);
    A.m_rows = lab("");
    gtk_widget_add_css_class(A.m_rows, "mono");
    gtk_label_set_selectable(GTK_LABEL(A.m_rows), TRUE);
    gtk_label_set_yalign(GTK_LABEL(A.m_rows), 0);
    GtkWidget *rsw = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(rsw), GTK_POLICY_AUTOMATIC, GTK_POLICY_NEVER);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(rsw), A.m_rows);
    gtk_box_append(GTK_BOX(right), rsw);
    A.m_zip = lab("");
    gtk_label_set_selectable(GTK_LABEL(A.m_zip), TRUE);
    gtk_label_set_wrap(GTK_LABEL(A.m_zip), TRUE);
    gtk_box_append(GTK_BOX(right), A.m_zip);

    GtkWidget *mb = gtk_flow_box_new();
    gtk_flow_box_set_selection_mode(GTK_FLOW_BOX(mb), GTK_SELECTION_NONE);
    gtk_flow_box_set_max_children_per_line(GTK_FLOW_BOX(mb), 5);
    gtk_flow_box_set_min_children_per_line(GTK_FLOW_BOX(mb), 1);
    A.b_cancel = gtk_button_new_with_label("Cancel run");
    g_signal_connect(A.b_cancel, "clicked", G_CALLBACK(on_cancel), NULL);
    A.b_zip = gtk_button_new_with_label("Zip results…");
    g_signal_connect(A.b_zip, "clicked", G_CALLBACK(on_zip), NULL);
    A.b_open = gtk_button_new_with_label("Open report");
    g_signal_connect(A.b_open, "clicked", G_CALLBACK(on_open_report), NULL);
    A.b_folder = gtk_button_new_with_label("Open folder");
    g_signal_connect(A.b_folder, "clicked", G_CALLBACK(on_open_folder), NULL);
    A.b_web = gtk_button_new_with_label("Web server on");
    gtk_widget_set_tooltip_text(A.b_web, "Share the results folder on your network (needs Python 3)");
    g_signal_connect(A.b_web, "clicked", G_CALLBACK(on_web), NULL);
    GtkWidget *mbs[] = { A.b_cancel, A.b_zip, A.b_open, A.b_folder, A.b_web };
    for (int i = 0; i < 5; i++) gtk_flow_box_append(GTK_FLOW_BOX(mb), mbs[i]);
    gtk_box_append(GTK_BOX(right), mb);
    GtkWidget *zc = lab("Full zips are a second copy of every recording (7–9 GB per station for the real run) - usually you want the reports zip.");
    gtk_label_set_wrap(GTK_LABEL(zc), TRUE);
    gtk_widget_add_css_class(zc, "dim-label");
    gtk_box_append(GTK_BOX(right), zc);

    gtk_box_append(GTK_BOX(right), section("Recent log"));
    A.m_log = gtk_text_view_new();
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(A.m_log), TRUE);
    gtk_text_view_set_editable(GTK_TEXT_VIEW(A.m_log), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(A.m_log), GTK_WRAP_CHAR);
    GtkWidget *logsw = gtk_scrolled_window_new();
    gtk_widget_set_vexpand(logsw, TRUE);
    gtk_widget_set_size_request(logsw, -1, 260);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(logsw), A.m_log);
    gtk_box_append(GTK_BOX(right), logsw);

    GtkWidget *rsw2 = gtk_scrolled_window_new();
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(rsw2), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(rsw2), right);
    gtk_paned_set_end_child(GTK_PANED(paned), rsw2);
    gtk_paned_set_position(GTK_PANED(paned), 660);
    gtk_paned_set_shrink_start_child(GTK_PANED(paned), FALSE);
    loading = FALSE;
    eas_page_rebuild_tuners();
    return paned;
}
