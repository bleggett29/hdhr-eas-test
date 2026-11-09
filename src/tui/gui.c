/*
 * gui.c - GTK4 GUI for HDHR EAS Test: main window, tuner status, and the
 * everyday tools of HDHomeRun TUI v0.9 (channel stepping, seek, tune, channel
 * map, PLPs, PLP details, 30-second captures, built-in viewer). The EAS screen is in
 * gui_eas.c. GPLv3.
 *
 * Built on HDHomeRun TUI v0.9 and RENDER v0.4 by RabbitEars.
 */
#include "gui.h"
#include <math.h>
#include "player.h"
#include "viewer.h"
#include "eas_capture.h"
#include "l1_detail_parser.h"

#include <ctype.h>
#include <stdarg.h>
#include <string.h>

#include "hdhomerun.h"
#include "hdhomerun_device.h"

App A;

/* ------------------------------------------------------------------ */
/* Small UI helpers                                                    */
/* ------------------------------------------------------------------ */
static void escape_closes(GtkWidget *win) {
    GtkEventController *sc = gtk_shortcut_controller_new();
    gtk_shortcut_controller_add_shortcut(GTK_SHORTCUT_CONTROLLER(sc),
        gtk_shortcut_new(gtk_keyval_trigger_new(GDK_KEY_Escape, 0), gtk_named_action_new("window.close")));
    gtk_widget_add_controller(win, sc);
}
void gui_msg(const char *fmt, ...) {
    char buf[600];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (A.msg) gtk_label_set_text(GTK_LABEL(A.msg), buf);
}

static gboolean idle_msg(gpointer data) {
    gui_msg("%s", (char *)data);
    g_free(data);
    return G_SOURCE_REMOVE;
}

void gui_post_msg(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char *s = g_strdup_vprintf(fmt, ap);
    va_end(ap);
    g_idle_add(idle_msg, s);
}

/* gui_choose(): a message with a row of buttons; cb gets the button index
 * (cancel_idx if the dialog is closed).  GTK 4.10+ uses GtkAlertDialog;
 * older GTK 4 (Debian 12 / Raspberry Pi OS bookworm ship 4.8) gets a small
 * hand-made modal window instead. */
typedef struct { void (*cb)(int, gpointer); gpointer data; int cancel; } ChooseCtx;

#if GTK_CHECK_VERSION(4, 10, 0)
static void choose_done(GObject *src, GAsyncResult *res, gpointer user) {
    ChooseCtx *c = user;
    GError *e = NULL;
    int r = gtk_alert_dialog_choose_finish(GTK_ALERT_DIALOG(src), res, &e);
    if (e) { r = c->cancel; g_error_free(e); }
    if (c->cb) c->cb(r, c->data);
    g_free(c);
}

void gui_choose(const char *title, const char *detail, const char *const *buttons,
                int cancel_idx, int default_idx, void (*cb)(int, gpointer), gpointer data) {
    GtkAlertDialog *d = gtk_alert_dialog_new("%s", title);
    if (detail) gtk_alert_dialog_set_detail(d, detail);
    gtk_alert_dialog_set_buttons(d, buttons);
    gtk_alert_dialog_set_cancel_button(d, cancel_idx);
    gtk_alert_dialog_set_default_button(d, default_idx);
    ChooseCtx *c = g_new0(ChooseCtx, 1);
    c->cb = cb; c->data = data; c->cancel = cancel_idx;
    gtk_alert_dialog_choose(d, GTK_WINDOW(A.win), NULL, choose_done, c);
    g_object_unref(d);
}
#else
typedef struct { ChooseCtx c; GtkWidget *win; gboolean done; } OldChoose;

static void old_choose_finish(OldChoose *o, int idx) {
    if (o->done) return;
    o->done = TRUE;
    if (o->c.cb) o->c.cb(idx, o->c.data);
    gtk_window_destroy(GTK_WINDOW(o->win));
}
static void old_choose_clicked(GtkWidget *b, gpointer u) {
    old_choose_finish(u, GPOINTER_TO_INT(g_object_get_data(G_OBJECT(b), "idx")));
}
static gboolean old_choose_close(GtkWindow *w, gpointer u) {
    (void)w;
    OldChoose *o = u;
    if (!o->done) { o->done = TRUE; if (o->c.cb) o->c.cb(o->c.cancel, o->c.data); }
    return FALSE;
}

void gui_choose(const char *title, const char *detail, const char *const *buttons,
                int cancel_idx, int default_idx, void (*cb)(int, gpointer), gpointer data) {
    OldChoose *o = g_new0(OldChoose, 1);
    o->c.cb = cb; o->c.data = data; o->c.cancel = cancel_idx;
    o->win = gtk_window_new();
    g_object_set_data_full(G_OBJECT(o->win), "ctx", o, g_free);
    gtk_window_set_title(GTK_WINDOW(o->win), title);
    gtk_window_set_transient_for(GTK_WINDOW(o->win), GTK_WINDOW(A.win));
    gtk_window_set_modal(GTK_WINDOW(o->win), TRUE);
    gtk_window_set_default_size(GTK_WINDOW(o->win), 420, -1);
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_widget_set_margin_start(box, 16); gtk_widget_set_margin_end(box, 16);
    gtk_widget_set_margin_top(box, 16); gtk_widget_set_margin_bottom(box, 16);
    GtkWidget *t = gtk_label_new(NULL);
    char *mk = g_markup_printf_escaped("<b>%s</b>", title);
    gtk_label_set_markup(GTK_LABEL(t), mk);
    g_free(mk);
    gtk_label_set_wrap(GTK_LABEL(t), TRUE);
    gtk_box_append(GTK_BOX(box), t);
    if (detail) {
        GtkWidget *dl = gtk_label_new(detail);
        gtk_label_set_wrap(GTK_LABEL(dl), TRUE);
        gtk_label_set_wrap_mode(GTK_LABEL(dl), PANGO_WRAP_WORD_CHAR);
        gtk_label_set_max_width_chars(GTK_LABEL(dl), 60);
        gtk_box_append(GTK_BOX(box), dl);
    }
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(row, GTK_ALIGN_END);
    GtkWidget *defb = NULL;
    for (int i = 0; buttons[i]; i++) {
        GtkWidget *b = gtk_button_new_with_label(buttons[i]);
        g_object_set_data(G_OBJECT(b), "idx", GINT_TO_POINTER(i));
        g_signal_connect(b, "clicked", G_CALLBACK(old_choose_clicked), o);
        gtk_box_append(GTK_BOX(row), b);
        if (i == default_idx) defb = b;
    }
    gtk_box_append(GTK_BOX(box), row);
    gtk_window_set_child(GTK_WINDOW(o->win), box);
    g_signal_connect(o->win, "close-request", G_CALLBACK(old_choose_close), o);
    GtkEventController *sc = gtk_shortcut_controller_new();
    gtk_shortcut_controller_add_shortcut(GTK_SHORTCUT_CONTROLLER(sc),
        gtk_shortcut_new(gtk_keyval_trigger_new(GDK_KEY_Escape, 0),
                         gtk_named_action_new("window.close")));
    gtk_widget_add_controller(o->win, sc);
    if (defb) gtk_window_set_default_widget(GTK_WINDOW(o->win), defb);
    gtk_window_present(GTK_WINDOW(o->win));
    if (defb) gtk_widget_grab_focus(defb);
}
#endif

typedef struct { void (*cb)(gboolean, gpointer); gpointer data; } ConfirmCtx;

static void confirm_done(int r, gpointer user) {
    ConfirmCtx *c = user;
    if (c->cb) c->cb(r == 1, c->data);
    g_free(c);
}

void gui_confirm(const char *title, const char *detail, const char *yes,
                 void (*cb)(gboolean, gpointer), gpointer data) {
    const char *buttons[] = { "Cancel", yes ? yes : "OK", NULL };
    ConfirmCtx *c = g_new0(ConfirmCtx, 1);
    c->cb = cb;
    c->data = data;
    gui_choose(title, detail, buttons, 0, 1, confirm_done, c);
}

void gui_info(const char *title, const char *detail) {
    const char *buttons[] = { "OK", NULL };
    gui_choose(title, detail, buttons, 0, 0, NULL, NULL);
}

typedef struct {
    GtkWidget *win, *entry;
    void (*cb)(const char *, gpointer);
    gpointer data;
} AskCtx;

static void ask_ok(GtkWidget *w, gpointer user) {
    (void)w;
    AskCtx *c = user;
    char *t = g_strdup(gtk_editable_get_text(GTK_EDITABLE(c->entry)));
    void (*cb)(const char *, gpointer) = c->cb;
    gpointer data = c->data;
    gtk_window_destroy(GTK_WINDOW(c->win));
    if (cb) cb(t, data);
    g_free(t);
}

static void ask_cancel(GtkWidget *w, gpointer user) {
    (void)w;
    AskCtx *c = user;
    gtk_window_destroy(GTK_WINDOW(c->win));
}

void gui_ask_text(const char *title, const char *prompt, const char *initial,
                  void (*cb)(const char *, gpointer), gpointer data) {
    AskCtx *c = g_new0(AskCtx, 1);
    c->cb = cb;
    c->data = data;
    c->win = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(c->win), title);
    gtk_window_set_transient_for(GTK_WINDOW(c->win), GTK_WINDOW(A.win));
    gtk_window_set_modal(GTK_WINDOW(c->win), TRUE);
    gtk_window_set_default_size(GTK_WINDOW(c->win), 420, -1);
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_start(box, 14); gtk_widget_set_margin_end(box, 14);
    gtk_widget_set_margin_top(box, 14); gtk_widget_set_margin_bottom(box, 14);
    GtkWidget *lab = gtk_label_new(prompt);
    gtk_label_set_wrap(GTK_LABEL(lab), TRUE);
    gtk_label_set_xalign(GTK_LABEL(lab), 0);
    c->entry = gtk_entry_new();
    if (initial) gtk_editable_set_text(GTK_EDITABLE(c->entry), initial);
    g_signal_connect(c->entry, "activate", G_CALLBACK(ask_ok), c);
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(row, GTK_ALIGN_END);
    GtkWidget *bc = gtk_button_new_with_label("Cancel");
    GtkWidget *bo = gtk_button_new_with_label("OK");
    gtk_widget_add_css_class(bo, "suggested-action");
    g_signal_connect(bc, "clicked", G_CALLBACK(ask_cancel), c);
    g_signal_connect(bo, "clicked", G_CALLBACK(ask_ok), c);
    gtk_box_append(GTK_BOX(row), bc);
    gtk_box_append(GTK_BOX(row), bo);
    gtk_box_append(GTK_BOX(box), lab);
    gtk_box_append(GTK_BOX(box), c->entry);
    gtk_box_append(GTK_BOX(box), row);
    gtk_window_set_child(GTK_WINDOW(c->win), box);
    g_object_set_data_full(G_OBJECT(c->win), "ctx", c, g_free);
    escape_closes(c->win);
    gtk_window_present(GTK_WINDOW(c->win));
}

/* A list to pick from (programs, channel maps). */
typedef struct {
    GtkWidget *win, *list;
    void (*cb)(int index, gpointer data);
    gpointer data;
} PickCtx;

static void pick_ok(GtkWidget *w, gpointer user) {
    (void)w;
    PickCtx *c = user;
    GtkListBoxRow *r = gtk_list_box_get_selected_row(GTK_LIST_BOX(c->list));
    int idx = r ? gtk_list_box_row_get_index(r) : -1;
    void (*cb)(int, gpointer) = c->cb;
    gpointer data = c->data;
    gtk_window_destroy(GTK_WINDOW(c->win));
    if (idx >= 0 && cb) cb(idx, data);
}

static void pick_activated(GtkListBox *b, GtkListBoxRow *r, gpointer user) { (void)b; (void)r; pick_ok(NULL, user); }

static void pick_cancel(GtkWidget *w, gpointer user) {
    (void)w;
    PickCtx *c = user;
    gtk_window_destroy(GTK_WINDOW(c->win));
}

static void gui_pick(const char *title, const char *prompt, const char *const *items, int n, int preselect,
                     void (*cb)(int, gpointer), gpointer data) {
    PickCtx *c = g_new0(PickCtx, 1);
    c->cb = cb;
    c->data = data;
    c->win = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(c->win), title);
    gtk_window_set_transient_for(GTK_WINDOW(c->win), GTK_WINDOW(A.win));
    gtk_window_set_modal(GTK_WINDOW(c->win), TRUE);
    gtk_window_set_default_size(GTK_WINDOW(c->win), 520, 380);
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_start(box, 12); gtk_widget_set_margin_end(box, 12);
    gtk_widget_set_margin_top(box, 12); gtk_widget_set_margin_bottom(box, 12);
    GtkWidget *lab = gtk_label_new(prompt);
    gtk_label_set_xalign(GTK_LABEL(lab), 0);
    c->list = gtk_list_box_new();
    for (int i = 0; i < n; i++) {
        GtkWidget *l = gtk_label_new(items[i]);
        gtk_label_set_xalign(GTK_LABEL(l), 0);
        gtk_widget_set_margin_start(l, 6);
        gtk_widget_set_margin_top(l, 3); gtk_widget_set_margin_bottom(l, 3);
        gtk_list_box_append(GTK_LIST_BOX(c->list), l);
    }
    if (preselect >= 0 && preselect < n)
        gtk_list_box_select_row(GTK_LIST_BOX(c->list), gtk_list_box_get_row_at_index(GTK_LIST_BOX(c->list), preselect));
    g_signal_connect(c->list, "row-activated", G_CALLBACK(pick_activated), c);
    GtkWidget *sw = gtk_scrolled_window_new();
    gtk_widget_set_vexpand(sw, TRUE);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(sw), c->list);
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(row, GTK_ALIGN_END);
    GtkWidget *bc = gtk_button_new_with_label("Cancel");
    GtkWidget *bo = gtk_button_new_with_label("OK");
    gtk_widget_add_css_class(bo, "suggested-action");
    g_signal_connect(bc, "clicked", G_CALLBACK(pick_cancel), c);
    g_signal_connect(bo, "clicked", G_CALLBACK(pick_ok), c);
    gtk_box_append(GTK_BOX(row), bc);
    gtk_box_append(GTK_BOX(row), bo);
    gtk_box_append(GTK_BOX(box), lab);
    gtk_box_append(GTK_BOX(box), sw);
    gtk_box_append(GTK_BOX(box), row);
    gtk_window_set_child(GTK_WINDOW(c->win), box);
    g_object_set_data_full(G_OBJECT(c->win), "ctx", c, g_free);
    escape_closes(c->win);
    gtk_window_present(GTK_WINDOW(c->win));
}

const char *gui_captures_dir(void) {
    static char d[1024];
    if (!d[0]) plat_expand_home("~/hdhr_captures", d, sizeof(d));
    return d;
}

static hdhr_tuner_t *cur_tuner(void) {
    return (A.sel >= 0 && A.sel < A.ntuners) ? &A.tuners[A.sel] : NULL;
}

static struct hdhomerun_device_t *open_tuner(const hdhr_tuner_t *t) {
    struct hdhomerun_device_t *hd = hdhomerun_device_create_from_str(t->ip, NULL);
    if (hd) hdhomerun_device_set_tuner(hd, t->tuner);
    return hd;
}

/* ------------------------------------------------------------------ */
/* Background work                                                     */
/* ------------------------------------------------------------------ */
typedef void (*WorkFn)(gpointer data);
typedef struct { WorkFn fn; gpointer data; } Work;

static gboolean idle_done(gpointer data) {
    (void)data;
    A.busy = FALSE;
    gtk_widget_set_sensitive(A.action_box, TRUE);
    g_mutex_lock(&A.lock);
    A.poke = TRUE;
    g_mutex_unlock(&A.lock);
    return G_SOURCE_REMOVE;
}

static gpointer work_thread(gpointer p) {
    Work *w = p;
    w->fn(w->data);
    g_free(w);
    g_idle_add(idle_done, NULL);
    return NULL;
}

/* Runs fn(data) off the UI thread; device calls can take a few seconds. */
static gboolean run_bg(WorkFn fn, gpointer data) {
    if (A.busy) { gui_msg("Busy - wait for the current action to finish."); return FALSE; }
    A.busy = TRUE;
    gtk_widget_set_sensitive(A.action_box, FALSE);
    Work *w = g_new0(Work, 1);
    w->fn = fn;
    w->data = data;
    g_thread_unref(g_thread_new("work", work_thread, w));
    return TRUE;
}

/* ------------------------------------------------------------------ */
/* Status poller                                                       */
/* ------------------------------------------------------------------ */
static void set_level(int i, int pct, long db, const char *unit) {
    if (pct < 0) pct = 0;
    if (pct > 100) pct = 100;
    gtk_level_bar_set_value(GTK_LEVEL_BAR(A.lvl[i]), pct);
    char t[64];
    if (db != -999) snprintf(t, sizeof(t), "%3d%%   %ld %s", pct, db, unit);
    else snprintf(t, sizeof(t), "%3d%%", pct);
    gtk_label_set_text(GTK_LABEL(A.lvl_txt[i]), t);
}

static gboolean idle_status(gpointer data) {
    (void)data;
    hdhr_status_t st;
    int for_idx;
    g_mutex_lock(&A.lock);
    st = A.last;
    for_idx = A.last_for;
    g_mutex_unlock(&A.lock);
    hdhr_tuner_t *t = cur_tuner();
    if (!t || for_idx != A.sel) return G_SOURCE_REMOVE;
    char title[160];
    snprintf(title, sizeof(title), "Tuner %08X-%d  (%s)", t->device_id, t->tuner, t->ip);
    gtk_label_set_text(GTK_LABEL(A.st_title), title);
    if (!st.ok) {
        gtk_label_set_text(GTK_LABEL(A.st_channel), "-");
        gtk_label_set_text(GTK_LABEL(A.st_lock), "no answer from the tuner");
        return G_SOURCE_REMOVE;
    }
    gtk_label_set_text(GTK_LABEL(A.st_channel), st.channel_disp);
    gtk_label_set_text(GTK_LABEL(A.st_lock), st.lock_disp);
    char b[256];
    if (st.id >= 0) snprintf(b, sizeof(b), "%s: %ld (0x%lX)", st.id_label, st.id, st.id);
    else b[0] = '\0';
    gtk_label_set_text(GTK_LABEL(A.st_id), b);
    if (st.vchannel[0] && strcmp(st.vchannel, "none")) snprintf(b, sizeof(b), "%s  %s", st.vchannel, strcmp(st.vname, "none") ? st.vname : "");
    else b[0] = '\0';
    gtk_label_set_text(GTK_LABEL(A.st_vch), b);
    set_level(0, st.ss, st.ss_db, "dBm");
    set_level(1, st.snq, st.snq_db, "dB");
    set_level(2, st.seq, -999, "");
    snprintf(b, sizeof(b), "%.3f Mbps", st.mbps);
    gtk_label_set_text(GTK_LABEL(A.st_rate), b);
    gtk_label_set_text(GTK_LABEL(A.st_target), st.target[0] ? st.target : "none");

    GString *g = g_string_new(NULL);
    for (int i = 0; i < st.nprog; i++) {
        char *e = g_markup_escape_text(st.progs[i], -1);
        if (strstr(st.progs[i], "(encrypted)")) g_string_append_printf(g, "<span foreground='#c01c28'>%s</span>\n", e);
        else g_string_append_printf(g, "%s\n", e);
        g_free(e);
    }
    gtk_label_set_markup(GTK_LABEL(A.st_progs), g->len ? g->str : "<i>none</i>");
    g_string_free(g, TRUE);
    g = g_string_new(NULL);
    for (int i = 0; i < st.nplp; i++) {
        char *e = g_markup_escape_text(st.plps[i], -1);
        const char *col = strstr(st.plps[i], "lock=1") ? "#26a269" : strstr(st.plps[i], "lock=0") ? "#c01c28" : NULL;
        if (col) g_string_append_printf(g, "<span foreground='%s'>%s</span>\n", col, e);
        else g_string_append_printf(g, "%s\n", e);
        g_free(e);
    }
    gtk_label_set_markup(GTK_LABEL(A.st_plps), g->len ? g->str : "<i>-</i>");
    g_string_free(g, TRUE);
    return G_SOURCE_REMOVE;
}

static gpointer poller_thread(gpointer p) {
    (void)p;
    struct hdhomerun_device_t *hd = NULL;
    char hd_ip[64] = "";
    for (;;) {
        g_mutex_lock(&A.lock);
        gboolean quit = A.quit;
        int sel = A.sel;
        hdhr_tuner_t t;
        bool have = sel >= 0 && sel < A.ntuners;
        if (have) t = A.tuners[sel];
        A.poke = FALSE;
        g_mutex_unlock(&A.lock);
        if (quit) break;
        if (have) {
            if (!hd || strcmp(hd_ip, t.ip)) {
                if (hd) hdhomerun_device_destroy(hd);
                hd = hdhomerun_device_create_from_str(t.ip, NULL);
                snprintf(hd_ip, sizeof(hd_ip), "%s", t.ip);
            }
            hdhr_status_t st;
            memset(&st, 0, sizeof(st));
            if (hd && hdhomerun_device_set_tuner(hd, t.tuner) > 0) hdhr_get_status(hd, &st);
            g_mutex_lock(&A.lock);
            A.last = st;
            A.last_for = sel;
            g_mutex_unlock(&A.lock);
            g_idle_add(idle_status, NULL);
        }
        for (int i = 0; i < 10; i++) {
            g_usleep(100000);
            g_mutex_lock(&A.lock);
            gboolean wake = A.poke || A.quit;
            g_mutex_unlock(&A.lock);
            if (wake) break;
        }
    }
    if (hd) hdhomerun_device_destroy(hd);
    return NULL;
}

static void poke(void) {
    g_mutex_lock(&A.lock);
    A.poke = TRUE;
    g_mutex_unlock(&A.lock);
}

/* ------------------------------------------------------------------ */
/* Tuner list                                                          */
/* ------------------------------------------------------------------ */
static void on_tuner_selected(GtkListBox *box, GtkListBoxRow *row, gpointer u) {
    (void)box; (void)u;
    g_mutex_lock(&A.lock);
    A.sel = row ? gtk_list_box_row_get_index(row) : -1;
    g_mutex_unlock(&A.lock);
    poke();
}

static void fill_tuner_list(void) {
    GtkWidget *child;
    while ((child = gtk_widget_get_first_child(A.tuner_list))) gtk_list_box_remove(GTK_LIST_BOX(A.tuner_list), child);
    for (int i = 0; i < A.ntuners; i++) {
        char t[160];
        snprintf(t, sizeof(t), "<b>%08X-%d</b>\n<small>%s</small>", A.tuners[i].device_id, A.tuners[i].tuner, A.tuners[i].ip);
        GtkWidget *l = gtk_label_new(NULL);
        gtk_label_set_markup(GTK_LABEL(l), t);
        gtk_label_set_xalign(GTK_LABEL(l), 0);
        gtk_widget_set_margin_start(l, 8); gtk_widget_set_margin_end(l, 8);
        gtk_widget_set_margin_top(l, 4); gtk_widget_set_margin_bottom(l, 4);
        gtk_list_box_append(GTK_LIST_BOX(A.tuner_list), l);
    }
    if (A.ntuners) gtk_list_box_select_row(GTK_LIST_BOX(A.tuner_list), gtk_list_box_get_row_at_index(GTK_LIST_BOX(A.tuner_list), 0));
    eas_page_rebuild_tuners();
}

typedef struct { hdhr_tuner_t list[HDHR_MAX_TUNERS]; int n; char ip[64]; } DiscCtx;

static gboolean idle_disc(gpointer p) {
    DiscCtx *d = p;
    g_mutex_lock(&A.lock);
    memcpy(A.tuners, d->list, sizeof(A.tuners));
    A.ntuners = d->n;
    A.sel = d->n ? 0 : -1;
    g_mutex_unlock(&A.lock);
    fill_tuner_list();
    gui_msg(d->n ? "Found %d tuner(s)." : "No HDHomeRun tuners found. Try Add device by IP.", d->n);
    g_free(d);
    return G_SOURCE_REMOVE;
}

static void work_discover(gpointer p) {
    DiscCtx *d = p;
    d->n = hdhr_discover(d->list, HDHR_MAX_TUNERS);
    if (d->ip[0]) hdhr_add_by_ip(d->ip, d->list, &d->n, HDHR_MAX_TUNERS);
    g_idle_add(idle_disc, d);
}

static void on_refresh(GtkWidget *w, gpointer u) {
    (void)w; (void)u;
    DiscCtx *d = g_new0(DiscCtx, 1);
    snprintf(d->ip, sizeof(d->ip), "%s", A.initial_ip);
    gui_msg("Looking for HDHomeRun devices...");
    if (!run_bg(work_discover, d)) g_free(d);
}

static void work_add_ip(gpointer p) {
    DiscCtx *d = p;
    int before = d->n;
    hdhr_add_by_ip(d->ip, d->list, &d->n, HDHR_MAX_TUNERS);
    if (d->n == before) gui_post_msg("No HDHomeRun answered at %s (or it's already listed).", d->ip);
    g_idle_add(idle_disc, d);
}

static void add_ip_cb2(const char *text, gpointer u) {
    (void)u;
    if (!text || !*text) return;
    DiscCtx *d = g_new0(DiscCtx, 1);
    memcpy(d->list, A.tuners, sizeof(d->list));
    d->n = A.ntuners;
    snprintf(d->ip, sizeof(d->ip), "%s", text);
    gui_msg("Adding %s ...", text);
    if (!run_bg(work_add_ip, d)) g_free(d);
}

static void on_add_ip(GtkWidget *w, gpointer u) {
    (void)w; (void)u;
    gui_ask_text("Add device", "HDHomeRun IP address (for devices discovery can't find):", "", add_ip_cb2, NULL);
}

/* ------------------------------------------------------------------ */
/* Tuning actions                                                      */
/* ------------------------------------------------------------------ */
typedef struct { hdhr_tuner_t t; int dir; char text[128]; } ActCtx;

static ActCtx *act_new(void) {
    hdhr_tuner_t *t = cur_tuner();
    if (!t) { gui_msg("Pick a tuner first."); return NULL; }
    ActCtx *a = g_new0(ActCtx, 1);
    a->t = *t;
    return a;
}

static void work_step(gpointer p) {
    ActCtx *a = p;
    struct hdhomerun_device_t *hd = open_tuner(&a->t);
    int ch = hd ? hdhr_step_channel(hd, a->dir) : -1;
    if (hd) hdhomerun_device_destroy(hd);
    if (ch > 0) gui_post_msg("Tuned to RF %d.", ch);
    else gui_post_msg("Couldn't change channel.");
    g_free(a);
}

static void on_step(GtkWidget *w, gpointer dir) {
    (void)w;
    ActCtx *a = act_new();
    if (!a) return;
    a->dir = GPOINTER_TO_INT(dir);
    if (!run_bg(work_step, a)) g_free(a);
}

static bool seek_progress(unsigned ch, double left, void *u) {
    (void)u;
    gui_post_msg("Seeking... RF %u (%.1fs)", ch, left);
    return !A.seek_cancel;
}

static gboolean idle_seek_end(gpointer p) { (void)p; gtk_widget_set_visible(A.btn_seek_stop, FALSE); return G_SOURCE_REMOVE; }

static void work_seek(gpointer p) {
    ActCtx *a = p;
    struct hdhomerun_device_t *hd = open_tuner(&a->t);
    unsigned ch = hd ? hdhr_seek(hd, a->dir, seek_progress, NULL) : 0;
    if (hd) hdhomerun_device_destroy(hd);
    if (A.seek_cancel) gui_post_msg("Seek stopped.");
    else if (ch) gui_post_msg("Found a signal on RF %u.", ch);
    else gui_post_msg("No other channel with a signal.");
    g_idle_add(idle_seek_end, NULL);
    g_free(a);
}

static void on_seek(GtkWidget *w, gpointer dir) {
    (void)w;
    ActCtx *a = act_new();
    if (!a) return;
    a->dir = GPOINTER_TO_INT(dir);
    A.seek_cancel = FALSE;
    if (run_bg(work_seek, a)) gtk_widget_set_visible(A.btn_seek_stop, TRUE);
    else g_free(a);
}

static void on_seek_stop(GtkWidget *w, gpointer u) { (void)w; (void)u; A.seek_cancel = TRUE; }

static void work_tune(gpointer p) {
    ActCtx *a = p;
    struct hdhomerun_device_t *hd = open_tuner(&a->t);
    int r = hd ? hdhr_tune(hd, a->text) : -1;
    if (hd) hdhomerun_device_destroy(hd);
    gui_post_msg(r == 0 ? "Tuned to %s." : "The tuner refused %s.", a->text);
    g_free(a);
}

static gboolean idle_play_changed(gpointer p);
static gboolean watching(void);
static void stop_watching_now(const hdhr_tuner_t *t);

/* Release: clear the tuner's lock, stream target and channel so anything
 * (this program, the EAS run, RabbitEars bandscan) can use it again. */
static void work_release(gpointer p) {
    ActCtx *a = p;
    int idx = -1;
    for (int i = 0; i < A.ntuners; i++)
        if (A.tuners[i].device_id == a->t.device_id && A.tuners[i].tuner == a->t.tuner &&
            !strcmp(A.tuners[i].ip, a->t.ip)) { idx = i; break; }
    if (watching() && idx >= 0 && A.play_tuner == idx) {     /* we're watching it */
        stop_watching_now(NULL);
        g_idle_add(idle_play_changed, NULL);
    }
    char msg[200];
    eas_release_tuner(a->t.ip, a->t.tuner, msg, sizeof(msg));
    gui_post_msg("%s", msg);
    g_mutex_lock(&A.lock);
    A.poke = TRUE;
    g_mutex_unlock(&A.lock);
    g_free(a);
}

static void release_confirmed(gboolean yes, gpointer p) {
    ActCtx *a = p;
    if (!yes || !run_bg(work_release, a)) g_free(a);
}

static void on_release(GtkWidget *w, gpointer u) {
    (void)w; (void)u;
    ActCtx *a = act_new();
    if (!a) return;
    char title[96];
    snprintf(title, sizeof(title), "Release tuner %08X-%d?", (unsigned)a->t.device_id, a->t.tuner);
    gui_confirm(title,
                "This frees the tuner: it clears its lock, stops its stream and sets its channel to none. "
                "Anything using it - live viewing, a capture, RabbitEars bandscan, a DVR - loses it.",
                "Release", release_confirmed, a);
}

static void tune_cb(const char *text, gpointer u) {
    (void)u;
    if (!text || !*text) return;
    if (!strcmp(text, "0") || !g_ascii_strcasecmp(text, "none")) {   /* 0 = release */
        ActCtx *r = act_new();
        if (r && !run_bg(work_release, r)) g_free(r);
        return;
    }
    ActCtx *a = act_new();
    if (!a) return;
    snprintf(a->text, sizeof(a->text), "%s", text);
    if (!run_bg(work_tune, a)) g_free(a);
}

static void on_tune(GtkWidget *w, gpointer u) {
    (void)w; (void)u;
    if (!cur_tuner()) { gui_msg("Pick a tuner first."); return; }
    gui_ask_text("Tune", "Channel (RF number) or frequency in Hz.  0 = release the tuner:", "", tune_cb, NULL);
}

static void work_plps(gpointer p) {
    ActCtx *a = p;
    struct hdhomerun_device_t *hd = open_tuner(&a->t);
    char err[200] = "";
    int r = hd ? hdhr_set_plps(hd, a->text, err, sizeof(err)) : -1;
    if (hd) hdhomerun_device_destroy(hd);
    if (r == 0) gui_post_msg("PLPs set.");
    else gui_post_msg("%s", err[0] ? err : "Couldn't set PLPs.");
    g_free(a);
}

static void plps_cb(const char *text, gpointer u) {
    (void)u;
    ActCtx *a = act_new();
    if (!a) return;
    snprintf(a->text, sizeof(a->text), "%s", text ? text : "");
    if (!run_bg(work_plps, a)) g_free(a);
}

static void on_plps(GtkWidget *w, gpointer u) {
    (void)w; (void)u;
    if (!cur_tuner()) { gui_msg("Pick a tuner first."); return; }
    gui_ask_text("ATSC 3.0 PLPs", "PLPs to receive, e.g. 0,1 (leave empty for all):", "", plps_cb, NULL);
}

/* Channel map: read maps in the background, pick in the UI, set in the background */
typedef struct { hdhr_tuner_t t; char maps[HDHR_MAX_MAPS][32]; int n; char cur[32]; int choice; } MapCtx;

static void work_set_map(gpointer p) {
    MapCtx *m = p;
    struct hdhomerun_device_t *hd = open_tuner(&m->t);
    int r = hd ? hdhr_set_channel_map(hd, m->maps[m->choice]) : -1;
    if (hd) hdhomerun_device_destroy(hd);
    gui_post_msg(r == 0 ? "Channel map set to %s." : "Couldn't set channel map %s.", m->maps[m->choice]);
    g_free(m);
}

static void map_picked(int idx, gpointer p) {
    MapCtx *m = p;
    m->choice = idx;
    if (!run_bg(work_set_map, m)) g_free(m);
}

static gboolean idle_map_list(gpointer p) {
    MapCtx *m = p;
    if (!m->n) { gui_msg("This device didn't list any channel maps."); g_free(m); return G_SOURCE_REMOVE; }
    const char *items[HDHR_MAX_MAPS];
    int pre = -1;
    for (int i = 0; i < m->n; i++) { items[i] = m->maps[i]; if (!strcmp(m->maps[i], m->cur)) pre = i; }
    char prompt[96];
    snprintf(prompt, sizeof(prompt), "Current map: %s", m->cur[0] ? m->cur : "?");
    gui_pick("Channel map", prompt, items, m->n, pre, map_picked, m);
    return G_SOURCE_REMOVE;
}

static void work_get_maps(gpointer p) {
    MapCtx *m = p;
    struct hdhomerun_device_t *hd = open_tuner(&m->t);
    if (hd) { m->n = hdhr_channel_maps(hd, m->maps, HDHR_MAX_MAPS, m->cur, sizeof(m->cur)); hdhomerun_device_destroy(hd); }
    g_idle_add(idle_map_list, m);
}

static void on_map(GtkWidget *w, gpointer u) {
    (void)w; (void)u;
    hdhr_tuner_t *t = cur_tuner();
    if (!t) { gui_msg("Pick a tuner first."); return; }
    MapCtx *m = g_new0(MapCtx, 1);
    m->t = *t;
    if (!run_bg(work_get_maps, m)) g_free(m);
}

/* ------------------------------------------------------------------ */
/* Live viewing: built-in viewer (FFmpeg + AC-4), ffplay as a fallback  */
/* ------------------------------------------------------------------ */
/* The viewer's picture: one paintable shared by the small viewer and the
 * full-screen window. A new frame only repaints it; the window's layout isn't
 * redone 30-60 times a second (that's what made playback choppy). */
#define FRAME_TYPE_PAINTABLE (frame_paintable_get_type())
G_DECLARE_FINAL_TYPE(FramePaintable, frame_paintable, FRAME, PAINTABLE, GObject)
struct _FramePaintable { GObject parent; GdkTexture *tex; double aspect; };

static void fp_snapshot(GdkPaintable *p, GdkSnapshot *snap, double w, double h) {
    FramePaintable *f = (FramePaintable *)p;
    if (f->tex) gdk_paintable_snapshot(GDK_PAINTABLE(f->tex), snap, w, h);
}
static double fp_aspect(GdkPaintable *p) { return ((FramePaintable *)p)->aspect; }
static void fp_iface_init(GdkPaintableInterface *i) {
    i->snapshot = fp_snapshot;
    i->get_intrinsic_aspect_ratio = fp_aspect;
}
G_DEFINE_TYPE_WITH_CODE(FramePaintable, frame_paintable, G_TYPE_OBJECT,
                        G_IMPLEMENT_INTERFACE(GDK_TYPE_PAINTABLE, fp_iface_init))
static void fp_finalize(GObject *o) {
    g_clear_object(&((FramePaintable *)o)->tex);
    G_OBJECT_CLASS(frame_paintable_parent_class)->finalize(o);
}
static void frame_paintable_class_init(FramePaintableClass *c) { G_OBJECT_CLASS(c)->finalize = fp_finalize; }
static void frame_paintable_init(FramePaintable *f) { f->aspect = 16.0 / 9.0; }

static void frame_paintable_set(FramePaintable *f, GdkTexture *tex) {
    if (tex) g_object_ref(tex);
    g_clear_object(&f->tex);
    f->tex = tex;
    if (tex) {
        double a = (double)gdk_texture_get_width(tex) / gdk_texture_get_height(tex);
        if (fabs(a - f->aspect) > 0.001) { f->aspect = a; gdk_paintable_invalidate_size(GDK_PAINTABLE(f)); }
    }
    gdk_paintable_invalidate_contents(GDK_PAINTABLE(f));
}

static FramePaintable *frames;   /* the viewer's picture */

/* Volume, in percent: AC-4 (ATSC 3.0) is usually very quiet, so it has its
 * own setting. Saved in viewer.conf next to the EAS settings. */
static int vol_ac4 = 500, vol_other = 100;
#define VOL_MAX  1000
#define VOL_STEP 25

static void vol_path(char *out, size_t n) { snprintf(out, n, "%s/viewer.conf", eas_config_dir()); }

static void vol_load(void) {
    char path[1100];
    vol_path(path, sizeof(path));
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        int x;
        if (sscanf(line, "vol_ac4=%d", &x) == 1 && x >= 0 && x <= VOL_MAX) vol_ac4 = x;
        if (sscanf(line, "vol_other=%d", &x) == 1 && x >= 0 && x <= VOL_MAX) vol_other = x;
    }
    fclose(f);
}

static void vol_save(void) {
    char path[1100];
    vol_path(path, sizeof(path));
    plat_mkdir_p(eas_config_dir());
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "# HDHR EAS Test viewer volume, percent\nvol_ac4=%d\nvol_other=%d\n", vol_ac4, vol_other);
    fclose(f);
}

static void vol_show(void) {
    if (!A.vol_label) return;
    int kind = A.viewer ? viewer_audio_kind(A.viewer) : VIEWER_AUDIO_NONE;
    char t[64];
    if (A.muted) snprintf(t, sizeof(t), "Muted");
    else if (kind == VIEWER_AUDIO_AC4) snprintf(t, sizeof(t), "Vol %d%% (AC-4)", vol_ac4);
    else if (kind == VIEWER_AUDIO_OTHER) snprintf(t, sizeof(t), "Vol %d%%", vol_other);
    else snprintf(t, sizeof(t), "Vol %d%% / AC-4 %d%%", vol_other, vol_ac4);
    gtk_label_set_text(GTK_LABEL(A.vol_label), t);
}

/* dir = +1 / -1: changes the setting the current stream uses */
static void vol_step(int dir) {
    int kind = A.viewer ? viewer_audio_kind(A.viewer) : VIEWER_AUDIO_NONE;
    int *v = kind == VIEWER_AUDIO_AC4 ? &vol_ac4 : &vol_other;
    if (kind == VIEWER_AUDIO_NONE) { gui_msg("Start watching first - the volume follows the station's audio type."); return; }
    *v += dir * (*v >= 200 ? 2 * VOL_STEP : VOL_STEP);
    if (*v < 0) *v = 0;
    if (*v > VOL_MAX) *v = VOL_MAX;
    if (A.viewer) viewer_set_volume(A.viewer, vol_ac4, vol_other);
    vol_save();
    vol_show();
}

static void on_vol_down(GtkWidget *w, gpointer u) { (void)w; (void)u; vol_step(-1); }
static void on_vol_up(GtkWidget *w, gpointer u) { (void)w; (void)u; vol_step(+1); }

typedef struct { hdhr_tuner_t t; hdhr_program_t progs[64]; int n; int choice; } PlayCtx;

static gboolean watching(void) { return A.viewer != NULL || A.play_pid > 0; }

static gboolean idle_play_changed(gpointer p) {
    (void)p;
    gtk_button_set_label(GTK_BUTTON(A.btn_play), watching() ? "Stop watching" : "Watch…");
    gtk_widget_set_sensitive(A.btn_full, A.viewer != NULL);
    gtk_widget_set_sensitive(A.btn_mute, A.viewer != NULL);
    gtk_widget_set_sensitive(A.btn_vdown, A.viewer != NULL);
    gtk_widget_set_sensitive(A.btn_vup, A.viewer != NULL);
    vol_show();
    if (!watching()) {
        frame_paintable_set(frames, NULL);
        gtk_label_set_text(GTK_LABEL(A.view_status), "Not watching. Pick a tuner, then Watch… to see it here.");
    }
    return G_SOURCE_REMOVE;
}

/* frames arrive on the viewer's thread; show them on the main thread */
static gint frames_pending = 0;

static void free_rgba(gpointer p) { free(p); }

static gboolean idle_frame(gpointer p) {
    viewer_frame_t *f = p;
    g_atomic_int_dec_and_test(&frames_pending);
    if (A.viewer) {
        GBytes *b = g_bytes_new_with_free_func(f->rgba, (gsize)f->stride * f->h, free_rgba, f->rgba);
        f->rgba = NULL;
        GdkTexture *tex = gdk_memory_texture_new(f->w, f->h, GDK_MEMORY_R8G8B8A8, b, f->stride);
        g_bytes_unref(b);
        frame_paintable_set(frames, tex);
        g_object_unref(tex);
    }
    viewer_frame_free(f);
    return G_SOURCE_REMOVE;
}

static void on_viewer_frame(void *user, viewer_frame_t *f) {
    (void)user;
    if (g_atomic_int_get(&frames_pending) > 2) { viewer_frame_free(f); return; }   /* GUI busy: drop */
    g_atomic_int_inc(&frames_pending);
    g_idle_add_full(G_PRIORITY_DEFAULT, idle_frame, f, NULL);   /* before the next repaint */
}

static gboolean idle_view_status(gpointer p) {
    if (A.viewer) gtk_label_set_text(GTK_LABEL(A.view_status), (char *)p);
    g_free(p);
    return G_SOURCE_REMOVE;
}

static void on_viewer_status(void *user, const char *text) {
    char *s = g_strdup_printf("%s%s", (char *)user, text);
    g_idle_add(idle_view_status, s);
}

static char view_prefix[96];

static void work_play_start(gpointer p) {
    PlayCtx *v = p;
    const char *prog = v->progs[v->choice].program;
    struct hdhomerun_device_t *hd = open_tuner(&v->t);
    char msg[400] = "";
    if (!hd) {
        gui_post_msg("Couldn't reach the tuner.");
    } else if (viewer_available()) {
        int port = hdhr_free_udp_port();
        char err[200] = "";
        snprintf(view_prefix, sizeof(view_prefix), "%08X-%d program %s: ", (unsigned)v->t.device_id, v->t.tuner, prog);
        viewer_t *vw = port > 0 ? viewer_start(port, on_viewer_frame, on_viewer_status, view_prefix, err, sizeof(err)) : NULL;
        if (!vw) {
            gui_post_msg("Couldn't start the viewer: %s", err[0] ? err : "no free UDP port");
        } else if (hdhr_stream_to_me(hd, &v->t, prog, port, msg, sizeof(msg)) < 0) {
            viewer_stop(vw);
            gui_post_msg("%s", msg);
        } else {
            A.viewer = vw;
            A.play_tuner = A.sel;
            viewer_set_mute(vw, A.muted);
            viewer_set_volume(vw, vol_ac4, vol_other);
            gui_post_msg("Watching program %s.%s", prog,
                         viewer_has_ac4() ? "" : " This build has no AC-4 decoder: ATSC 3.0 audio will be silent.");
        }
    } else {                                            /* no built-in viewer: ffplay window */
        plat_pid_t pid = 0;
        hdhr_play_start(hd, &v->t, prog, &pid, msg, sizeof(msg));
        A.play_pid = pid;
        A.play_tuner = A.sel;
        gui_post_msg("%s", msg[0] ? msg : "Couldn't start ffplay.");
    }
    if (hd) hdhomerun_device_destroy(hd);
    g_idle_add(idle_play_changed, NULL);
    g_free(v);
}

static void prog_picked(int idx, gpointer p) {
    PlayCtx *v = p;
    v->choice = idx;
    if (!run_bg(work_play_start, v)) g_free(v);
}

static gboolean idle_prog_list(gpointer p) {
    PlayCtx *v = p;
    if (!v->n) { gui_msg("No programs found - is the tuner locked?"); g_free(v); return G_SOURCE_REMOVE; }
    const char *items[64];
    for (int i = 0; i < v->n; i++) items[i] = v->progs[i].display;
    gui_pick("Watch", "Select the program to watch:", items, v->n, 0, prog_picked, v);
    return G_SOURCE_REMOVE;
}

static void work_programs(gpointer p) {
    PlayCtx *v = p;
    struct hdhomerun_device_t *hd = open_tuner(&v->t);
    if (hd) {
        hdhr_status_t st;
        if (hdhr_get_status(hd, &st) == 0 && st.locked) v->n = hdhr_programs(hd, v->progs, 64);
        hdhomerun_device_destroy(hd);
    }
    if (v->n == 1) { v->choice = 0; work_play_start(v); return; }   /* only one program: play it */
    g_idle_add(idle_prog_list, v);
}

typedef struct { hdhr_tuner_t t; gboolean ended_by_itself; } StopCtx;

/* stop whatever is playing; also clears the tuner's stream target */
static void stop_watching_now(const hdhr_tuner_t *t) {
    if (A.viewer) { viewer_stop(A.viewer); A.viewer = NULL; }
    struct hdhomerun_device_t *hd = t ? open_tuner(t) : NULL;
    hdhr_play_stop(hd, &A.play_pid);                     /* ends ffplay if any; target none */
    if (hd) hdhomerun_device_destroy(hd);
}

static void work_play_stop(gpointer p) {
    StopCtx *c = p;
    stop_watching_now(&c->t);
    gui_post_msg("%s", c->ended_by_itself ? "The stream ended - stopped watching." : "Stopped watching.");
    g_idle_add(idle_play_changed, NULL);
    g_free(c);
}

static void stop_play(gboolean ended_by_itself) {
    StopCtx *c = g_new0(StopCtx, 1);
    c->t = A.tuners[A.play_tuner >= 0 && A.play_tuner < A.ntuners ? A.play_tuner : 0];
    c->ended_by_itself = ended_by_itself;
    if (!run_bg(work_play_stop, c)) g_free(c);
}

/* the stream ended, or the ffplay window was closed: tidy up */
static gboolean play_watch(gpointer u) {
    (void)u;
    vol_show();
    if (A.busy) return G_SOURCE_CONTINUE;
    if (A.viewer && !viewer_running(A.viewer)) stop_play(TRUE);
    else if (A.play_pid > 0 && !plat_pid_alive(A.play_pid)) stop_play(TRUE);
    return G_SOURCE_CONTINUE;
}

static void on_play(GtkWidget *w, gpointer u) {
    (void)w; (void)u;
    if (watching()) { stop_play(FALSE); return; }
    if (!viewer_available()) {
        char ffplay[1024];
        if (!player_find(ffplay, sizeof(ffplay))) {
            gui_info("No viewer", "This build has no built-in viewer and no ffplay was found.");
            return;
        }
    }
    hdhr_tuner_t *t = cur_tuner();
    if (!t) { gui_msg("Pick a tuner first."); return; }
    PlayCtx *v = g_new0(PlayCtx, 1);
    v->t = *t;
    if (!run_bg(work_programs, v)) g_free(v);
}

static void on_mute(GtkWidget *w, gpointer u) {
    (void)u;
    A.muted = !A.muted;
    if (A.viewer) viewer_set_mute(A.viewer, A.muted);
    gtk_button_set_label(GTK_BUTTON(w), A.muted ? "Unmute" : "Mute");
    vol_show();
}

/* full screen: a borderless window with its own picture; Esc, F, F11 or a
 * double-click returns */
static void fs_close(void) { if (A.fs_win) gtk_window_destroy(GTK_WINDOW(A.fs_win)); }

/* "destroy" covers every way the window goes (Esc, close button, program exit) */
static void fs_destroyed(GtkWidget *w, gpointer u) {
    (void)w; (void)u;
    A.fs_win = NULL;
    A.fs_pic = NULL;
}

static gboolean fs_key(GtkEventControllerKey *c, guint key, guint code, GdkModifierType m, gpointer u) {
    (void)c; (void)code; (void)m; (void)u;
    if (key == GDK_KEY_Escape || key == GDK_KEY_f || key == GDK_KEY_F || key == GDK_KEY_F11) { fs_close(); return TRUE; }
    if (key == GDK_KEY_m || key == GDK_KEY_M) { on_mute(A.btn_mute, NULL); return TRUE; }
    if (key == GDK_KEY_plus || key == GDK_KEY_equal || key == GDK_KEY_KP_Add || key == GDK_KEY_Up) { vol_step(+1); return TRUE; }
    if (key == GDK_KEY_minus || key == GDK_KEY_KP_Subtract || key == GDK_KEY_Down) { vol_step(-1); return TRUE; }
    return FALSE;
}

static void fs_click(GtkGestureClick *g, int n, double x, double y, gpointer u) {
    (void)g; (void)x; (void)y; (void)u;
    if (n == 2) fs_close();
}

static void on_full(GtkWidget *w, gpointer u) {
    (void)w; (void)u;
    if (!A.viewer) return;
    if (A.fs_win) { fs_close(); return; }
    A.fs_win = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(A.fs_win), APP_NAME " - viewer");
    gtk_widget_add_css_class(A.fs_win, "viewer");
    A.fs_pic = gtk_picture_new();
    gtk_picture_set_content_fit(GTK_PICTURE(A.fs_pic), GTK_CONTENT_FIT_CONTAIN);
    gtk_widget_add_css_class(A.fs_pic, "viewer");
    gtk_picture_set_paintable(GTK_PICTURE(A.fs_pic), GDK_PAINTABLE(frames));
    gtk_window_set_child(GTK_WINDOW(A.fs_win), A.fs_pic);
    GtkEventController *k = gtk_event_controller_key_new();
    g_signal_connect(k, "key-pressed", G_CALLBACK(fs_key), NULL);
    gtk_widget_add_controller(A.fs_win, k);
    GtkGesture *g = gtk_gesture_click_new();
    g_signal_connect(g, "pressed", G_CALLBACK(fs_click), NULL);
    gtk_widget_add_controller(A.fs_pic, GTK_EVENT_CONTROLLER(g));
    g_signal_connect(A.fs_win, "destroy", G_CALLBACK(fs_destroyed), NULL);
    gtk_window_fullscreen(GTK_WINDOW(A.fs_win));
    gtk_window_present(GTK_WINDOW(A.fs_win));
}

static void view_click(GtkGestureClick *g, int n, double x, double y, gpointer u) {
    (void)g; (void)x; (void)y; (void)u;
    if (n == 2) on_full(NULL, NULL);
}

/* ------------------------------------------------------------------ */
/* PLP & L1 details                                                    */
/* ------------------------------------------------------------------ */
typedef struct { hdhr_tuner_t t; char *text; char saved[1100]; } DetCtx;

static void work_details_save(gpointer p) {
    DetCtx *d = p;
    struct hdhomerun_device_t *hd = open_tuner(&d->t);
    plat_mkdir_p(gui_captures_dir());
    char base[1200];
    time_t now = time(NULL);
    struct tm tm;
    plat_localtime(now, &tm);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y%m%d-%H%M%S", &tm);
    snprintf(base, sizeof(base), "%s/plp-details-%08X-%d-%s.details", gui_captures_dir(), d->t.device_id, d->t.tuner, ts);
    int r = -1;
    if (hd) {
        eas_details_lock();
        r = save_atsc3_details_auto(hd, d->t.tuner, base);
        eas_details_unlock();
        hdhomerun_device_destroy(hd);
    }
    char *dot = strrchr(base, '.');
    if (dot) strcpy(dot, ".txt");
    gui_post_msg(r == 0 ? "Saved %s" : "Couldn't save the details (%s).", base);
    g_free(d);
}

static void on_details_save(GtkWidget *w, gpointer u) {
    (void)w;
    DetCtx *d = g_new0(DetCtx, 1);
    d->t = *(hdhr_tuner_t *)u;
    if (!run_bg(work_details_save, d)) g_free(d);
}

static void on_close_window(GtkWidget *w, gpointer win) { (void)w; gtk_window_destroy(GTK_WINDOW(win)); }

static gboolean idle_details(gpointer p) {
    DetCtx *d = p;
    if (!d->text) { gui_msg("Couldn't read the ATSC 3.0 details - is the tuner on an ATSC 3.0 channel?"); g_free(d); return G_SOURCE_REMOVE; }
    GtkWidget *win = gtk_window_new();
    char title[96];
    snprintf(title, sizeof(title), "ATSC 3.0 PLP & L1 details - %08X-%d", d->t.device_id, d->t.tuner);
    gtk_window_set_title(GTK_WINDOW(win), title);
    gtk_window_set_transient_for(GTK_WINDOW(win), GTK_WINDOW(A.win));
    gtk_window_set_default_size(GTK_WINDOW(win), 900, 640);
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_set_margin_start(box, 8); gtk_widget_set_margin_end(box, 8);
    gtk_widget_set_margin_top(box, 8); gtk_widget_set_margin_bottom(box, 8);
    GtkWidget *tv = gtk_text_view_new();
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(tv), TRUE);
    gtk_text_view_set_editable(GTK_TEXT_VIEW(tv), FALSE);
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(tv)), d->text, -1);
    GtkWidget *sw = gtk_scrolled_window_new();
    gtk_widget_set_vexpand(sw, TRUE);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(sw), tv);
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(row, GTK_ALIGN_END);
    hdhr_tuner_t *tcopy = g_new0(hdhr_tuner_t, 1);
    *tcopy = d->t;
    g_object_set_data_full(G_OBJECT(win), "tuner", tcopy, g_free);
    GtkWidget *bs = gtk_button_new_with_label("Save to file");
    GtkWidget *bc = gtk_button_new_with_label("Close");
    g_signal_connect(bs, "clicked", G_CALLBACK(on_details_save), tcopy);
    g_signal_connect(bc, "clicked", G_CALLBACK(on_close_window), win);
    gtk_box_append(GTK_BOX(row), bs);
    gtk_box_append(GTK_BOX(row), bc);
    gtk_box_append(GTK_BOX(box), sw);
    gtk_box_append(GTK_BOX(box), row);
    gtk_window_set_child(GTK_WINDOW(win), box);
    escape_closes(win);
    gtk_window_present(GTK_WINDOW(win));
    g_free(d->text);
    g_free(d);
    return G_SOURCE_REMOVE;
}

static void work_details(gpointer p) {
    DetCtx *d = p;
    struct hdhomerun_device_t *hd = open_tuner(&d->t);
    if (hd) {
        struct l1_detail_info *info = create_l1_detail_info(MAX_DISPLAY_LINES);
        eas_details_lock();
        int r = info ? collect_atsc3_details(hd, d->t.tuner, info) : -1;
        eas_details_unlock();
        if (r == 0) {
            GString *g = g_string_new(NULL);
            for (int i = 0; i < info->line_count; i++) {
                if (!strcmp(info->display_lines[i], "__HLINE__")) g_string_append(g, "--------------------------------------------------------------------------------\n");
                else { g_string_append(g, info->display_lines[i]); g_string_append_c(g, '\n'); }
            }
            d->text = g_string_free(g, FALSE);
        }
        if (info) free_l1_detail_info(info);
        hdhomerun_device_destroy(hd);
    }
    g_idle_add(idle_details, d);
}

static void on_details(GtkWidget *w, gpointer u) {
    (void)w; (void)u;
    hdhr_tuner_t *t = cur_tuner();
    if (!t) { gui_msg("Pick a tuner first."); return; }
    DetCtx *d = g_new0(DetCtx, 1);
    d->t = *t;
    if (!run_bg(work_details, d)) g_free(d);
}

/* ------------------------------------------------------------------ */
/* 30-second captures (same files as the TUI's s/a/x/z keys)          */
/* ------------------------------------------------------------------ */
enum { CAP_NORMAL = 0, CAP_PCAP = 1 };
typedef struct { hdhr_tuner_t t; int kind; gboolean retry; } CapCtx;

static gboolean idle_cap_end(gpointer p) {
    (void)p;
    A.capturing = FALSE;
    gtk_widget_set_visible(A.btn_cap_cancel, FALSE);
    return G_SOURCE_REMOVE;
}

/* "atsc3:31:0+1" (+ lock) -> "31p0p1"; 1.0 -> "27" */
static void spec_from_status(const hdhr_status_t *st, char *out, size_t n) {
    out[0] = '\0';
    const char *p = strchr(st->channel, ':');
    p = p ? p + 1 : st->channel;
    unsigned rf = (unsigned)strtoul(p, NULL, 10);
    if (!st->atsc3) { snprintf(out, n, "%u", rf); return; }
    char plps[64] = "";
    const char *c2 = strchr(p, ':');
    if (c2) {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "%s", c2 + 1);
        for (char *save = NULL, *tok = strtok_r(tmp, "+", &save); tok; tok = strtok_r(NULL, "+", &save)) {
            size_t L = strlen(plps);
            snprintf(plps + L, sizeof(plps) - L, "p%d", atoi(tok));
        }
    } else {
        for (int i = 0; i < st->nplp; i++) {
            if (!strstr(st->plps[i], "lock=1")) continue;
            size_t L = strlen(plps);
            snprintf(plps + L, sizeof(plps) - L, "p%d", atoi(st->plps[i]));
        }
    }
    snprintf(out, n, "%u%s", rf, plps[0] ? plps : "p0");
}

static long debug_errors(struct hdhomerun_device_t *hd, int tuner) {
    char path[48], *v;
    snprintf(path, sizeof(path), "/tuner%d/debug", tuner);
    if (hdhomerun_device_get_var(hd, path, &v, NULL) <= 0) return -1;
    char buf[1024];
    snprintf(buf, sizeof(buf), "%s", v);
    long te = hdhr_status_value(buf, "te="), ne = hdhr_status_value(buf, "ne="), se = hdhr_status_value(buf, "se=");
    return (te > 0 ? te : 0) + (ne > 0 ? ne : 0) + (se > 0 ? se : 0);
}

static void work_capture(gpointer p) {
    CapCtx *c = p;
    struct hdhomerun_device_t *hd = open_tuner(&c->t);
    hdhr_status_t st;
    if (!hd || hdhr_get_status(hd, &st) != 0) { gui_post_msg("Couldn't reach the tuner."); goto out; }
    if (!st.locked) { gui_post_msg("No signal lock. Can't save a capture."); goto out; }
    if (c->kind == CAP_PCAP && !st.atsc3) { gui_post_msg("PCAP captures are for ATSC 3.0 channels."); goto out; }
    char original[64];
    snprintf(original, sizeof(original), "%s", st.channel);
    char spec[64];
    spec_from_status(&st, spec, sizeof(spec));
    plat_mkdir_p(gui_captures_dir());

    int attempt = 0;
    for (;;) {
        attempt++;
        eas_job_t job;
        eas_job_init(&job);
        snprintf(job.ip, sizeof(job.ip), "%s", c->t.ip);
        job.tuner = c->t.tuner;
        char err[200];
        if (eas_parse_channel_spec(spec, &job, err, sizeof(err)) < 0) { gui_post_msg("%s", err); eas_job_destroy(&job); break; }
        job.fmt = !job.atsc3 ? EAS_FMT_TS : (c->kind == CAP_PCAP ? EAS_FMT_PCAP : EAS_FMT_DBG);
        job.seg_seconds = 31536000;          /* one file */
        job.stop_time = time(NULL) + 30;
        job.force_release = FALSE;
        snprintf(job.outdir, sizeof(job.outdir), "%s", gui_captures_dir());
        long err0 = job.atsc3 ? 0 : debug_errors(hd, c->t.tuner);
        if (eas_job_start(&job) != 0) { gui_post_msg("Couldn't start the capture."); eas_job_destroy(&job); break; }
        time_t t0 = time(NULL);
        gboolean bad = FALSE;
        for (;;) {
            plat_sleep_ms(500);
            eas_status_t es;
            eas_job_status(&job, &es);
            long left = 30 - (long)(time(NULL) - t0);
            if (left < 0) left = 0;
            const char *base = strrchr(es.cur_file, '/');
            gui_post_msg("Saving %s ... %lds left%s%s", base ? base + 1 : "capture", left,
                         c->retry ? " (retries on errors)" : "", attempt > 1 ? " - retry" : "");
            if (!es.running) break;
            if (A.cap_cancel) { eas_job_request_stop(&job); continue; }
            if (c->retry && time(NULL) - t0 >= 2 && time(NULL) - t0 < 30) {
                if (job.atsc3) {
                    hdhr_status_t s2;
                    if (hdhr_get_status(hd, &s2) == 0 && s2.seq < 100) bad = TRUE;
                } else {
                    long e = debug_errors(hd, c->t.tuner);
                    if (e > err0 && err0 >= 0) bad = TRUE;
                }
                if (bad) eas_job_request_stop(&job);
            }
        }
        eas_job_join(&job);
        eas_status_t es;
        eas_job_status(&job, &es);
        eas_job_destroy(&job);
        if (bad && !A.cap_cancel) {
            remove(es.cur_file);
            char txt[800];
            snprintf(txt, sizeof(txt), "%s", es.cur_file);
            char *dot = strrchr(txt, '.');
            if (dot) { strcpy(dot, ".txt"); remove(txt); }
            gui_post_msg("Signal errors - restarting the capture...");
            hdhomerun_device_set_tuner_channel(hd, original);
            struct hdhomerun_tuner_status_t ls;
            hdhomerun_device_wait_for_lock(hd, &ls);
            plat_sleep_ms(1000);
            continue;
        }
        if (A.cap_cancel) gui_post_msg("Capture stopped. Partial file kept: %s", es.cur_file);
        else gui_post_msg("Saved %s (%.1f MB)%s", es.cur_file, es.bytes_total / 1048576.0,
                          job.atsc3 ? " + details .txt" : "");
        break;
    }
    if (st.atsc3) {   /* give the tuner back the way it was */
        plat_sleep_ms(500);
        hdhomerun_device_set_tuner_channel(hd, original);
        struct hdhomerun_tuner_status_t ls;
        hdhomerun_device_wait_for_lock(hd, &ls);
    }
out:
    if (hd) hdhomerun_device_destroy(hd);
    g_idle_add(idle_cap_end, NULL);
    g_free(c);
}

static void start_capture(int kind, gboolean retry) {
    hdhr_tuner_t *t = cur_tuner();
    if (!t) { gui_msg("Pick a tuner first."); return; }
    CapCtx *c = g_new0(CapCtx, 1);
    c->t = *t;
    c->kind = kind;
    c->retry = retry;
    A.cap_cancel = FALSE;
    if (run_bg(work_capture, c)) {
        A.capturing = TRUE;
        gtk_widget_set_visible(A.btn_cap_cancel, TRUE);
    } else g_free(c);
}

static void on_cap_normal(GtkWidget *w, gpointer u) { (void)w; (void)u; start_capture(CAP_NORMAL, FALSE); }
static void on_cap_retry(GtkWidget *w, gpointer u) { (void)w; (void)u; start_capture(CAP_NORMAL, TRUE); }
static void on_cap_pcap(GtkWidget *w, gpointer u) { (void)w; (void)u; start_capture(CAP_PCAP, FALSE); }
static void on_cap_pcap_retry(GtkWidget *w, gpointer u) { (void)w; (void)u; start_capture(CAP_PCAP, TRUE); }
static void on_cap_cancel(GtkWidget *w, gpointer u) { (void)w; (void)u; A.cap_cancel = TRUE; }
static void on_open_captures(GtkWidget *w, gpointer u) {
    (void)w; (void)u;
    plat_mkdir_p(gui_captures_dir());
    plat_open_uri(gui_captures_dir());
}

/* ------------------------------------------------------------------ */
/* Window                                                              */
/* ------------------------------------------------------------------ */
static GtkWidget *kv(GtkWidget *grid, int row, const char *key) {
    GtkWidget *k = gtk_label_new(key);
    gtk_label_set_xalign(GTK_LABEL(k), 0);
    gtk_widget_add_css_class(k, "dim-label");
    GtkWidget *v = gtk_label_new("-");
    gtk_label_set_xalign(GTK_LABEL(v), 0);
    gtk_label_set_selectable(GTK_LABEL(v), TRUE);
    gtk_grid_attach(GTK_GRID(grid), k, 0, row, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), v, 1, row, 2, 1);
    return v;
}

static GtkWidget *button(const char *label, const char *tip, GCallback cb, gpointer data) {
    GtkWidget *b = gtk_button_new_with_label(label);
    if (tip) gtk_widget_set_tooltip_text(b, tip);
    g_signal_connect(b, "clicked", cb, data);
    return b;
}

static GtkWidget *tuners_page(void) {
    GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    A.tuner_list = gtk_list_box_new();
    g_signal_connect(A.tuner_list, "row-selected", G_CALLBACK(on_tuner_selected), NULL);
    GtkWidget *lsw = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(lsw), A.tuner_list);
    gtk_widget_set_size_request(lsw, 190, -1);
    gtk_paned_set_start_child(GTK_PANED(paned), lsw);
    gtk_paned_set_resize_start_child(GTK_PANED(paned), FALSE);

    GtkWidget *right = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_start(right, 12); gtk_widget_set_margin_end(right, 12);
    gtk_widget_set_margin_top(right, 10); gtk_widget_set_margin_bottom(right, 10);
    A.st_title = gtk_label_new("Pick a tuner");
    gtk_widget_add_css_class(A.st_title, "title-3");
    gtk_label_set_xalign(GTK_LABEL(A.st_title), 0);
    gtk_box_append(GTK_BOX(right), A.st_title);

    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_column_spacing(GTK_GRID(grid), 12);
    gtk_grid_set_row_spacing(GTK_GRID(grid), 4);
    A.st_channel = kv(grid, 0, "Channel");
    A.st_lock = kv(grid, 1, "Lock");
    A.st_id = kv(grid, 2, "ID");
    A.st_vch = kv(grid, 3, "Virtual");
    const char *names[3] = { "Signal strength", "Signal quality", "Symbol quality" };
    for (int i = 0; i < 3; i++) {
        GtkWidget *k = gtk_label_new(names[i]);
        gtk_label_set_xalign(GTK_LABEL(k), 0);
        gtk_widget_add_css_class(k, "dim-label");
        A.lvl[i] = gtk_level_bar_new_for_interval(0, 100);
        gtk_level_bar_add_offset_value(GTK_LEVEL_BAR(A.lvl[i]), GTK_LEVEL_BAR_OFFSET_LOW, 50);
        gtk_level_bar_add_offset_value(GTK_LEVEL_BAR(A.lvl[i]), GTK_LEVEL_BAR_OFFSET_HIGH, 80);
        gtk_widget_set_hexpand(A.lvl[i], TRUE);
        gtk_widget_set_valign(A.lvl[i], GTK_ALIGN_CENTER);
        A.lvl_txt[i] = gtk_label_new("");
        gtk_label_set_xalign(GTK_LABEL(A.lvl_txt[i]), 0);
        gtk_widget_set_size_request(A.lvl_txt[i], 150, -1);
        gtk_grid_attach(GTK_GRID(grid), k, 0, 4 + i, 1, 1);
        gtk_grid_attach(GTK_GRID(grid), A.lvl[i], 1, 4 + i, 1, 1);
        gtk_grid_attach(GTK_GRID(grid), A.lvl_txt[i], 2, 4 + i, 1, 1);
    }
    A.st_rate = kv(grid, 7, "Network rate");
    A.st_target = kv(grid, 8, "Network target");
    gtk_box_append(GTK_BOX(right), grid);

    GtkWidget *info = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 16);
    GtkWidget *pf = gtk_frame_new("Programs");
    A.st_progs = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(A.st_progs), 0);
    gtk_label_set_yalign(GTK_LABEL(A.st_progs), 0);
    gtk_label_set_selectable(GTK_LABEL(A.st_progs), TRUE);
    gtk_widget_set_margin_start(A.st_progs, 8); gtk_widget_set_margin_top(A.st_progs, 4);
    GtkWidget *psw = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(psw), A.st_progs);
    gtk_widget_set_vexpand(psw, TRUE);
    gtk_widget_set_hexpand(psw, TRUE);
    gtk_frame_set_child(GTK_FRAME(pf), psw);
    GtkWidget *lf = gtk_frame_new("ATSC 3.0 PLPs");
    A.st_plps = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(A.st_plps), 0);
    gtk_label_set_yalign(GTK_LABEL(A.st_plps), 0);
    gtk_label_set_selectable(GTK_LABEL(A.st_plps), TRUE);
    gtk_widget_set_margin_start(A.st_plps, 8); gtk_widget_set_margin_top(A.st_plps, 4);
    GtkWidget *lsw2 = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(lsw2), A.st_plps);
    gtk_widget_set_hexpand(lsw2, TRUE);
    gtk_frame_set_child(GTK_FRAME(lf), lsw2);
    GtkWidget *lists = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_size_request(lists, 300, -1);
    gtk_widget_set_hexpand(lists, FALSE);
    gtk_widget_set_hexpand(pf, FALSE);
    gtk_widget_set_hexpand(lf, FALSE);
    gtk_widget_set_vexpand(pf, TRUE);
    gtk_widget_set_vexpand(lf, TRUE);
    gtk_widget_set_hexpand(psw, FALSE);
    gtk_widget_set_hexpand(lsw2, FALSE);
    gtk_box_append(GTK_BOX(lists), pf);
    gtk_box_append(GTK_BOX(lists), lf);

    /* the viewer */
    GtkWidget *vf = gtk_frame_new("Viewer");
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    vol_load();
    frames = g_object_new(FRAME_TYPE_PAINTABLE, NULL);
    A.view_pic = gtk_picture_new_for_paintable(GDK_PAINTABLE(frames));
    gtk_picture_set_content_fit(GTK_PICTURE(A.view_pic), GTK_CONTENT_FIT_CONTAIN);
    gtk_widget_add_css_class(A.view_pic, "viewer");
    gtk_widget_set_size_request(A.view_pic, 384, 216);
    gtk_widget_set_hexpand(A.view_pic, TRUE);
    gtk_widget_set_vexpand(A.view_pic, TRUE);
    GtkGesture *vg = gtk_gesture_click_new();
    g_signal_connect(vg, "pressed", G_CALLBACK(view_click), NULL);
    gtk_widget_add_controller(A.view_pic, GTK_EVENT_CONTROLLER(vg));
    gtk_box_append(GTK_BOX(vbox), A.view_pic);
    GtkWidget *vrow = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_widget_set_margin_start(vrow, 6); gtk_widget_set_margin_end(vrow, 6); gtk_widget_set_margin_bottom(vrow, 2);
    A.btn_play = button("Watch…", "Watch a program here (AC-4 audio for ATSC 3.0)", G_CALLBACK(on_play), NULL);
    A.btn_full = button("Full screen", "Full screen (Esc, F or double-click to return)", G_CALLBACK(on_full), NULL);
    A.btn_mute = button("Mute", "Mute or unmute the sound", G_CALLBACK(on_mute), NULL);
    A.btn_vdown = button("Vol −", "Quieter (full screen: - or Down)", G_CALLBACK(on_vol_down), NULL);
    A.btn_vup = button("Vol +", "Louder - up to 1000%; AC-4 is usually very quiet (full screen: + or Up)", G_CALLBACK(on_vol_up), NULL);
    A.vol_label = gtk_label_new("");
    gtk_widget_add_css_class(A.vol_label, "mono");
    A.view_status = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(A.view_status), 0);
    gtk_label_set_ellipsize(GTK_LABEL(A.view_status), PANGO_ELLIPSIZE_END);
    gtk_widget_set_hexpand(A.view_status, TRUE);
    gtk_box_append(GTK_BOX(vrow), A.btn_play);
    gtk_box_append(GTK_BOX(vrow), A.btn_full);
    gtk_box_append(GTK_BOX(vrow), A.btn_mute);
    gtk_box_append(GTK_BOX(vrow), A.btn_vdown);
    gtk_box_append(GTK_BOX(vrow), A.btn_vup);
    gtk_box_append(GTK_BOX(vrow), A.vol_label);
    gtk_box_append(GTK_BOX(vbox), vrow);
    gtk_widget_set_margin_start(A.view_status, 8); gtk_widget_set_margin_bottom(A.view_status, 6);
    gtk_box_append(GTK_BOX(vbox), A.view_status);
    gtk_frame_set_child(GTK_FRAME(vf), vbox);
    gtk_widget_set_hexpand(vf, TRUE);

    gtk_box_append(GTK_BOX(info), lists);
    gtk_box_append(GTK_BOX(info), vf);
    gtk_widget_set_vexpand(info, TRUE);
    gtk_box_append(GTK_BOX(right), info);

    A.action_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *r1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_append(GTK_BOX(r1), button("◀ Channel", "Previous channel", G_CALLBACK(on_step), GINT_TO_POINTER(-1)));
    gtk_box_append(GTK_BOX(r1), button("Channel ▶", "Next channel", G_CALLBACK(on_step), GINT_TO_POINTER(1)));
    gtk_box_append(GTK_BOX(r1), button("◀ Seek", "Seek down to the next channel with a signal", G_CALLBACK(on_seek), GINT_TO_POINTER(-1)));
    gtk_box_append(GTK_BOX(r1), button("Seek ▶", "Seek up to the next channel with a signal", G_CALLBACK(on_seek), GINT_TO_POINTER(1)));
    gtk_box_append(GTK_BOX(r1), button("Tune…", "Tune to a channel or frequency", G_CALLBACK(on_tune), NULL));
    gtk_box_append(GTK_BOX(r1), button("Channel map…", "Change the tuner's channel map", G_CALLBACK(on_map), NULL));
    gtk_box_append(GTK_BOX(r1), button("PLPs…", "Set the ATSC 3.0 PLPs", G_CALLBACK(on_plps), NULL));
    gtk_box_append(GTK_BOX(r1), button("Release tuner", "Free this tuner: clear its lock, stream and channel (same as Tune 0)", G_CALLBACK(on_release), NULL));
    GtkWidget *r2 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_append(GTK_BOX(r2), button("PLP details…", "ATSC 3.0 PLP, L1 and SNR details", G_CALLBACK(on_details), NULL));
    gtk_box_append(GTK_BOX(r2), button("Save 30 s", "ATSC 1.0: transport stream (.ts). ATSC 3.0: debug capture (.dbg + .txt)", G_CALLBACK(on_cap_normal), NULL));
    gtk_box_append(GTK_BOX(r2), button("Save 30 s, retry on errors", "Restarts the capture if signal errors appear", G_CALLBACK(on_cap_retry), NULL));
    gtk_box_append(GTK_BOX(r2), button("Save 30 s PCAP", "ATSC 3.0 ALP-PCAP capture (.pcap + .txt), if the model supports it", G_CALLBACK(on_cap_pcap), NULL));
    gtk_box_append(GTK_BOX(r2), button("PCAP, retry on errors", NULL, G_CALLBACK(on_cap_pcap_retry), NULL));
    gtk_box_append(GTK_BOX(A.action_box), r1);
    gtk_box_append(GTK_BOX(A.action_box), r2);
    gtk_box_append(GTK_BOX(right), A.action_box);

    GtkWidget *r3 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    A.btn_seek_stop = button("Stop seek", NULL, G_CALLBACK(on_seek_stop), NULL);
    A.btn_cap_cancel = button("Stop capture", NULL, G_CALLBACK(on_cap_cancel), NULL);
    gtk_widget_set_visible(A.btn_seek_stop, FALSE);
    gtk_widget_set_visible(A.btn_cap_cancel, FALSE);
    char capl[1200];
    snprintf(capl, sizeof(capl), "Captures are saved in %s", gui_captures_dir());
    GtkWidget *cl = gtk_label_new(capl);
    gtk_widget_add_css_class(cl, "dim-label");
    gtk_box_append(GTK_BOX(r3), A.btn_seek_stop);
    gtk_box_append(GTK_BOX(r3), A.btn_cap_cancel);
    gtk_box_append(GTK_BOX(r3), cl);
    gtk_box_append(GTK_BOX(r3), button("Open folder", NULL, G_CALLBACK(on_open_captures), NULL));
    gtk_box_append(GTK_BOX(right), r3);

    gtk_paned_set_end_child(GTK_PANED(paned), right);
    return paned;
}

static void on_about(GtkWidget *w, gpointer u) {
    (void)w; (void)u;
    const char *authors[] = { "Brian Scott - HDHR EAS Test (EAS capture, reports, GUI, Windows port)",
                              "Mark J. Colombo (RabbitEars) - HDHomeRun TUI v0.9 and RENDER v0.4",
                              "Silicondust USA Inc. - libhdhomerun",
                              "drmpeg - dtv-utils (L1 parsing)",
                              "Paul B Mahol - FFmpeg AC-4 decoder (used by the ffplay build)", NULL };
    gtk_show_about_dialog(GTK_WINDOW(A.win),
                          "program-name", APP_NAME,
                          "version", "v" APP_VERSION,
                          "copyright", "Copyright \u00A9 2026 Brian Scott\n"
                                       "HDHomeRun TUI and RENDER \u00A9 2025 Mark J. Colombo (RabbitEars)",
                          "comments", "Record your TV stations during the nationwide EAS test and see what each one sent.\n"
                                      "By Brian Scott. Built on HDHomeRun TUI v0.9 and RENDER v0.4 by RabbitEars.",
                          "website", "https://www.rabbitears.info",
                          "website-label", "rabbitears.info",
                          "authors", authors,
                          "license-type", GTK_LICENSE_GPL_3_0,
                          NULL);
}

static gboolean tick(gpointer u) {
    (void)u;
    eas_page_tick();
    return G_SOURCE_CONTINUE;
}

static void on_close(GtkWindow *w, gpointer u) {
    (void)w; (void)u;
    g_mutex_lock(&A.lock);
    A.quit = TRUE;
    g_mutex_unlock(&A.lock);
    A.cap_cancel = TRUE;
    A.seek_cancel = TRUE;
    fs_close();
    if (watching() && A.play_tuner >= 0 && A.play_tuner < A.ntuners) stop_watching_now(&A.tuners[A.play_tuner]);
}

static void activate(GtkApplication *app, gpointer u) {
    (void)u;
    GtkCssProvider *css = gtk_css_provider_new();
    const char *css_text =
        "entry.error { color: #c01c28; }\n"
        ".note { color: #e5a50a; font-weight: bold; }\n"
        ".caution { color: #c01c28; font-weight: bold; }\n"
        ".mono { font-family: monospace; }\n"
        "picture.viewer, window.viewer { background-color: black; }\n";
#if GTK_CHECK_VERSION(4, 12, 0)
    gtk_css_provider_load_from_string(css, css_text);
#else
    gtk_css_provider_load_from_data(css, css_text, -1);
#endif
    gtk_style_context_add_provider_for_display(gdk_display_get_default(), GTK_STYLE_PROVIDER(css),
                                               GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

    A.win = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(A.win), APP_NAME " v" APP_VERSION);
    gtk_window_set_default_size(GTK_WINDOW(A.win), 1150, 760);
    g_signal_connect(A.win, "close-request", G_CALLBACK(on_close), NULL);

    GtkWidget *hb = gtk_header_bar_new();
    GtkWidget *stack = gtk_stack_new();
    GtkWidget *sw = gtk_stack_switcher_new();
    gtk_stack_switcher_set_stack(GTK_STACK_SWITCHER(sw), GTK_STACK(stack));
    gtk_header_bar_set_title_widget(GTK_HEADER_BAR(hb), sw);
    gtk_header_bar_pack_start(GTK_HEADER_BAR(hb), button("Refresh", "Find HDHomeRun devices again", G_CALLBACK(on_refresh), NULL));
    gtk_header_bar_pack_start(GTK_HEADER_BAR(hb), button("Add device…", "Add an HDHomeRun by IP address", G_CALLBACK(on_add_ip), NULL));
    gtk_header_bar_pack_end(GTK_HEADER_BAR(hb), button("About", NULL, G_CALLBACK(on_about), NULL));
    gtk_window_set_titlebar(GTK_WINDOW(A.win), hb);

    GtkWidget *outer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_stack_add_titled(GTK_STACK(stack), tuners_page(), "tuners", "Tuners");
    gtk_stack_add_titled(GTK_STACK(stack), eas_page_new(), "eas", "EAS Test");
    gtk_widget_set_vexpand(stack, TRUE);
    gtk_box_append(GTK_BOX(outer), stack);
    A.msg = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(A.msg), 0);
    gtk_label_set_ellipsize(GTK_LABEL(A.msg), PANGO_ELLIPSIZE_END);
    gtk_widget_set_margin_start(A.msg, 10); gtk_widget_set_margin_end(A.msg, 10);
    gtk_widget_set_margin_top(A.msg, 4); gtk_widget_set_margin_bottom(A.msg, 4);
    gtk_box_append(GTK_BOX(outer), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL));
    gtk_box_append(GTK_BOX(outer), A.msg);
    gtk_window_set_child(GTK_WINDOW(A.win), outer);
    gtk_window_present(GTK_WINDOW(A.win));

    A.sel = -1;
    A.last_for = -1;
    A.poller = g_thread_new("poll", poller_thread, NULL);
    g_timeout_add(1000, tick, NULL);
    g_timeout_add(1000, play_watch, NULL);
    on_refresh(NULL, NULL);
    idle_play_changed(NULL);
}

int main(int argc, char **argv) {
    plat_init();
    /* Background modes this program runs for itself (no window) */
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--eas-daemon")) return eas_daemon_main(argc, argv);
        if (!strcmp(argv[i], "--eas-zip")) return eas_zip_main(argc, argv);
        if (!strcmp(argv[i], "--eas")) return eas_headless_main(argc, argv);
    }
    memset(&A, 0, sizeof(A));
    g_mutex_init(&A.lock);
    for (int i = 1; i < argc; i++) {
#ifndef _WIN32
        if (!strcmp(argv[i], "--pause-services")) A.pause_services = TRUE;
#endif
        if (!strcmp(argv[i], "-i") && i + 1 < argc) snprintf(A.initial_ip, sizeof(A.initial_ip), "%s", argv[++i]);
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            printf("%s v%s - GTK GUI\nBuilt on HDHomeRun TUI v0.9 and RENDER v0.4 by RabbitEars. GPLv3.\n\n", APP_NAME, APP_VERSION);
            printf("Usage: %s [-i <ip>]%s\n", argv[0],
#ifndef _WIN32
                   " [--pause-services]"
#else
                   ""
#endif
                   );
            return 0;
        }
    }
    eas_config_load(&A.cfg);
    A.app = gtk_application_new("info.rabbitears.HdhrEasTest", G_APPLICATION_NON_UNIQUE);
    g_signal_connect(A.app, "activate", G_CALLBACK(activate), NULL);
    char *argv0[] = { argv[0], NULL };
    int rc = g_application_run(G_APPLICATION(A.app), 1, argv0);
    g_mutex_lock(&A.lock);
    A.quit = TRUE;
    g_mutex_unlock(&A.lock);
    if (A.poller) g_thread_join(A.poller);
    g_object_unref(A.app);
    return rc;
}
