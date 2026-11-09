/*
 * Copyright (C) 2026 Brian Scott - HDHR EAS Test.
 * gui.h - GTK4 GUI for HDHR EAS Test. GPLv3.
 */
#ifndef HDHR_EAS_GUI_H
#define HDHR_EAS_GUI_H

#include <gtk/gtk.h>
#include "hdhr_dev.h"
#include "eas_run.h"
#include "plat.h"

#define APP_NAME    "HDHR EAS Test"
#define APP_VERSION "0.5"

typedef struct {
    GtkApplication *app;
    GtkWidget *win;
    gboolean pause_services;      /* Linux, started with --pause-services */
    char initial_ip[64];

    /* devices */
    hdhr_tuner_t tuners[HDHR_MAX_TUNERS];
    int ntuners;
    int sel;                      /* selected tuner index, -1 none */
    GtkWidget *tuner_list;

    /* status panel */
    GtkWidget *st_title, *st_channel, *st_lock, *st_id, *st_vch;
    GtkWidget *lvl[3], *lvl_txt[3];
    GtkWidget *st_rate, *st_target, *st_progs, *st_plps;
    GtkWidget *msg;
    GtkWidget *action_box;        /* disabled while an action runs */
    GtkWidget *btn_play, *btn_cap_cancel, *btn_seek_stop;

    /* status poller */
    GMutex lock;
    hdhr_status_t last;
    int last_for;                 /* tuner index the status belongs to */
    gboolean poke, quit;
    GThread *poller;

    /* actions */
    gboolean busy;
    volatile gboolean seek_cancel;
    volatile gboolean cap_cancel;
    gboolean capturing;
    plat_pid_t play_pid;          /* ffplay (fallback when there's no built-in viewer) */
    int play_tuner;
    struct viewer *viewer;        /* built-in viewer */
    GtkWidget *view_pic, *view_status, *btn_full, *btn_mute, *btn_vdown, *btn_vup, *vol_label, *fs_win, *fs_pic;
    gboolean muted;

    /* EAS page */
    eas_config_t cfg;
    GtkWidget *eas_tuner_grid;
    GtkWidget *e_start, *e_stop, *e_seg, *e_fmt, *e_outdir, *e_render, *e_test_min, *e_test_seg;
    GtkWidget *e_units, *e_host, *e_lead, *e_estimate;
    GtkWidget *m_runner, *m_phase, *m_window, *m_count, *m_out, *m_web, *m_msg, *m_rows, *m_log, *m_zip;
    GtkWidget *b_cancel, *b_zip, *b_open, *b_folder, *b_web;
    char zip_offered_for[1024];
    int eas_rows;
} App;

extern App A;

/* gui.c */
void gui_msg(const char *fmt, ...) G_GNUC_PRINTF(1, 2);
void gui_post_msg(const char *fmt, ...) G_GNUC_PRINTF(1, 2);      /* from worker threads */
void gui_confirm(const char *title, const char *detail, const char *yes,
                 void (*cb)(gboolean yes, gpointer data), gpointer data);
void gui_info(const char *title, const char *detail);
void gui_choose(const char *title, const char *detail, const char *const *buttons,
                int cancel_idx, int default_idx, void (*cb)(int idx, gpointer data), gpointer data);
void gui_ask_text(const char *title, const char *prompt, const char *initial,
                  void (*cb)(const char *text, gpointer data), gpointer data);
const char *gui_captures_dir(void);

/* gui_eas.c */
GtkWidget *eas_page_new(void);
void eas_page_rebuild_tuners(void);
void eas_page_tick(void);

#endif
