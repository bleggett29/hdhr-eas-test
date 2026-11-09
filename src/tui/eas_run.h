/*
 * Copyright (C) 2026 Brian Scott - HDHR EAS Test.
 * eas_run.h - EAS capture scheduling: saved setup, the run itself (pause
 * other tuner users, record, resume, render), and the background runner the
 * TUI launches for Test Run / Arm.
 *
 * Part of the EAS edition of HDHomeRun TUI. GPLv3, same as the TUI.
 */
#ifndef EAS_RUN_H
#define EAS_RUN_H

#include <stdbool.h>
#include <sys/types.h>
#include <time.h>

#define EAS_MAX_TUNERS 32

typedef struct {
    char devid[16];       /* "10A85A62" - used to find the device if its IP changes */
    char ip[64];
    int tuner;
    char chan[48];        /* "27", "31p0", "31p0p1"                                 */
} eas_cfg_tuner_t;

typedef struct {
    eas_cfg_tuner_t tuners[EAS_MAX_TUNERS];
    int ntuners;
    char start[32];       /* "YYYY-MM-DD HH:MM" local time */
    char stop[32];
    int seg;              /* segment seconds                */
    int fmt3;             /* 1 = ALP-PCAP, 2 = debug        */
    char outdir[512];
    char pause_units[512];
    char pause_ssh[128];  /* "" = this machine              */
    int pause_lead;       /* seconds before start           */
    int auto_render;      /* render + summary when done     */
    int test_minutes;
    int test_seg;
} eas_config_t;

/* What the background runner is doing, read back from its state file. */
#define EAS_STATE_MAX_ROWS 32
typedef struct {
    bool present;         /* a state file exists           */
    bool alive;           /* the runner process is running */
    long pid;
    char mode[16];        /* test | armed                  */
    char phase[32];       /* starting waiting pausing recording rendering done cancelled failed */
    char message[256];
    time_t start, stop, updated;
    char outdir[512];
    char summary[600];
    char web[600];        /* URL of the report on the built-in web server */
    int nrows;
    char rows[EAS_STATE_MAX_ROWS][256];   /* "label|chan|state|segs|MB|signal|msg" */
} eas_state_t;

const char *eas_config_dir(void);
void eas_config_defaults(eas_config_t *c);
int  eas_config_load(eas_config_t *c);            /* 0 = loaded, 1 = defaults used */
int  eas_config_save(const eas_config_t *c);
eas_cfg_tuner_t *eas_config_find(eas_config_t *c, const char *devid, const char *ip, int tuner);
eas_cfg_tuner_t *eas_config_add(eas_config_t *c, const char *devid, const char *ip, int tuner);
int  eas_config_active_count(const eas_config_t *c);

int  eas_parse_when(const char *s, time_t *out);

/* Checks an armed/test run can start; fills err on failure. */
int  eas_config_validate(const eas_config_t *c, bool test, char *err, size_t errlen);
/* Rough size of a run in GB, and free space where it would go (-1 if unknown). */
void eas_config_estimate(const eas_config_t *c, bool test, double *need_gb, double *free_gb);

/* Launch / talk to the background runner. */
int  eas_launch_background(const char *mode, bool pause_services, char *err, size_t errlen);   /* "test" | "armed" */
void eas_state_read(eas_state_t *st);
int  eas_cancel_running(void);
int  eas_detect_units(char *out, size_t n);       /* running systemd units that use an HDHomeRun */
int  eas_find_render(char *out, size_t n);

/* Results web server (python3 -m http.server), runs in the background. */
void eas_expand_home(const char *in, char *out, size_t n);
int  eas_lan_ip(char *out, size_t n);
int  eas_web_status(int *port, char *dir, size_t dirlen);   /* pid if running, else 0 */
/* Serves `base` (or the summary's own folder if it isn't under base) and
 * fills url with a link to `summary` (or to the folder if summary is ""). */
int  eas_web_serve(const char *base, const char *summary, char *url, size_t n, char *err, size_t errlen);
void eas_web_stop(void);

/* Zip a finished run folder in the background.
 * what: "reports" = ATSC 3.0 HTML reports + logs, "full" = everything (pcap, ts, ...). */
int  eas_zip_start(const char *rundir, const char *what, char *zip_path, size_t n, char *err, size_t errlen);
/* 0 = no zip, 1 = being made (bytes so far in *size), 2 = ready (*size) */
int  eas_zip_status(const char *rundir, const char *what, char *zip_path, size_t n, long long *size);
long long eas_dir_bytes(const char *dir, const char *what);

/* Entry points called from main() before ncurses starts. */
int  eas_headless_main(int argc, char **argv);    /* --eas  (command-line use, optional)   */
int  eas_daemon_main(int argc, char **argv);      /* --eas-daemon (internal, TUI launches) */
int  eas_zip_main(int argc, char **argv);         /* --eas-zip    (internal, background zip) */

#endif
