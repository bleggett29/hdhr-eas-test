/*
 * progress.h - minimal console progress feedback for long-running phases
 *
 *   progress_t p;
 *   progress_begin(&p, "Reading STLTP capture", total_bytes);
 *   ... progress_update(&p, bytes_done); ...   // redraws at most 5x/second; callers
 *                                               // should call it every few hundred packets
 *   progress_end(&p);                           // "Reading STLTP capture... done (12.3 s)"
 *
 * On a terminal the line updates in place with a percentage. When stdout is
 * redirected (log file, pipe) only the start and "done" lines are written.
 * With debug output on (RENDER_DEBUG / -d) progress is suppressed, since the
 * debug messages already show activity and would garble an in-place line.
 * Call progress_clear() before printing a normal message mid-phase.
 */
#ifndef PROGRESS_H
#define PROGRESS_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "debug_log.h"

typedef struct {
    const char *label;
    uint64_t total;          // 0 = unknown (no percentage)
    int active;              // progress output enabled for this phase
    int tty;                 // stdout is a terminal: update in place
    int drawn;               // an in-place line is currently on screen
    int last_pct;
    double start, last_draw;
} progress_t;

static inline double progress_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static inline void progress_draw(progress_t *p, int pct) {
    if (pct >= 0) printf("\r%s... %3d%%", p->label, pct);
    else          printf("\r%s...", p->label);
    fflush(stdout);
    p->drawn = 1;
}

static inline void progress_begin(progress_t *p, const char *label, uint64_t total) {
    memset(p, 0, sizeof(*p));
    p->label = label;
    p->total = total;
    p->active = !render_debug_enabled();
    p->tty = isatty(fileno(stdout));
    p->last_pct = -1;
    p->start = p->last_draw = progress_now();
    if (!p->active) return;
    if (p->tty) {
        progress_draw(p, total ? 0 : -1);
    } else {
        printf("%s...\n", label);
        fflush(stdout);
    }
}

static inline void progress_update(progress_t *p, uint64_t done) {
    if (!p->active || !p->tty || !p->total) return;
    double now = progress_now();
    if (now - p->last_draw < 0.2) return;
    int pct = (int)(done >= p->total ? 100 : done * 100 / p->total);
    if (pct == p->last_pct && p->drawn) return;
    p->last_pct = pct;
    p->last_draw = now;
    progress_draw(p, pct);
}

/* Erase the in-place line so a normal message can be printed; the next update redraws it. */
static inline void progress_clear(progress_t *p) {
    if (!p->active || !p->tty || !p->drawn) return;
    printf("\r%*s\r", (int)strlen(p->label) + 9, "");
    p->drawn = 0;
    p->last_pct = -1;
}

static inline void progress_end(progress_t *p) {
    if (!p->active) return;
    double secs = progress_now() - p->start;
    progress_clear(p);
    printf("%s... done (%.1f s)\n", p->label, secs);
    fflush(stdout);
    p->active = 0;
}

#endif /* PROGRESS_H */
