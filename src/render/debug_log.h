/*
 * debug_log.h - console debug output switch for RENDER
 *
 * DBG_PRINTF() prints only when debug output is on. The switch (RENDER_DEBUG,
 * "N" by default) and the -d command-line option live in a3render.c.
 *
 * g_render_debug is declared weak so that programs linking input.c, mmt.c etc.
 * without a3render.c (test harnesses, hdhomerun_tui) still link; there,
 * debug output is simply off.
 */
#ifndef DEBUG_LOG_H
#define DEBUG_LOG_H

#include <stdio.h>

#ifdef _WIN32
/* PE/COFF has no usable weak undefined symbols; on Windows render.exe always
 * links a3render.c, which defines g_render_debug. */
extern int g_render_debug;

static inline int render_debug_enabled(void) {
    return g_render_debug;
}
#else
extern int g_render_debug __attribute__((weak));

static inline int render_debug_enabled(void) {
    return &g_render_debug != NULL && g_render_debug;
}
#endif

/* An expression, like printf, so it can be used anywhere printf was. */
#define DBG_PRINTF(...) (render_debug_enabled() ? printf(__VA_ARGS__) : 0)

#endif /* DEBUG_LOG_H */
