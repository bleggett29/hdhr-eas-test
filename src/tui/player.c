/*
 * Copyright (C) 2026 Brian Scott - HDHR EAS Test.
 * player.c - live viewing with ffplay (FFmpeg) for HDHR EAS Test. GPLv3.
 */
#include "player.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool player_find(char *out, size_t n) {
    char dir[1024];
    if (plat_exe_dir(dir, sizeof(dir)) == 0) {
        char p[1200];
        snprintf(p, sizeof(p), "%s/ffplay%s", dir, PLAT_EXE_SUFFIX);
        if (plat_is_file(p)) { snprintf(out, n, "%s", p); return true; }
    }
    return plat_find_program("ffplay", out, n);
}

int player_has_ac4(const char *ffplay) {
    static char cached_for[1024] = "";
    static int cached = -1;
    if (cached_for[0] && strcmp(cached_for, ffplay) == 0) return cached;

    char cmd[1400];
#ifdef _WIN32
    snprintf(cmd, sizeof(cmd), "\"\"%s\" -hide_banner -decoders 2>NUL\"", ffplay);
#else
    snprintf(cmd, sizeof(cmd), "\"%s\" -hide_banner -decoders 2>/dev/null", ffplay);
#endif
    size_t cap = 512 * 1024;            /* the decoder list is long; AC-4 is after the video ones */
    char *buf = malloc(cap);
    if (!buf) return -1;
    int rc = plat_run_capture(cmd, buf, cap);
    int r;
    if (rc < 0 || !strstr(buf, "Decoders:")) r = -1;
    else r = strstr(buf, " ac4 ") ? 1 : 0;
    free(buf);
    snprintf(cached_for, sizeof(cached_for), "%s", ffplay);
    cached = r;
    return r;
}

plat_pid_t player_spawn(const char *ffplay, int port, const char *title, bool detached) {
    char url[160];
    /* fifo_size/overrun_nonfatal ride out bursts; buffer_size enlarges the socket buffer */
    snprintf(url, sizeof(url),
             "udp://0.0.0.0:%d?buffer_size=4194304&fifo_size=1000000&overrun_nonfatal=1", port);
    const char *argv[] = {
        ffplay, "-hide_banner", "-loglevel", "error",
        "-window_title", title,
        "-x", "960", "-y", "540",
        "-analyzeduration", "5000000", "-probesize", "10000000",
        "-i", url, NULL
    };
    return plat_spawn_ex(argv, NULL, false, detached, true);   /* ffplay has a window */
}

const char *player_hint(void) {
#ifdef _WIN32
    return "Rebuild with build_windows.sh (it builds ffplay with AC-4 into the program folder).";
#else
    return "Run tools/build_ffplay_ac4.sh to build ffplay with AC-4 next to the program.";
#endif
}
