/*
 * Copyright (C) 2026 Brian Scott - HDHR EAS Test.
 * player.h - live viewing with ffplay (FFmpeg) for HDHR EAS Test.
 *
 * The tuner streams the chosen program as MPEG-TS over UDP to this computer
 * and ffplay plays it. ATSC 3.0 audio is Dolby AC-4, which needs an ffplay
 * built with the AC-4 decoder (tools/build_ffplay_ac4.sh). GPLv3.
 */
#ifndef HDHR_PLAYER_H
#define HDHR_PLAYER_H

#include <stdbool.h>
#include <stddef.h>
#include "plat.h"

/* ffplay next to this program first (the AC-4 build), then on the PATH. */
bool player_find(char *out, size_t n);

/* 1 = this ffplay can decode AC-4, 0 = it can't, -1 = couldn't tell. Cached per path. */
int player_has_ac4(const char *ffplay);

/* Start ffplay listening for MPEG-TS on UDP <port>. detached=false keeps it a
 * child process (the TUI waits for it); the GUI uses detached=true. */
plat_pid_t player_spawn(const char *ffplay, int port, const char *title, bool detached);

/* One line telling the user how to get an ffplay with AC-4. */
const char *player_hint(void);

#endif
