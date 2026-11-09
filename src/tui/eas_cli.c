/*
 * Copyright (C) 2026 Brian Scott - HDHR EAS Test.
 * eas_cli.c - console entry point for HDHR EAS Test's background modes.
 * The GUI starts this program's modes itself; it's also handy for scripting.
 * GPLv3.
 */
#include <stdio.h>
#include <string.h>
#include "eas_run.h"
#include "plat.h"

int main(int argc, char **argv) {
    plat_init();
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--eas-daemon")) return eas_daemon_main(argc, argv);
        if (!strcmp(argv[i], "--eas-zip")) return eas_zip_main(argc, argv);
        if (!strcmp(argv[i], "--eas")) return eas_headless_main(argc, argv);
    }
    printf("HDHR EAS Test v0.5 - command line. Copyright (C) 2026 Brian Scott. GPLv3.\n");
    printf("  %s --eas --help    record from the command line\n", argv[0]);
    printf("Most people use the GUI (hdhr_eas_test.exe on Windows, hdhr_eas_test_gui on Linux) or the Linux TUI (hdhr_eas_test).\n");
    return 0;
}
