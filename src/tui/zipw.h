/*
 * Copyright (C) 2026 Brian Scott - HDHR EAS Test.
 * zipw.h - minimal ZIP64 writer (store or deflate) for HDHR EAS Test. GPLv3.
 */
#ifndef HDHR_EAS_ZIPW_H
#define HDHR_EAS_ZIPW_H

#include <stdbool.h>
#include <stddef.h>

/* Zips the files in dir that match `what` ("reports" or "full") into out_zip,
 * under a top folder named after dir. Writes to out_zip.part first. 0 = ok. */
int zipw_dir(const char *dir, const char *what, const char *out_zip, char *err, size_t errlen);

/* Which files belong in each kind of zip. */
bool zipw_wants(const char *name, const char *what);

#endif
