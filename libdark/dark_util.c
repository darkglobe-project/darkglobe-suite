/*
 * dark_util.c — Timing utilities for DarkGlobe Suite
 *
 * format_runtime
 *
 * Copyright (c) 2026 Vittorio Moccia / ITB.it
 * Licensed under the MIT License
 */

#include "dark_common.h"


void format_runtime(unsigned long long total_ns, char *dest, size_t destlen)
{
   double ms = (double)total_ns / 1000000.0;
   if (ms < 1000.0)
      snprintf(dest, destlen, "%.2fms", ms);
   else
      snprintf(dest, destlen, "%.2fs", ms / 1000.0);
}
