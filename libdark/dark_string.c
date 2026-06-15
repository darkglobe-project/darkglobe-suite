/*
 * dark_string.c — String utilities for DarkGlobe Suite
 *
 * securecpy, securecat, trim, unfold_header, strip_whitespace
 *
 * From DarkARC by Vittorio Moccia / ITB.it
 * Copyright (c) 2026 Vittorio Moccia / ITB.it
 * Licensed under the MIT License
 */

#include "dark_common.h"


long securecpy(register char *pc_dst, register const char *pc_src, long l_sizeof)
{
   register long i;
   if (pc_dst == NULL || l_sizeof < 1) return (0);
   if (pc_src == NULL) { pc_dst[0] = '\0'; return (0); }
   if (l_sizeof > 1)
   {
      pc_dst[0] = '\0';
      l_sizeof--;
      for (i = 0; i < l_sizeof && (pc_dst[i] = pc_src[i]) != 0; i++) continue;
      pc_dst[i] = '\0';
      return (i);
   }
   else
   {
      return (0);
   }
}

long securecat(register char *pc_dst, register const char *pc_src, long l_sizeof)
{
   register long i, j;
   if (pc_dst == NULL || l_sizeof < 1) return (0);

   for (j = 0; j < l_sizeof; j++)
      if (pc_dst[j] == 0) break;

   /* NULL source: nothing to append, leave the existing string intact */
   if (pc_src == NULL) return (j);

   if ((j + 1) == (l_sizeof))
      return (0);
   if (l_sizeof > 1)
   {
      l_sizeof--;
      for (i = 0; j < l_sizeof && (pc_dst[j] = pc_src[i]) != 0; i++, j++) continue;
      pc_dst[j] = '\0';
      return (j);
   }
   else
   {
      return (0);
   }
}

void trim(char *s)
{
   if (!s || !*s) return;
   char *start = s;
   while (isspace((unsigned char)*start)) start++;
   if (start != s) memmove(s, start, strlen(start) + 1);

   int l = strlen(s);
   while (l > 0 && isspace((unsigned char)s[l - 1]))
   {
      s[--l] = '\0';
   }
}

void unfold_header(char *h)
{
   char *src = h, *dst = h;
   while (*src)
   {
      if (*src == '\r' && *(src + 1) == '\n' && isspace((unsigned char)*(src + 2)))
      {
         src += 2;
         while (isspace((unsigned char)*src)) src++;
         *dst++ = ' ';
      }
      else if (*src == '\n' && isspace((unsigned char)*(src + 1)))
      {
         src++;
         while (isspace((unsigned char)*src)) src++;
         *dst++ = ' ';
      }
      else if (*src == '\r' && *(src + 1) == '\n')
      {
         break;
      }
      else
      {
         *dst++ = *src++;
      }
   }
   *dst = '\0';
}

void strip_whitespace(char *s)
{
   if (!s) return;
   char *r = s, *w = s;
   while (*r)
   {
      if (!isspace((unsigned char)*r))
         *w++ = *r;
      r++;
   }
   *w = '\0';
}
