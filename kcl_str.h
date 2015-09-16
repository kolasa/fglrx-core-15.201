/****************************************************************************
 *                                                                          *
 * Copyright 1999-2005 ATI Technologies Inc., Markham, Ontario, CANADA.     *
 * All Rights Reserved.                                                     *
 *                                                                          *
 * Your use and or redistribution of this software in source and \ or       *
 * binary form, with or without modification, is subject to: (i) your       *
 * ongoing acceptance of and compliance with the terms and conditions of    *
 * the ATI Technologies Inc. software End User License Agreement; and (ii)  *
 * your inclusion of this notice in any version of this software that you   *
 * use or redistribute.  A copy of the ATI Technologies Inc. software End   *
 * User License Agreement is included with this software and is also        *
 * available by contacting ATI Technologies Inc. at http://www.ati.com      *
 *                                                                          *
 ****************************************************************************/

/** \brief Declarations for KCL string manipulation */

#ifndef KCL_STR_H
#define KCL_STR_H

#include "kcl_config.h"
#include "kcl_type.h"

#ifdef ESX

#define FIREGL_ESX_MAX_STR_SIZE  512

void* KCL_STR_Memset(void* s,
                     int c,
                     kcl_u64 count);

void* ATI_API_CALL KCL_STR_Memcpy(void* d,
                                  const void* s,
                                  kcl_u64 count);

int ATI_API_CALL KCL_STR_Memcmp(const void* s1,
                                const void* s2,
                                kcl_u64 count);

KCL_TYPE_SizeSigned ATI_API_CALL KCL_STR_Strlen(const char* s);

char* ATI_API_CALL KCL_STR_Strncpy(char* d,
                                   const char* s,
                                   kcl_u64 count);

int ATI_API_CALL KCL_STR_Strncmp(const char* s1,
                                 const char* s2,
                                 kcl_u64 count);

int ATI_API_CALL KCL_STR_Snprintf(char* buf,
                                  kcl_u64 size,
                                  const char* fmt,
                                  ...);

#else
void* ATI_API_CALL KCL_STR_Memset(void* s,
                                  int c,
                                  KCL_TYPE_SizeSigned count);

void* ATI_API_CALL KCL_STR_Memcpy(void* d,
                                  const void* s,
                                  KCL_TYPE_SizeSigned count);

void* ATI_API_CALL KCL_STR_Memmove(void* s1,
                                   const void* s2,
                                   KCL_TYPE_SizeSigned n);

int ATI_API_CALL KCL_STR_Memcmp(const void* s1,
                                const void* s2,
                                KCL_TYPE_SizeSigned n);

KCL_TYPE_SizeSigned ATI_API_CALL KCL_STR_Strlen(const char* s);

char* ATI_API_CALL KCL_STR_Strncpy(char* d,
                                   const char* s,
                                   KCL_TYPE_SizeSigned count);

int ATI_API_CALL KCL_STR_Strncmp(const char* s1,
                                 const char* s2,
                                 KCL_TYPE_SizeSigned count);

int ATI_API_CALL KCL_STR_Snprintf(char* buf,
                                  KCL_TYPE_SizeSigned size,
                                  const char* fmt,
                                  ...);
#endif /*ifdef ESX*/

//below functions should be the same in both esx and linux
char* ATI_API_CALL KCL_STR_Strcpy(char* d, const char* s);
int ATI_API_CALL KCL_STR_Strcmp(const char* s1, const char* s2);
char* ATI_API_CALL KCL_STR_Strchr(const char *s, int c);
int ATI_API_CALL KCL_STR_Sprintf(char* buf, const char* fmt, ...);
int ATI_API_CALL KCL_STR_Strnicmp(const char* s1,
                                  const char* s2,
                                  KCL_TYPE_SizeSigned count);

#endif /*KCL_STR_H*/
