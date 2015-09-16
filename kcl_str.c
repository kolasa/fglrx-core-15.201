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

/** \brief Implementation of KCL string manipulation
 *
 * CONVENTIONS
 *
 * Public symbols:
 * - prefixed with KCL_STR
 * - are not static
 * - declared in the corresponding header
 *
 * Private symbols:
 * - prefixed with kcl
 * - are static
 * - not declared in the corresponding header
 *
 */
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
#include <generated/autoconf.h>
#else
#include <linux/autoconf.h>
#endif
#include <linux/string.h>
#include <linux/module.h>

#include "kcl_config.h"
#include "kcl_type.h"
#include "kcl_str.h"

/** \brief Fill memory with a constant byte
 *  \param s Pointer to memory
 *  \param c Initializing value
 *  \param count Number of bytes to initialize
 *  \return Pointer to initialized memory
 */
void* ATI_API_CALL KCL_STR_Memset(void* s,
                                  int c,
                                  KCL_TYPE_SizeSigned count)
{
    return memset(s, c, count);
}


/** \brief Copy memory area. The memory areas may not overlap
 *  \param d Pointer to destination
 *  \param s Pointer to source
 *  \param count Number of bytes to copy
 *  \return Pointer to destination
 */
void* ATI_API_CALL KCL_STR_Memcpy(void* d,
                                  const void* s,
                                  KCL_TYPE_SizeSigned count)
{
    return memcpy(d, s, count);
}

/** \brief Copy memory area. The memory areas may overlap
 *  \param d Pointer to destination
 *  \param s Pointer to source
 *  \param count Number of bytes to copy
 *  \return Pointer to destination
 */
void* ATI_API_CALL KCL_STR_Memmove(void* d,
                                   const void* s,
                                   KCL_TYPE_SizeSigned count)
{
    return memmove(d, s, count);
}

/** \brief Compare memory areas
 *  \param s1 Pointer to first memory area
 *  \param s2 Pointer to second memory area
 *  \param count Number of bytes to compare
 *  \return Negative if first count bytes of s1 less than first count bytes of s2
 *  \return Zero if first count bytes of s1 equal to first count bytes of s2
 *  \return Positive if first count bytes of s1 greater than first count bytes of s2
 */
int ATI_API_CALL KCL_STR_Memcmp(const void* s1,
                                const void* s2,
                                KCL_TYPE_SizeSigned count)
{
    return memcmp(s1, s2, count);
}

/** \brief Get length of zero-ended string
 *  \param s Pointer to the string
 *  \return String length (not including zero character)
 */
KCL_TYPE_SizeSigned ATI_API_CALL KCL_STR_Strlen(const char* s)
{
    return strlen(s);
}

/** \brief Copy zero-ended string
 *  \param d Pointer to destination
 *  \param s Pointer to source
 *  \return Pointer to destination
 */
char* ATI_API_CALL KCL_STR_Strcpy(char* d, const char* s)
{
    return strcpy(d, s);
}

/** \brief Copy zero-ended string with maximum length restriction
 *  \param d Pointer to destination
 *  \param s Pointer to source
 *  \param count Number of bytes to copy
 *  \return Pointer to destination
 */
char* ATI_API_CALL KCL_STR_Strncpy(char* d,
                                   const char* s,
                                   KCL_TYPE_SizeSigned count)
{
    return strncpy(d, s, count);
}

/** \brief Compare two zero-ended strings
 *  \param s1 Pointer to first string
 *  \param s2 Pointer to second string
 *  \return Negative if s1 less than s2
 *  \return Zero if s1 equal to s2
 *  \return Positive if s1 greater than s2
 */
int ATI_API_CALL KCL_STR_Strcmp(const char* s1, const char* s2)
{
    return strcmp(s1, s2);
}

/** \brief Compare two zero-ended strings with maximum length restriction
 *  \param s1 Pointer to first string
 *  \param s2 Pointer to second string
 *  \param count Maximum number of bytes to copy
 *  \return Negative if s1 less than s2
 *  \return Zero if s1 equal to s2
 *  \return Positive if s1 greater than s2
 */
int ATI_API_CALL KCL_STR_Strncmp(const char* s1,
                                 const char* s2,
                                 KCL_TYPE_SizeSigned count)
{
    return strncmp(s1, s2, count);
}

/** \brief Compare two zero-ended strings with maximum length restriction,
 *  \brief case insensitive
 *  \param s1 Pointer to first string
 *  \param s2 Pointer to second string
 *  \param count Maximum number of bytes to copy
 *  \return Negative if s1 less than s2
 *  \return Zero if s1 equal to s2
 *  \return Positive if s1 greater than s2
 */
int ATI_API_CALL KCL_STR_Strnicmp(const char* s1,
                                  const char* s2,
                                  KCL_TYPE_SizeSigned count)
{
    return strnicmp(s1, s2, count);
}

/** \brief Locate character in string
 *  \param s Pointer to the string
 *  \param c Character to locate
 *  \return Pointer to the first matched character or NULL if character not found
 */
char* ATI_API_CALL KCL_STR_Strchr(const char *s, int c)
{
    return strchr(s, c);
}

/** \brief Do formatted output to string
 *  \param buf Pointer to the output buffer
 *  \param fmt Formatting string
 *  \return Number of character printed or negative on error
 */
int ATI_API_CALL KCL_STR_Sprintf(char* buf, const char* fmt, ...)
{
    va_list marker;

    va_start(marker, fmt);
    vsprintf(buf, fmt, marker);
    va_end(marker);

    return strlen(buf);
}

/** \brief Do formatted output to string with maximum length restriction
 *  \param buf Pointer to the output buffer
 *  \param size Buffer size
 *  \param fmt Formatting string
 *  \return Number of character printed or negative on error
 */
int ATI_API_CALL KCL_STR_Snprintf(char* buf,
                                  KCL_TYPE_SizeSigned size,
                                  const char* fmt,
                                  ...)
{
    va_list marker;

    va_start(marker, fmt);
    vsnprintf(buf, size, fmt, marker);
    va_end(marker);

    return strlen(buf);
}

/* FIXME: these are temporary workarounds to support code using old naming convention */
int ATI_API_CALL kcl_sprintf(char* buf, const char* fmt, ...)
{
    va_list marker;

    va_start(marker, fmt);
    vsprintf(buf, fmt, marker);
    va_end(marker);

    return strlen(buf);
}

int ATI_API_CALL kcl_snprintf(char* buf,
                               size_t size,
                               const char* fmt,
                               ...)
{
    va_list marker;

    va_start(marker, fmt);
    vsnprintf(buf, size, fmt, marker);
    va_end(marker);

    return strlen(buf);
}
/* End of FIXME */
