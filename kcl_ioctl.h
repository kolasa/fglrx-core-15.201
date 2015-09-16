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

/** \brief Declarations for KCL IOCTL supporting interfaces */

#ifndef KCL_IOCTL_H
#define KCL_IOCTL_H

#include "kcl_config.h"
#include "kcl_type.h"
#include "kcl_io.h"

#ifdef __x86_64__

int ATI_API_CALL KCL_IOCTL_ReadUserSpacePointer(KCL_TYPE_U32* src,
                                                void** dst);

int ATI_API_CALL KCL_IOCTL_ReadUserSpaceU16(KCL_TYPE_U16* src,
                                            KCL_TYPE_U16* dst);

int ATI_API_CALL KCL_IOCTL_ReadUserSpaceU32(KCL_TYPE_U32* src,
                                            KCL_TYPE_U32* dst);

int ATI_API_CALL KCL_IOCTL_ReadUserSpaceU64(KCL_TYPE_U32* src,
                                            KCL_TYPE_U64* dst);

int ATI_API_CALL KCL_IOCTL_WriteUserSpacePointer(void* src,
                                                 KCL_TYPE_U32* dst);

int ATI_API_CALL KCL_IOCTL_WriteUserSpaceU16(KCL_TYPE_U16 src,
                                             KCL_TYPE_U16* dst);

int ATI_API_CALL KCL_IOCTL_WriteUserSpaceU32(KCL_TYPE_U32 src,
                                             KCL_TYPE_U32* dst);

int ATI_API_CALL KCL_IOCTL_WriteUserSpaceU64(KCL_TYPE_U64 src,
                                             KCL_TYPE_U32* dst);

int ATI_API_CALL KCL_IOCTL_ReadUserSpaceU64FromU64(KCL_TYPE_U64* src,
                                                   KCL_TYPE_U64* dst);

int ATI_API_CALL KCL_IOCTL_WriteUserSpaceU64FromU64(KCL_TYPE_U64 src,
                                                    KCL_TYPE_U64* dst);

int ATI_API_CALL KCL_IOCTL_RegisterConversion32(unsigned int cmd,
    int (*handler)(unsigned int, unsigned int, unsigned long, KCL_IO_FILE_Handle));

void ATI_API_CALL KCL_IOCTL_UnregisterConversion32(unsigned int cmd);

void* ATI_API_CALL KCL_IOCTL_AllocUserSpace32(long size);

#endif // __x86_64__

#endif
