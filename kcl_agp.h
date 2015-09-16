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

/** \brief KCL AGP interface declarations */

#ifndef KCL_AGP_H
#define KCL_AGP_H

#include "kcl_config.h"
#include "kcl_type.h"
#include "kcl_pci.h"

typedef void* KCL_AGP_MemHandle;

typedef struct
{
    KCL_TYPE_U16 major;
    KCL_TYPE_U16 minor;
} KCL_AGP_Version;

typedef struct
{
    KCL_AGP_Version version;
    KCL_PCI_DevHandle pcidev;
    KCL_TYPE_U16 vendor;
    KCL_TYPE_U16 device;
    unsigned long mode;
    KCL_TYPE_Offset aper_base;
    KCL_TYPE_SizeUnsigned aper_size;
    int max_memory; /* In pages */
    int current_memory;
    int cant_use_aperture;
    unsigned long page_mask;
} KCL_AGP_KernInfo;

unsigned int KCL_AGP_IsInUse(void);
int ATI_API_CALL KCL_AGP_Available(KCL_PCI_DevHandle pcidev);
void ATI_API_CALL KCL_AGP_Uninit(void);
KCL_AGP_MemHandle ATI_API_CALL KCL_AGP_AllocateMemory(KCL_TYPE_SizeUnsigned pages, unsigned long type);
void ATI_API_CALL KCL_AGP_FreeMemory(KCL_AGP_MemHandle handle);
int ATI_API_CALL KCL_AGP_BindMemory(KCL_AGP_MemHandle handle, KCL_TYPE_Offset start);
int ATI_API_CALL KCL_AGP_UnbindMemory(KCL_AGP_MemHandle handle);
int ATI_API_CALL KCL_AGP_Enable(unsigned long mode);
int ATI_API_CALL KCL_AGP_FindCapsRegisters(KCL_PCI_DevHandle dev);
int ATI_API_CALL KCL_AGP_ReadCapsRegisters(KCL_PCI_DevHandle dev, unsigned int* caps);
int ATI_API_CALL KCL_AGP_Acquire(KCL_PCI_DevHandle dev);
void ATI_API_CALL KCL_AGP_Release(void);
void ATI_API_CALL KCL_AGP_CopyInfo(KCL_AGP_KernInfo* info);
unsigned long ATI_API_CALL KCL_AGP_GetMemoryPageCount(KCL_AGP_MemHandle handle);

#endif
