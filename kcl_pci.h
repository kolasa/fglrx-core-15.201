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

/** \brief KCL PCI interface declarations */

#ifndef KCL_PCI_H
#define KCL_PCI_H

#include "kcl_config.h"
#include "kcl_type.h"

#ifdef ESX 
/*
 ** The PCI interface treats multi-function devices as independent
 ** devices.  The slot/function address of each device is encoded
 ** in a single byte as follows:
 **
 **	7:3 = slot
 **	2:0 = function
 **/
#define PCI_GET_FUNC(devfn)    ((devfn) & 0x07)
#define PCI_GET_SLOT(devfn)    (((devfn) >> 3) & 0x1f)
#define PCI_ENCODE_DEVFN(slot, func)     ((((slot) & 0x1f) << 3) | ((func) & 0x07))

#define KCL_PCI_DEV_MAX_BARS        6
#define KCL_PCI_BAR_RESOURCE_IO     0x01      
#define KCL_PCI_BAR_RESOURCE_MEM_64     0x04
#define KCL_PCI_BAR_RESOURCE_PREFETCHABLE  0x08
#define  PCI_COMMAND_IO		0x1	/* Enable response in I/O space */
#define  PCI_COMMAND_MEMORY	0x2	/* Enable response in Memory space */
#define  PCI_COMMAND_MASTER	0x4	/* Enable bus mastering */

typedef enum
{
   KCL_PCI_IORESOURCE_NONE    = 0,
   KCL_PCI_IORESOURCE_UNKNOWN = 1,
   KCL_PCI_IORESOURCE_MEM     = 2,
   KCL_PCI_IORESOURCE_PORT    = 3,
}KCL_PCI_IO_Resource_type;

typedef enum
{
    KCL_PCI_ACCESS_8   = 1,
    KCL_PCI_ACCESS_16  = 2,
    KCL_PCI_ACCESS_32  = 4
}KCL_PCI_ConfigSpaceAccess;

#else  //macro used in linux driver

#define KCL_PCI_DEV_MAX_BARS        8           /** Maximum BARs(funcs) per pci device */

#ifndef IORESOURCE_MEM_64
#define IORESOURCE_MEM_64 0x00100000  // It is not defined before 2.6.30
#endif

#endif /*ifdef ESX*/

typedef void* KCL_PCI_DevHandle;

#ifndef ESX 
int ATI_API_CALL KCL_PCI_CheckBDF(
    int busnum, int devnum, int funcnum,
    KCL_TYPE_U16* vendor, KCL_TYPE_U16* device, unsigned int* irq);
unsigned int ATI_API_CALL KCL_PCI_GetIRQ(KCL_PCI_DevHandle pcidev);
#endif

KCL_PCI_DevHandle ATI_API_CALL KCL_PCI_GetDevHandle(
    KCL_TYPE_U32 bus, KCL_TYPE_U32 slot);

KCL_TYPE_U8 ATI_API_CALL KCL_PCI_GetBusNumber(KCL_PCI_DevHandle pcidev);
unsigned int ATI_API_CALL KCL_PCI_GetFunc(KCL_PCI_DevHandle pcidev);
unsigned int ATI_API_CALL KCL_PCI_GetSlot(KCL_PCI_DevHandle pcidev);
unsigned int ATI_API_CALL KCL_PCI_GetRevID(KCL_PCI_DevHandle pcidev);

int ATI_API_CALL KCL_PCI_ReadConfigByte(
    KCL_PCI_DevHandle dev, KCL_TYPE_U8 where, KCL_TYPE_U8* val_ptr);

int ATI_API_CALL KCL_PCI_ReadConfigWord(
    KCL_PCI_DevHandle dev, KCL_TYPE_U8 where, KCL_TYPE_U16* val_ptr);

int ATI_API_CALL KCL_PCI_ReadConfigDword(
    KCL_PCI_DevHandle dev, KCL_TYPE_U8 where, KCL_TYPE_U32* val_ptr);

int ATI_API_CALL KCL_PCI_WriteConfigByte(
    KCL_PCI_DevHandle dev, KCL_TYPE_U8 where, KCL_TYPE_U8 val);

int ATI_API_CALL KCL_PCI_WriteConfigWord(
    KCL_PCI_DevHandle dev, KCL_TYPE_U8 where, KCL_TYPE_U16 val);

int ATI_API_CALL KCL_PCI_WriteConfigDword(
    KCL_PCI_DevHandle dev, KCL_TYPE_U8 where, KCL_TYPE_U32 val);

#ifdef ESX
unsigned long long ATI_API_CALL KCL_PCI_BAR_GetBase(
    KCL_PCI_DevHandle dev, unsigned int res);
unsigned long long ATI_API_CALL KCL_PCI_BAR_GetSize(
    KCL_PCI_DevHandle dev, unsigned int res);
unsigned long long ATI_API_CALL KCL_PCI_BAR_GetType (
    KCL_PCI_DevHandle dev, unsigned int res);
#else
unsigned long ATI_API_CALL KCL_PCI_BAR_GetBase(
    KCL_PCI_DevHandle dev, unsigned int res);
unsigned long ATI_API_CALL KCL_PCI_BAR_GetSize(
    KCL_PCI_DevHandle dev, unsigned int res);
unsigned int ATI_API_CALL KCL_PCI_BAR_IS_IO(KCL_PCI_DevHandle dev, unsigned int res);
unsigned int ATI_API_CALL KCL_PCI_BAR_IS_MEM64(KCL_PCI_DevHandle dev, unsigned int res);
unsigned int ATI_API_CALL KCL_PCI_BAR_IS_PREFETCHABLE(KCL_PCI_DevHandle dev, unsigned int res);
#endif /*ifdef ESX*/

#ifdef ESX
int ATI_API_CALL KCL_PCI_MAP_IO_Res (int moduleID,
                                     KCL_PCI_DevHandle dev,
                                     unsigned char pciBar,
                                     unsigned long long *mappedAddress);
int ATI_API_CALL KCL_PCI_UNMAP_IO_Res (int moduleID,
                                       KCL_PCI_DevHandle dev,
                                       unsigned char pciBar);
int ATI_API_CALL KCL_PCI_RESERVE_IO_Res (unsigned long long start, unsigned long long size, void** handle, unsigned int resource_type);

int ATI_API_CALL KCL_PCI_RELEASE_IO_Res (void* handle);
#endif /*ifdef ESX*/

int ATI_API_CALL KCL_PCI_EnableDevice(KCL_PCI_DevHandle dev);
void ATI_API_CALL KCL_PCI_PrePowerUp(KCL_PCI_DevHandle dev);
void ATI_API_CALL KCL_PCI_PostPowerUp(KCL_PCI_DevHandle dev);
void ATI_API_CALL KCL_PCI_EnableBusMastering(KCL_PCI_DevHandle dev);

#ifndef ESX
void ATI_API_CALL KCL_PCI_EnableBars(KCL_PCI_DevHandle dev);
void ATI_API_CALL KCL_PCI_DisableDevice(KCL_PCI_DevHandle dev);

#if defined(__x86_64__)
void* ATI_API_CALL KCL_PCI_AllocDmaCoherentMem(
    KCL_PCI_DevHandle dev, int size, unsigned long long* dma_handle);

void ATI_API_CALL KCL_PCI_FreeDmaCoherentMem(
    KCL_PCI_DevHandle dev, int size, void* cpu_addr,
    unsigned long long dma_handle);
#endif //__x86_64__
#endif /*ifndef ESX*/

#endif
