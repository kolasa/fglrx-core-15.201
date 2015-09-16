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

/** \brief Declarations for KCL I/O interfaces */

#ifndef KCL_IO_H
#define KCL_IO_H

#include "kcl_config.h"
#include "kcl_wait.h"

typedef void* KCL_IO_FILE_Handle;
typedef void* KCL_IO_FILE_PollTableHandle;
typedef void* KCL_IO_FASYNC_QueueHandle;

void* ATI_API_CALL KCL_IO_FILE_GetPrivateData(KCL_IO_FILE_Handle filp);

void ATI_API_CALL KCL_IO_FILE_SetPrivateData(KCL_IO_FILE_Handle filp,
                                             void* private_data);

int ATI_API_CALL KCL_IO_FILE_OpenedExclusively(KCL_IO_FILE_Handle filp);
int ATI_API_CALL KCL_IO_FILE_OpenedForReadWrite(KCL_IO_FILE_Handle filp);

#ifndef ESX
void ATI_API_CALL KCL_IO_FILE_PollWait(KCL_IO_FILE_Handle filp,
                                       KCL_WAIT_ObjectHandle wait_object,
                                       KCL_IO_FILE_PollTableHandle pt);

int ATI_API_CALL KCL_IO_FASYNC_SetupAsyncQueue(
    int fd, KCL_IO_FILE_Handle filp, int mode,
    KCL_IO_FASYNC_QueueHandle* pasync_queue);

void ATI_API_CALL KCL_IO_FASYNC_Terminate(
    KCL_IO_FASYNC_QueueHandle* pasync_queue);
#endif /*ifndef ESX*/

#define KCL_IOREMAPTYPE_Default         0
#define KCL_IOREMAPTYPE_NoCache         1
#define KCL_IOREMAPTYPE_WriteCombine    2

#ifdef ESX
void* ATI_API_CALL KCL_IO_MEM_Map(void* vmkdev,
                                  void* pciDevHandle,
                                  unsigned long long offset,
                                  unsigned long size,
                                  int type, 
                                  void** ioResHandle,
                                  void** ioReservation);

void ATI_API_CALL KCL_IO_MEM_Unmap(void* vmkdev, void* pciDevHandle, void* pt, void* ioResHandle, void* ioReservation);
void ATI_API_CALL KCL_IO_PORT_WriteByte(void* ioPortReservation, unsigned char value, unsigned short port);
void ATI_API_CALL KCL_IO_PORT_WriteDword(void* ioPortReservation, unsigned int value, unsigned short port);
char ATI_API_CALL KCL_IO_PORT_ReadByte(void* ioPortReservation, unsigned short port);
unsigned int ATI_API_CALL KCL_IO_PORT_ReadDword(void* ioPortReservation, unsigned short port);
#else
void* ATI_API_CALL KCL_IO_MEM_Map(unsigned long long offset,
                                  unsigned long size,
                                  int type);

void ATI_API_CALL KCL_IO_MEM_Unmap(void* pt);
void ATI_API_CALL KCL_IO_PORT_WriteByte(unsigned char value,
                                        unsigned short port);

void ATI_API_CALL KCL_IO_PORT_WriteDword(unsigned int value,
                                         unsigned short port);

char ATI_API_CALL KCL_IO_PORT_ReadByte(unsigned short port);
unsigned int ATI_API_CALL KCL_IO_PORT_ReadDword(unsigned short port);
void ATI_API_CALL KCL_IO_MEM_CopyToIO(void *dst, void *src, size_t count);
#endif /*ifdef ESX*/

#endif /*KCL_IO_H*/
