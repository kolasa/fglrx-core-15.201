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

/** \brief Declarations for KCL WAIT interface */

#ifndef KCL_WAIT_H
#define KCL_WAIT_H

#include "kcl_config.h"

typedef void* KCL_WAIT_ObjectHandle;
typedef void* KCL_WAIT_Handle;

KCL_WAIT_Handle ATI_API_CALL KCL_WAIT_Add(KCL_WAIT_ObjectHandle object_handle);
#ifndef ESX
KCL_WAIT_Handle ATI_API_CALL KCL_WAIT_Add_Exclusive(KCL_WAIT_ObjectHandle object_handle);
#endif /*ifndef ESX*/

void ATI_API_CALL KCL_WAIT_Remove(KCL_WAIT_Handle wait_handle,
                                  KCL_WAIT_ObjectHandle object_handle);

void ATI_API_CALL KCL_WAIT_Wakeup(KCL_WAIT_ObjectHandle object_handle);
KCL_WAIT_ObjectHandle ATI_API_CALL KCL_WAIT_CreateObject(void);
void ATI_API_CALL KCL_WAIT_RemoveObject(KCL_WAIT_ObjectHandle wait_object);

#ifdef ESX
void ATI_API_CALL KCL_WAIT_Schedule(KCL_WAIT_Handle wait_handle);
void ATI_API_CALL KCL_WAIT_ScheduleTimeout(KCL_WAIT_Handle wait_handle, long timeout);
#endif /*ifdef ESX*/

#endif
