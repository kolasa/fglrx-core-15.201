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

/** \brief KCL general purpose type declarations */

#ifndef KCL_TYPE_H
#define KCL_TYPE_H

typedef unsigned long       KCL_TYPE_DevMajorMinor;
typedef unsigned long       KCL_TYPE_Offset;
typedef unsigned char       KCL_TYPE_U8;
typedef unsigned short      KCL_TYPE_U16;
typedef unsigned int        KCL_TYPE_U32;
typedef unsigned long long  KCL_TYPE_U64;
typedef unsigned long long  KCL_TYPE_DmaAddr;
typedef long long           KCL_TYPE_FileOffset;

#ifdef __x86_64__
typedef long                KCL_TYPE_SizeSigned;
typedef unsigned long       KCL_TYPE_SizeUnsigned;
#else
typedef int                 KCL_TYPE_SizeSigned;
typedef unsigned int        KCL_TYPE_SizeUnsigned;
#endif

/*****************************************************************************/
typedef long         kcl_off_t;
#ifdef __x86_64__
typedef long  kcl_ssize_t;
typedef unsigned long kcl_size_t;
#else
typedef int kcl_ssize_t;
typedef unsigned int kcl_size_t;
#endif
typedef unsigned char kcl_u8;
typedef unsigned short kcl_u16;
typedef unsigned int kcl_u32;
typedef unsigned long long kcl_u64;
typedef unsigned long long kcl_dma_addr_t;
typedef long long kcl_loff_t;

/****************************************************************************/
//void* pointer defines
#ifndef ESX
typedef void* KCL_SEMA_Handle;
#endif
typedef void* KCL_NOTIFIER_BLOCKER;

#endif
