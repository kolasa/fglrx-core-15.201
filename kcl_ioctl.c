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

/** \brief Implementation of KCL IOCTL supporting interfaces
 *
 * CONVENTIONS
 *
 * Public symbols:
 * - prefixed with KCL_IOCTL
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
#include <asm/uaccess.h>

#ifdef __x86_64__
#   include "asm/compat.h"
#   if LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,0)
    DEFINE_PER_CPU(unsigned long, old_rsp);
#   endif
#   if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
#       if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)
#           include "linux/ioctl32.h"
#       else
#           include "asm/ioctl32.h"
#       endif
#   endif
#endif

#include "kcl_config.h"
#include "kcl_osconfig.h"
#include "kcl_type.h"
#include "kcl_ioctl.h"
#include "kcl_io.h"

#ifdef __x86_64__

/** \brief Read pointer from 32-bit user space to 64-bit kernel space
 *  \param [in] src Pointer to source
 *  \param [out] dst Pointer to destination
 *  \return Zero on success, nonzero on error
 */
int ATI_API_CALL KCL_IOCTL_ReadUserSpacePointer(KCL_TYPE_U32* src,
                                                void** dst)
{
    unsigned long temp;
    int err = get_user(temp, src);
    *dst = (void*) temp;
    return err;
}

/** \brief Read 16-bit data from 32-bit user space to 64-bit kernel space
 *  \param [in] src Pointer to source
 *  \param [out] dst Pointer to destination
 *  \return Zero on success, nonzero on error
 */
int ATI_API_CALL KCL_IOCTL_ReadUserSpaceU16(KCL_TYPE_U16* src,
                                             KCL_TYPE_U16* dst)
{
    u16 temp;
    int err = get_user(temp, src);
    *dst = temp;
    return err;
}

/** \brief Read 32-bit data from 32-bit user space to 64-bit kernel space
 *  \param [in] src Pointer to source
 *  \param [out] dst Pointer to destination
 *  \return Zero on success, nonzero on error
 */
int ATI_API_CALL KCL_IOCTL_ReadUserSpaceU32(KCL_TYPE_U32* src,
                                             KCL_TYPE_U32* dst)
{
    u32 temp;
    int err = get_user(temp, src);
    *dst = temp;
    return err;
}

/** \brief Read 64-bit data from 32-bit user space to 64-bit kernel space
 *  \param [in] src Pointer to source
 *  \param [out] dst Pointer to destination
 *  \return Zero on success, nonzero on error
 */
int ATI_API_CALL KCL_IOCTL_ReadUserSpaceU64(KCL_TYPE_U32* src,
                                             KCL_TYPE_U64* dst)
{
    u64 temp;
    int err = get_user(temp, src);
    *dst = temp;
    return err;
}

/** \brief Read 64-bit data from 64-bit user space to 64-bit kernel space
 *  \param [in] src Pointer to source
 *  \param [out] dst Pointer to destination
 *  \return Zero on success, nonzero on error
 */
int ATI_API_CALL KCL_IOCTL_ReadUserSpaceU64FromU64(KCL_TYPE_U64* src,
                                                   KCL_TYPE_U64* dst)
{
    u64 temp;
    int err = get_user(temp, src);
    *dst = temp;
    return err;
}

/** \brief Write pointer from 64-bit kernel space to 32-bit user space
 *  \param [in] src Source data
 *  \param [out] dst Pointer to destination
 *  \return Zero on success, nonzero on error
 */
int ATI_API_CALL KCL_IOCTL_WriteUserSpacePointer(void* src,
                                                 KCL_TYPE_U32* dst)
{
    unsigned long temp = (unsigned long)src;
    return put_user(temp, dst);
}

/** \brief Write 16-bit data from 64-bit kernel space to 32-bit user space
 *  \param [in] src Source data
 *  \param [out] dst Pointer to destination
 *  \return Zero on success, nonzero on error
 */
int ATI_API_CALL KCL_IOCTL_WriteUserSpaceU16(KCL_TYPE_U16 src,
                                              KCL_TYPE_U16* dst)
{
    u16 temp = src;
    return put_user(temp, dst);
}

/** \brief Write 32-bit data from 64-bit kernel space to 32-bit user space
 *  \param [in] src Source data
 *  \param [out] dst Pointer to destination
 *  \return Zero on success, nonzero on error
 */
int ATI_API_CALL KCL_IOCTL_WriteUserSpaceU32(KCL_TYPE_U32 src,
                                              KCL_TYPE_U32* dst)
{
    u32 temp = src;
    return put_user(temp, dst);
}

/** \brief Write 64-bit data from 64-bit kernel space to 32-bit user space
 *  \param src [in] Source data
 *  \param dst [out] Pointer to destination
 *  \return Zero on success, nonzero on error
 */
int ATI_API_CALL KCL_IOCTL_WriteUserSpaceU64(KCL_TYPE_U64 src,
                                              KCL_TYPE_U32* dst)
{
    u64 temp = src;
    return put_user(temp, dst);
}

/** \brief Write 64-bit data from 64-bit kernel space to 64-bit user space
 *  \param src [in] Source data
 *  \param dst [out] Pointer to destination
 *  \return Zero on success, nonzero on error
 */
int ATI_API_CALL KCL_IOCTL_WriteUserSpaceU64FromU64(KCL_TYPE_U64 src,
                                                    KCL_TYPE_U64* dst)
{
    u64 temp = src;
    return put_user(temp, dst);
}

/** \brief Register 32-on-64 IOCTL conversion
 *  \param cmd [in] IOCTL ID
 *  \param handler [in] IOCTL handler
 *  \return Zero on error, nonzero on success
 */
int ATI_API_CALL KCL_IOCTL_RegisterConversion32(
        unsigned int cmd,
        int (*handler)(unsigned int,
                       unsigned int,
                       unsigned long,
                       KCL_IO_FILE_Handle))
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
    return 0;
#else
    return register_ioctl32_conversion(cmd, (ioctl_trans_handler_t)handler);
#endif
}

/** \brief Unregister 32-on-64 IOCTL conversion
 *  \param cmd [in] IOCTL ID
 */
void ATI_API_CALL KCL_IOCTL_UnregisterConversion32(unsigned int cmd)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
    return;
#else
    unregister_ioctl32_conversion(cmd);
#endif
}

/** \brief Allocate user space for 32-bit app making 64-bit IOCTL
 *  \param size [in] Number of bytes to allocate
 *  \return Pointer to allocated memory
 */
void* ATI_API_CALL KCL_IOCTL_AllocUserSpace32(long size)
{
    void __user *ret = COMPAT_ALLOC_USER_SPACE(size);

    /* prevent stack overflow */
    if (!access_ok(VERIFY_WRITE, ret, size))
        return NULL;

    return (void *)ret;
}

#endif // __x86_64__
