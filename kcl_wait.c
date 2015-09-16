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

/** \brief KCL WAIT interface implementation
 *
 * CONVENTIONS
 *
 * Public symbols:
 * - prefixed with KCL_WAIT
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
#include <linux/wait.h>
#include <linux/highmem.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include "kcl_config.h"
#include "kcl_wait.h"

/** \brief Create wait object, init it and add to the kernel queue
 ** \param object_handle [in] Object handle
 ** \return Kernel wait handle on success, 0 otherwise
 */
KCL_WAIT_Handle ATI_API_CALL KCL_WAIT_Add(KCL_WAIT_ObjectHandle object_handle)
{
    wait_queue_t* wait_handle = kmalloc(sizeof(wait_queue_t), GFP_KERNEL);

    if (!wait_handle)
    {
        return 0;
    }

    init_waitqueue_entry(wait_handle, current);
    add_wait_queue((wait_queue_head_t*)object_handle, wait_handle);

    return (KCL_WAIT_Handle)wait_handle;
}

/** \brief Create wait object, init it and add to the kernel queue
 ** \param object_handle [in] Object handle
 ** \return Kernel wait handle on success, 0 otherwise
 */
KCL_WAIT_Handle ATI_API_CALL KCL_WAIT_Add_Exclusive(KCL_WAIT_ObjectHandle object_handle)
{
    wait_queue_t* wait_handle = kmalloc(sizeof(wait_queue_t), GFP_KERNEL);

    if (!wait_handle)
    {
        return 0;
    }

    init_waitqueue_entry(wait_handle, current);
    add_wait_queue_exclusive((wait_queue_head_t*)object_handle, wait_handle);

    return (KCL_WAIT_Handle)wait_handle;
}

/** \brief Remove wait object from the kernel queue and destroy it
 ** \param wait_handle [in] Kernel wait handle
 ** \param object_handle [in] Object handle
 */
void ATI_API_CALL KCL_WAIT_Remove(KCL_WAIT_Handle wait_handle,
                                  KCL_WAIT_ObjectHandle object_handle)
{
    remove_wait_queue((wait_queue_head_t*)object_handle,
                      (wait_queue_t*)wait_handle);

    if (wait_handle)
    {
        kfree(wait_handle);
    }
}

/** \brief Send wake up signal to the wait object
 ** \param object_handle [in] Object handle
 */
void ATI_API_CALL KCL_WAIT_Wakeup(KCL_WAIT_ObjectHandle object_handle)
{
    wake_up_interruptible((wait_queue_head_t*)object_handle);
}

/** \brief Create and init user wait object
 ** \return Object handle
 */
KCL_WAIT_ObjectHandle ATI_API_CALL KCL_WAIT_CreateObject(void)
{
    wait_queue_head_t* wait_object = kmalloc(sizeof(wait_queue_head_t), GFP_ATOMIC);

    if (wait_object)
    {
        init_waitqueue_head(wait_object);
    }

    return (KCL_WAIT_ObjectHandle)wait_object;
}

/** \brief Destroy user wait object
 ** \return Object handle
 */
void ATI_API_CALL KCL_WAIT_RemoveObject(KCL_WAIT_ObjectHandle wait_object)
{
    if (wait_object)
    {
        kfree(wait_object);
    }
}

