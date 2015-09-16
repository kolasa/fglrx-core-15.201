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

/** \brief Implementation of KCL I/O interfaces
 *
 * Support for the following interfaces:
 * - file operations
 * - file asynchronious i/o
 * - device i/o memory mapping
 * - port i/o
 *
 * CONVENTIONS
 *
 * Public symbols:
 * - prefixed with KCL_IO
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
#include <linux/poll.h>
#include <linux/signal.h>
#include <asm/io.h>

#include "kcl_config.h"
#include "kcl_io.h"
#include "kcl_wait.h"

/** \brief Get pointer to private file data
 ** \param filp [in] File handle
 ** \return Pointer to private file data
 */
void* ATI_API_CALL KCL_IO_FILE_GetPrivateData(KCL_IO_FILE_Handle filp)
{
    return ((struct file*)filp)->private_data;
}

/** \brief Set pointer to private file data
 ** \param filp [in] File handle
 ** \param private_data [in] Pointer to private file data
 */
void ATI_API_CALL KCL_IO_FILE_SetPrivateData(KCL_IO_FILE_Handle filp, void* private_data)
{
    ((struct file*)filp)->private_data = private_data;
}

/** \brief Check whether file opened exclusively
 ** \param filp [in] File handle
 ** \return nonzero if file opened exclusively, zero otherwise
 */
int ATI_API_CALL KCL_IO_FILE_OpenedExclusively(KCL_IO_FILE_Handle filp)
{
    return (((struct file*)filp)->f_flags & O_EXCL) != 0;
}

/** \brief Check whether file opened for read/write
 ** \param filp [in] File handle
 ** \return nonzero if file opened for read/write, zero otherwise
 */
int ATI_API_CALL KCL_IO_FILE_OpenedForReadWrite(KCL_IO_FILE_Handle filp)
{
    return (((struct file*)filp)->f_flags & 3) != 0;
}

/** \brief Perform poll operation on file
 ** \param filp [in] File handle
 ** \param queue_head [in] Wait queue associated with file
 ** \param pt [in] Poll table handle
 ** \return TBD
 */
void ATI_API_CALL KCL_IO_FILE_PollWait(
    KCL_IO_FILE_Handle filp,
    KCL_WAIT_ObjectHandle wait_object,
    KCL_IO_FILE_PollTableHandle pt)
{
    poll_wait((struct file*)filp,
              (wait_queue_head_t*)wait_object,
              (struct poll_table_struct*)pt);
}

/** \brief Setup file asynchronous i/o queue
 ** \param fd [in] File descriptor
 ** \param filp [in] File handle
 ** \param mode [in] Mode
 ** \param pasync_queue [in] Pointer to the queue handle
 ** \return negative on error, 0 if it did no changes and positive on successive changes
 */
int ATI_API_CALL KCL_IO_FASYNC_SetupAsyncQueue(
    int fd, KCL_IO_FILE_Handle filp, int mode,
    KCL_IO_FASYNC_QueueHandle* pasync_queue)
{
    return fasync_helper(
                fd, (struct file*)filp, mode,
                (struct fasync_struct**)pasync_queue);
}

/** \brief Terminate file asynchronous i/o queue
 ** \param pasync_queue [in] Pointer to the queue handle
 */
void ATI_API_CALL KCL_IO_FASYNC_Terminate(
    KCL_IO_FASYNC_QueueHandle* pasync_queue)
{
    kill_fasync ((struct fasync_struct**)pasync_queue, SIGIO, POLLIN);
}

/** \brief Map device i/o mem to be used by CPU
 ** \param offset [in] Physical address of the device i/o memory
 ** \param size [in] Number of bytes to map
 ** \param type [in] one of the KCL_IOREMAPTYPE_xxx types
 ** \return Logical address (not guaranteed to be virtual)
 */
void* ATI_API_CALL KCL_IO_MEM_Map(unsigned long long offset,
                                  unsigned long size,
                                  int type)
{
    switch (type)
    {
    case KCL_IOREMAPTYPE_WriteCombine:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
        return ioremap_wc(offset, size);
#endif

    case KCL_IOREMAPTYPE_NoCache:
        return ioremap_nocache(offset, size);

    case KCL_IOREMAPTYPE_Default:
    default:
        return ioremap(offset, size);
    }
}

/** \brief Unmap device i/o mem
 ** \return pt Logical address
 */
void ATI_API_CALL KCL_IO_MEM_Unmap(void* pt)
{
    iounmap(pt);
}

void ATI_API_CALL KCL_IO_PORT_WriteByte(unsigned char value, unsigned short port)
{
    outb(value, port);
}

/** \brief Write dword (4 bytes) to port
 ** \param value [in] Value to write
 ** \param port [in] Port number
 */
void ATI_API_CALL KCL_IO_PORT_WriteDword(unsigned int value, unsigned short port)
{
    outl(value, port);
}

/** \brief Read byte from port
 ** \param port [in] Port number
 ** \return Read value
 */
char ATI_API_CALL KCL_IO_PORT_ReadByte(unsigned short port)
{
    return inb(port);
}

/** \brief Read dword (4 bytes) from port
 ** \param port [in] Port number
 ** \return Read value
 */
unsigned int ATI_API_CALL KCL_IO_PORT_ReadDword(unsigned short port)
{
    return inl(port);
}

void ATI_API_CALL KCL_IO_MEM_CopyToIO(void *dst, void *src, size_t count)
{
    memcpy_toio(dst, src, count);
}
