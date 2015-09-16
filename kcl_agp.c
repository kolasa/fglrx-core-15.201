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

/** \brief KCL AGP interface implementation
 *
 * CONVENTIONS
 *
 * Public symbols:
 * - prefixed with KCL_AGP
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
#include <linux/pci.h>
#include <linux/agp_backend.h>
#include <linux/string.h>
#include <asm-generic/errno-base.h>

#include "kcl_config.h"
#include "kcl_type.h"
#include "kcl_agp.h"
#include "kcl_debug.h"

static unsigned int kcl_agp_is_in_use = 0;

/** \brief Return AGP use status
 ** \return 0 if AGP is not in use, nonzero otherwise
 */
unsigned int KCL_AGP_IsInUse(void)
{
    return kcl_agp_is_in_use;
}

#if defined(CONFIG_AGP) || defined(CONFIG_AGP_MODULE)

typedef struct {
    void              (*free_memory)(struct agp_memory*);
    struct agp_memory*(*allocate_memory)(size_t, u32);
    int               (*bind_memory)(struct agp_memory*, off_t);
    int               (*unbind_memory)(struct agp_memory*);
    void              (*enable)(u32);
    int               (*acquire)(void);
    void              (*release)(void);
    int               (*copy_info)(struct agp_kern_info*);
} kcl_agp_callbacks_t;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)

/* In Linux >= 2.6.12, due to support for multiple AGP bridges, some
 * AGP functions need a pointer to the AGP bridge. KCL_AGP_Acquire
 * stores a pointer to the pci device in a global
 * variable. kcl_agp_wrap_backend_acquire below uses it to retrieve
 * the pointer to the bridge and stores it in the global variable
 * kcl_agp_bridge. All AGP functions that need the bridge pointer
 * are wrapped here and get the global bridge pointer. */

static struct agp_bridge_data* kcl_agp_bridge = NULL;
static struct pci_dev* kcl_pci_device = NULL;

static struct agp_memory* kcl_agp_wrap_allocate_memory(size_t pg_count, u32 type)
{
    return agp_allocate_memory(kcl_agp_bridge, pg_count, type);
}

static void kcl_agp_wrap_enable(u32 mode)
{
    agp_enable(kcl_agp_bridge, mode);
}

static int kcl_agp_wrap_backend_acquire(void)
{
    kcl_agp_bridge = agp_backend_acquire(kcl_pci_device);
    return kcl_agp_bridge != NULL ? 0 : -EBUSY;
}

static void kcl_agp_wrap_backend_release(void)
{
    agp_backend_release(kcl_agp_bridge);
    kcl_agp_bridge = NULL;
}

static int kcl_agp_wrap_copy_info(struct agp_kern_info* kinfo)
{
    return agp_copy_info(kcl_agp_bridge, kinfo);
}

static const kcl_agp_callbacks_t kcl_agp_callbacks =
{
    &agp_free_memory,
    &kcl_agp_wrap_allocate_memory,
    &agp_bind_memory,
    &agp_unbind_memory,
    &kcl_agp_wrap_enable,
    &kcl_agp_wrap_backend_acquire,
    &kcl_agp_wrap_backend_release,
    &kcl_agp_wrap_copy_info
};

#else // == 2.6.11

static const kcl_agp_callbacks_t kcl_agp_callbacks = {
    &agp_free_memory,
    &agp_allocate_memory,
    &agp_bind_memory,
    &agp_unbind_memory,
    &agp_enable,
    &agp_backend_acquire,
    &agp_backend_release,
    &agp_copy_info
};

#endif // >= 2.6.12

#else // < 2.6.11

static const kcl_agp_callbacks_t kcl_agp_callbacks = {
    &agp_free_memory,
    &agp_allocate_memory,
    &agp_bind_memory,
    &agp_unbind_memory,
    &agp_enable,
    &agp_backend_acquire,
    &agp_backend_release,
    &agp_copy_info
};

#endif // >= 2.6.11

// Continue compilation with defined(CONFIG_AGP) || defined(CONFIG_AGP_MODULE)
// No kernel version dependencies

static const kcl_agp_callbacks_t* kcl_agp_callbacks_ptr = NULL;

#define AGP_AVAILABLE(func) (kcl_agp_callbacks_ptr && kcl_agp_callbacks_ptr-> func )
#define AGP_FUNC(func) (*kcl_agp_callbacks_ptr-> func )
// note: avoid ##-tokens with latest GCC (i.e. RedHat 7.1 beta)

/** \brief Check whether AGP is available
 ** \param pcidev PCI device handle
 ** \return 1 if AGP has been acqured successfully, 0 othewise
 */
int ATI_API_CALL KCL_AGP_Available(KCL_PCI_DevHandle pcidev)
{
    kcl_agp_is_in_use = 1;
    kcl_agp_callbacks_ptr = &kcl_agp_callbacks;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)
    kcl_pci_device = (struct pci_dev*)pcidev;
#endif
    if (AGP_FUNC(acquire)() == 0)
    {
        AGP_FUNC(release)();
        return 1; /* success */
    }

    KCL_DEBUG1(FN_FIREGL_INIT, "AGP/GART kernel module present but API is incomplete\n");
    KCL_AGP_Uninit();

    return 0; /* failed */
}

/** \brief Mark AGP as uninitialized
 */
void ATI_API_CALL KCL_AGP_Uninit(void)
{
    kcl_agp_is_in_use = 0;
    kcl_agp_callbacks_ptr = NULL;
}

/** \brief Allocate AGP memory
 ** \param pages Number of pages
 ** \param type Memory type
 ** \return Handle to the allocated memory on success or NULL on fail
 */
KCL_AGP_MemHandle ATI_API_CALL KCL_AGP_AllocateMemory(KCL_TYPE_SizeUnsigned pages, unsigned long type)
{
    if (AGP_AVAILABLE(allocate_memory))
    {
        return (KCL_AGP_MemHandle)AGP_FUNC(allocate_memory)(pages, type);
    }
    else
    {
        return NULL;
    }
}

/** \brief Free AGP memory
 ** \param handle Handle to the allocated memory
 */
void ATI_API_CALL KCL_AGP_FreeMemory(KCL_AGP_MemHandle handle)
{
    if (AGP_AVAILABLE(free_memory))
    {
        AGP_FUNC(free_memory)((struct agp_memory*)handle);
    }
}

/** \brief Bind AGP memory to an offset
 ** \param handle Memory handle
 ** \param start Offset
 ** \return Zero on success, nonzero on fail
 */
int ATI_API_CALL KCL_AGP_BindMemory(KCL_AGP_MemHandle handle, KCL_TYPE_Offset start)
{
    if (AGP_AVAILABLE(bind_memory))
    {
        return AGP_FUNC(bind_memory)((struct agp_memory*)handle, start);
    }
    else
    {
        return -EINVAL;
    }
}

/** \brief Unbind AGP memory
 ** \param handle Memory handle
 ** \return Zero on success, nonzero on fail
 */
int ATI_API_CALL KCL_AGP_UnbindMemory(KCL_AGP_MemHandle handle)
{
    if (AGP_AVAILABLE(unbind_memory))
    {
        return AGP_FUNC(unbind_memory)((struct agp_memory*)handle);
    }
    else
    {
        return -EINVAL;
    }
}

/** \brief Enable AGP
 ** \param mode Mode
 ** \return Zero on success, nonzero on fail
 */
int ATI_API_CALL KCL_AGP_Enable(unsigned long mode)
{
    if (AGP_AVAILABLE(enable))
    {
        AGP_FUNC(enable)(mode);
        return 0;
    }
    else
    {
        return -EINVAL;
    }
}

/** \brief Find AGP caps registers in PCI config space
 ** \param dev PCI device handle
 ** \return Positive register index on success, negative errno on error
 */
int ATI_API_CALL KCL_AGP_FindCapsRegisters(KCL_PCI_DevHandle dev)
{
    u8 capndx;
    u32 cap_id;

    if (!dev)
    {
        return -ENODEV;
    }

    pci_read_config_byte((struct pci_dev*)dev, 0x34, &capndx);

    if (capndx == 0x00)
    {
        return -ENODATA;
    }

    do
    { // search capability list for AGP caps
        pci_read_config_dword((struct pci_dev*)dev, capndx, &cap_id);

        if ((cap_id & 0xff) == 0x02)
        {
            return capndx;
        }

        capndx = (cap_id >> 8) & 0xff;
    }
    while (capndx != 0x00);

    return -ENODATA;
}

/** \brief Get AGP caps
 ** \param dev PCI device handle
 ** \param caps pointer to caps vector
 ** \return Zero on success, nonzero on fail
 */
int ATI_API_CALL KCL_AGP_ReadCapsRegisters(KCL_PCI_DevHandle dev, unsigned int* caps)
{
    int capndx;

    if (!caps)
    {
        return -EINVAL;
    }

    if (!dev)
    {
        return -ENODEV;
    }

    if ((capndx = KCL_AGP_FindCapsRegisters(dev)) < 0)
    {
        return capndx;
    }
    else
    {
        pci_read_config_dword((struct pci_dev*)dev, capndx + 0, &(caps[0])); /* AGP CAPPTR */
        pci_read_config_dword((struct pci_dev*)dev, capndx + 4, &(caps[1])); /* AGP STATUS */
        pci_read_config_dword((struct pci_dev*)dev, capndx + 8, &(caps[2])); /* AGP COMMAND */

        return 0; /* success */
    }
}

/** \brief Acquire AGP
 ** \param dev PCI device handle
 ** \return Zero on success, nonzero on fail
 */
int ATI_API_CALL KCL_AGP_Acquire(KCL_PCI_DevHandle dev)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)
    kcl_pci_device = (struct pci_dev*)dev;
#endif
    if (AGP_AVAILABLE(acquire))
    {
        return AGP_FUNC(acquire)();
    }
    else
    {
        return -EINVAL;
    }
}

/** \brief Release AGP
 */
void ATI_API_CALL KCL_AGP_Release(void)
{
    if (AGP_AVAILABLE(release))
    {
        AGP_FUNC(release)();
    }
}

/** \brief Get AGP info from the OS kernel
 ** \param info Pointer to the info structure
 */
void ATI_API_CALL KCL_AGP_CopyInfo(KCL_AGP_KernInfo* info)
{
    struct pci_dev *device = NULL;

    memset(info, 0, sizeof(KCL_AGP_KernInfo));

    if (AGP_AVAILABLE(copy_info))
    {
        struct agp_kern_info kern;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)
        if (kcl_agp_bridge == NULL)
        {
            AGP_FUNC(acquire)();
            AGP_FUNC(copy_info)(&kern);
            AGP_FUNC(release)();
        }
        else
#endif
        {
            AGP_FUNC(copy_info)(&kern);
        }

        info->pcidev = device = kern.device;

        info->version.major = kern.version.major;
        info->version.minor = kern.version.minor;

        if (kern.device)
        {
            info->vendor = kern.device->vendor;
            info->device = kern.device->device;
        }

        info->mode = kern.mode;
        info->aper_base = kern.aper_base;
        info->aper_size = kern.aper_size;
        info->max_memory = kern.max_memory;
        info->current_memory = kern.current_memory;
        info->cant_use_aperture = kern.cant_use_aperture;
        info->page_mask = kern.page_mask;
    }

    /* FGL_FIX: some chipset drivers do not read the mode member from hardware */
    if (device)
    {
        if (!info->mode)
        {
            u8 capptr = pci_find_capability(device, PCI_CAP_ID_AGP);

            if (capptr)
            {
                u32 tmp;
                pci_read_config_dword(device,
                                      capptr + PCI_AGP_STATUS, &tmp);

                info->mode = tmp; /* note: unsigned int (32/64) = u32; */
            }
        }
    }
}

/** \brief Get number of pages occupied by AGP memory chunk
 ** \param handle AGP memory handle
 ** \return Number of pages
 */
unsigned long ATI_API_CALL KCL_AGP_GetMemoryPageCount(KCL_AGP_MemHandle handle)
{
    return ((struct agp_memory*)handle)->page_count;
}

#else // !defined(CONFIG_AGP) && !defined(CONFIG_AGP_MODULE)

int ATI_API_CALL KCL_AGP_Available(KCL_PCI_DevHandle pcidev)
{
    return 0;
}

void ATI_API_CALL KCL_AGP_Uninit(void)
{}


void ATI_API_CALL KCL_AGP_FreeMemory(KCL_AGP_MemHandle handle)
{}

KCL_AGP_MemHandle ATI_API_CALL KCL_AGP_AllocateMemory(KCL_TYPE_SizeUnsigned pages, unsigned long type)
{
    return NULL;
}

int ATI_API_CALL KCL_AGP_BindMemory(KCL_AGP_MemHandle handle, KCL_TYPE_Offset start)
{
    return -EINVAL;
}

int ATI_API_CALL KCL_AGP_UnbindMemory(KCL_AGP_MemHandle handle)
{
    return -EINVAL;
}

int ATI_API_CALL KCL_AGP_Enable(unsigned long mode)
{
    return -EINVAL;
}

int ATI_API_CALL KCL_AGP_ReadCapsRegisters(KCL_PCI_DevHandle dev, unsigned int *caps)
{
    return -EINVAL;
}

int ATI_API_CALL KCL_AGP_Acquire(KCL_PCI_DevHandle dev)
{
    return -EINVAL;
}

void ATI_API_CALL KCL_AGP_Release(void)
{}

void ATI_API_CALL KCL_AGP_CopyInfo(KCL_AGP_KernInfo* info)
{}

unsigned long ATI_API_CALL KCL_AGP_GetMemoryPageCount(KCL_AGP_MemHandle handle)
{
    return 0;
}

#endif //defined(CONFIG_AGP) || defined(CONFIG_AGP_MODULE)
