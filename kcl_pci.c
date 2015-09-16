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

/** \brief KCL PCI interface implementation
 *
 * CONVENTIONS
 *
 * Public symbols:
 * - prefixed with KCL_PCI
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

#include "kcl_config.h"
#include "kcl_type.h"
#include "kcl_pci.h"

/** \brief Return info about PCI device at specified BDF
 * Check presence of a PCI device at the specified (bus,device,function) triad
 * and return vendor ID, device ID and IRQ number for this device
 * (if corresponding pointers are provided by the caller)
 ** \param busnum [in] PCI bus number
 ** \param devnum [in] PCI device number
 ** \param funcnum [in] PCI function number
 ** \param vendor [out] Pointer to PCI vendor ID
 ** \param device [out] Pointer to PCI device ID
 ** \param irq [out] Pointer to PCI IRQ number
 ** \return 0 if the device is not found, 1 otherwise
 */
int ATI_API_CALL KCL_PCI_CheckBDF(
    int busnum, int devnum, int funcnum,
    KCL_TYPE_U16* vendor, KCL_TYPE_U16* device, unsigned int* irq)
{
    struct pci_dev* pci_dev;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23)
    pci_dev = pci_get_bus_and_slot(busnum, PCI_DEVFN(devnum, funcnum));
#else
    pci_dev = pci_find_slot(busnum, PCI_DEVFN(devnum, funcnum));
#endif

    if (!pci_dev)
    {
        return 0;
    }

    if (vendor)
    {
        *vendor = pci_dev->vendor;
    }

    if (device)
    {
        *device = pci_dev->device;
    }

    if (irq)
    {
        *irq = pci_dev->irq;
    }

    return 1;
}

/** \brief Get PCI device handle
 ** \param bus [in] PCI bus
 ** \param slot [in] PCI slot
 ** \return PCI device handle
 */
KCL_PCI_DevHandle ATI_API_CALL KCL_PCI_GetDevHandle(
    KCL_TYPE_U32 bus, KCL_TYPE_U32 slot)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23)
    return (KCL_PCI_DevHandle)pci_get_bus_and_slot(bus, slot);
#else
    return (KCL_PCI_DevHandle)pci_find_slot(bus, slot);
#endif
}

/** \brief Get PCI device bus number
 ** \param pcidev [in] PCI device handle
 ** \return PCI device bus number
 */
KCL_TYPE_U8 ATI_API_CALL KCL_PCI_GetBusNumber(KCL_PCI_DevHandle pcidev)
{
    struct pci_dev* dev = (struct pci_dev*)pcidev;
    return dev->bus->number;
}

/** \brief Get PCI device function number
 ** \param pcidev [in] PCI device handle
 ** \return PCI device function number
 */
unsigned int ATI_API_CALL KCL_PCI_GetFunc(KCL_PCI_DevHandle pcidev)
{
    struct pci_dev* dev = (struct pci_dev*)pcidev;
    return PCI_FUNC(dev->devfn);
}

/** \brief Get PCI device IRQ number
 ** \param pcidev [in] PCI device handle
 ** \return PCI device IRQ number
 */
unsigned int ATI_API_CALL KCL_PCI_GetIRQ(KCL_PCI_DevHandle pcidev)
{
    struct pci_dev* dev = (struct pci_dev*)pcidev;
    return dev->irq;
}

/** \brief Get PCI device slot number
 ** \param pcidev [in] PCI device handle
 ** \return PCI device slot number
 */
unsigned int ATI_API_CALL KCL_PCI_GetSlot(KCL_PCI_DevHandle pcidev)
{
    struct pci_dev* dev = (struct pci_dev*)pcidev;
    return PCI_SLOT(dev->devfn);
}

unsigned int ATI_API_CALL KCL_PCI_GetRevID(KCL_PCI_DevHandle pcidev)
{
    struct pci_dev* dev = (struct pci_dev*)pcidev;
    return dev->revision;
}

/** \brief Read byte from PCI config space
 ** \param pcidev [in] PCI device handle
 ** \param where [in] PCI register
 ** \param val_ptr [out] Pointer to where to save register value
 ** \return TBD
 */
int ATI_API_CALL KCL_PCI_ReadConfigByte(
    KCL_PCI_DevHandle dev, KCL_TYPE_U8 where, KCL_TYPE_U8* val_ptr)
{
    return pci_read_config_byte((struct pci_dev*)dev, where, val_ptr);
}
/** \brief Read 2-byte word from PCI config space
 ** \param pcidev [in] PCI device handle
 ** \param where [in] PCI register
 ** \param val_ptr [out] Pointer to where to save register value
 ** \return TBD
 */
int ATI_API_CALL KCL_PCI_ReadConfigWord(
    KCL_PCI_DevHandle dev, KCL_TYPE_U8 where, KCL_TYPE_U16* val_ptr)
{
    return pci_read_config_word((struct pci_dev*)dev, where, val_ptr);
}

/** \brief Read 4-byte dword from PCI config space
 ** \param pcidev [in] PCI device handle
 ** \param where [in] PCI register
 ** \param val_ptr [out] Pointer to where to save register value
 ** \return TBD
 */
int ATI_API_CALL KCL_PCI_ReadConfigDword(
    KCL_PCI_DevHandle dev, KCL_TYPE_U8 where, KCL_TYPE_U32* val_ptr)
{
    return pci_read_config_dword((struct pci_dev*)dev, where, val_ptr);
}

/** \brief Write byte to PCI config space
 ** \param pcidev [in] PCI device handle
 ** \param where [in] PCI register
 ** \param val [in] Value to write
 ** \return TBD
 */
int ATI_API_CALL KCL_PCI_WriteConfigByte(
    KCL_PCI_DevHandle dev, KCL_TYPE_U8 where, KCL_TYPE_U8 val)
{
    return pci_write_config_byte((struct pci_dev*)dev, where, val);
}

/** \brief Write 2-byte word to PCI config space
 ** \param pcidev [in] PCI device handle
 ** \param where [in] PCI register
 ** \param val [in] Value to write
 ** \return TBD
 */
int ATI_API_CALL KCL_PCI_WriteConfigWord(
    KCL_PCI_DevHandle dev, KCL_TYPE_U8 where, KCL_TYPE_U16 val)
{
    return pci_write_config_word((struct pci_dev*)dev, where, val);
}

/** \brief Write 4-byte dword to PCI config space
 ** \param pcidev [in] PCI device handle
 ** \param where [in] PCI register
 ** \param val [in] Value to write
 ** \return TBD
 */
int ATI_API_CALL KCL_PCI_WriteConfigDword(
    KCL_PCI_DevHandle dev, KCL_TYPE_U8 where, KCL_TYPE_U32 val)
{
    return pci_write_config_dword((struct pci_dev*)dev, where, val);
}

/** \brief Get base address of specified PCI BAR
 ** \param dev [in] PCI device handle
 ** \param res [in] PCI BAR index
 ** \return Base address of specified PCI BAR
 */
unsigned long ATI_API_CALL KCL_PCI_BAR_GetBase(
    KCL_PCI_DevHandle dev, unsigned int res)
{
    return pci_resource_start((struct pci_dev*)dev, res);
}

/** \brief Get address range of specified PCI BAR
 ** \param dev [in] PCI device handle
 ** \param res [in] PCI BAR index
 ** \return Address range of specified PCI BAR
 */
unsigned long ATI_API_CALL KCL_PCI_BAR_GetSize(
    KCL_PCI_DevHandle dev, unsigned int res)
{
    return pci_resource_len((struct pci_dev*)dev, res);
}

/** \brief Check if it is IO BAR
 ** \param dev [in] PCI device handle
 ** \param res [in] PCI BAR index
 ** \return non-zero for IO BAR
 */
unsigned int ATI_API_CALL KCL_PCI_BAR_IS_IO(
    KCL_PCI_DevHandle dev, unsigned int res)
{
    return pci_resource_flags((struct pci_dev*)dev, res) & IORESOURCE_IO;
}

/** \brief Check if it is 64bit MEM BAR
 ** \param dev [in] PCI device handle
 ** \param res [in] PCI BAR index
 ** \return non-zero for 64bit BAR
 */
unsigned int ATI_API_CALL KCL_PCI_BAR_IS_MEM64(
    KCL_PCI_DevHandle dev, unsigned int res)
{
    return pci_resource_flags((struct pci_dev*)dev, res) & IORESOURCE_MEM_64;
}

/** \brief Check if it is prefetchable
 ** \param dev [in] PCI device handle
 ** \param res [in] PCI BAR index
 ** \return non-zero for prefetchable
 */
unsigned int ATI_API_CALL KCL_PCI_BAR_IS_PREFETCHABLE(
    KCL_PCI_DevHandle dev, unsigned int res)
{
    return pci_resource_flags((struct pci_dev*)dev, res) & IORESOURCE_PREFETCH;
}

/** \brief Enable PCI device
 ** \param dev [in] PCI device handle
 ** \return 0 on success, nonzero otherwise
 */
int ATI_API_CALL KCL_PCI_EnableDevice(KCL_PCI_DevHandle dev)
{
    return (pci_enable_device((struct pci_dev*)dev));
}

/** \brief pre Power up PCI device operations
 ** \param dev [in] PCI device handle
 */
void ATI_API_CALL KCL_PCI_PrePowerUp(KCL_PCI_DevHandle dev)
{
    struct pci_dev * pci_dev = (struct pci_dev *)dev;
    struct pci_dev * bridge = pci_dev->bus->self;
    u16 reg16;
    int pos=0;

    pos = pci_find_capability(bridge, 0x10); /*PCI_CAP_ID_EXP*/
    if(pos)
    {
        pci_read_config_word(bridge, pos+16, &reg16); /*PCI_EXP_LNKCTL */
        if(reg16 & 0x0010) /* Link Disable */
        {
            reg16 &= ~0x0010;
            pci_write_config_word(bridge, pos+16, reg16);
        }

        pci_read_config_word(bridge, pos + 2, &reg16); /*PCI_EXP_FLAGS*/
        if((reg16 & 0x000f) > 1) /* check pcie Capability version */
        {
            pci_read_config_word(bridge, pos+40, &reg16); /* Device Control 2 */
            if(!(reg16&0x0400))/* Enable LTR mechanism */
            {
                reg16 |= 0x0400;
                pci_write_config_word(bridge, pos+40, reg16);
            }
        }
    }
    pci_set_power_state(pci_dev, PCI_D0);
}

/** \brief post Power up PCI device operations
 ** \param dev [in] PCI device handle
 */
void ATI_API_CALL KCL_PCI_PostPowerUp(KCL_PCI_DevHandle dev)
{
    struct pci_dev * pci_dev = (struct pci_dev *)dev;
    if(pci_enable_device(pci_dev) == 0)
    {
        pci_set_master(pci_dev);
    }
}
/** \brief Tell OS to enable bus mastering for the specified PCI device
 ** \param dev [in] PCI device handle
 */
void ATI_API_CALL KCL_PCI_EnableBusMastering(KCL_PCI_DevHandle dev)
{
    pci_set_master((struct pci_dev*)dev);
}

/** \brief Tell PCI device to enable I/O space, memory space and bus mastering
 ** \param dev [in] PCI device handle
 */
void ATI_API_CALL KCL_PCI_EnableBars(KCL_PCI_DevHandle dev)
{
    u16 cmd;
    pci_read_config_word((struct pci_dev*)dev, PCI_COMMAND, &cmd);
    cmd |= (PCI_COMMAND_IO | PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);
    pci_write_config_word((struct pci_dev*)dev, PCI_COMMAND, cmd);
}

/** \brief Disable PCI device
 ** \param dev [in] PCI device handle
 */
void ATI_API_CALL KCL_PCI_DisableDevice(KCL_PCI_DevHandle dev)
{
    // 2.6.20 ealier kernels don't like the driver doing this repeatedly.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
    struct pci_dev * pci_dev = (struct pci_dev *)dev;
    if(pci_is_enabled(pci_dev))
        pci_disable_device(pci_dev);
#endif
}

#if defined(__x86_64__)
/** \brief Allocate DMA coherent memory
 ** \param dev [in] PCI device handle
 ** \param size [in] Memory size
 ** \param dma_handle_ptr [out] Pointer to the physical (DMA) address for the allocated memory
 ** \return Virtual address of the allocated memory
 */
void* ATI_API_CALL KCL_PCI_AllocDmaCoherentMem(
    KCL_PCI_DevHandle dev, int size, unsigned long long* dma_handle_ptr)
{
    return (pci_alloc_consistent((struct pci_dev*)dev, size, dma_handle_ptr));
}

/** \brief Free DMA coherent memory
 ** \param dev [in] PCI device handle
 ** \param size [in] Memory size
 ** \param cpu_addr [in] Virtual memory address
 ** \param dma_handle [in] Physical (DMA) memory address
 */
void ATI_API_CALL KCL_PCI_FreeDmaCoherentMem(
    KCL_PCI_DevHandle dev, int size, void* cpu_addr, unsigned long long dma_handle)
{
    pci_free_consistent((struct pci_dev*)dev, size, cpu_addr, dma_handle);
}
#endif //__x86_64__

