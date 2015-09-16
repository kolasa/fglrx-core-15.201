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

#ifdef __KERNEL__

#ifndef MODULE
!!! This is not currently supported,
!!! since it requires changes to linux/init/main.c.
#endif /* !MODULE */

// ============================================================
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0) 
#error Kernel versions older than 2.6.0 are no longer supported by this module.
#endif 

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
#include <generated/autoconf.h>
#else
#include <linux/autoconf.h>
#endif

#if !defined(CONFIG_X86) 
#if !defined(CONFIG_X86_PC) 
#if !defined(CONFIG_X86_XEN) 
#if !defined(CONFIG_X86_64)
#if !defined(CONFIG_X86_VOYAGER)
#if !defined(CONFIG_X86_NUMAQ)
#if !defined(CONFIG_X86_SUMMIT)
#if !defined(CONFIG_X86_BIGSMP)
#if !defined(CONFIG_X86_VISWS)
#if !defined(CONFIG_X86_GENERICARCH)
#error unknown or undefined architecture configured
#endif
#endif
#endif
#endif
#endif
#endif
#endif
#endif
#endif
#endif

/* The dirty-page-tracking patch included in NLD 9 SMP kernels defines
 * a static inline function that uses a GPL-only symbol in a header
 * file. Therefore any non-GPL module built against such a kernel
 * configuration is broken and cannot be loaded. We work around that
 * problem by disabling the respective kernel configuration option for
 * our module build.
 *
 * This will break page tracking when this kernel module is
 * used. However, on a standard system page tracking is disabled
 * anyways. It is only activated and used by specific in-kernel agents
 * for example for CPU hot-plugging. I wonder why a desktop
 * distribution would even include such a kernel patch. */
#ifdef CONFIG_MEM_MIRROR
/* Prevent asm/mm_track.h from being included in subsequent
 * kernel headers as that would redefine CONFIG_MEM_MIRROR. */ 
#ifndef CONFIG_X86_64
#define __I386_MMTRACK_H__
#define mm_track(ptep)                 
#else
#define __X86_64_MMTRACK_H__
#define mm_track_pte(ptep)
#define mm_track_pmd(ptep)
#define mm_track_pgd(ptep)
#define mm_track_pml4(ptep)
#define mm_track_phys(x)
#endif
#warning "Disabling CONFIG_MEM_MIRROR because it does not work with non-GPL modules."
#warning "This will break page tracking when the fglrx kernel module is used."
#undef CONFIG_MEM_MIRROR
#endif /* CONFIG_MEM_MIRROR */

/* To avoid compatibility issues with old kernels, only use DMA API 
   for kernels configured to support hardware IOMMU in NB chipset.
   Note, AMD and Intel have differnt iommu drivers in different loacations 
   and they use different config options. These options can only be enabled
   on x86_64 with newer 2.6 kernels (2.6.23 for intel, 2.6.26 for amd). 
*/
#if defined(CONFIG_AMD_IOMMU) || defined(CONFIG_DMAR)
    #define FIREGL_DMA_REMAPPING
#endif

// ============================================================

// always defined
#define __AGP__BUILTIN__

//#define FGL_USE_SCT /* for developer use only */
// ============================================================

#include <asm/unistd.h> /* for installing the patch wrapper */
#include <linux/module.h>
#include <linux/device.h>

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/pci.h>
#include <linux/wait.h>
#include <linux/miscdevice.h>
// newer SuSE kernels need this
#include <linux/highmem.h>

#include <linux/vmalloc.h>

#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/console.h>
#include <linux/random.h>

#include <linux/timex.h>
#include <linux/kthread.h>
#include <linux/err.h>
#include <asm/io.h>
#include <asm/mman.h>
#include <asm/uaccess.h>
#include <asm/processor.h>
#include <asm/tlbflush.h> // for flush_tlb_page
#include <asm/cpufeature.h>
#ifdef CONFIG_MTRR
#include <asm/mtrr.h>
#endif
#ifdef CONFIG_EFI
#include <linux/efi.h>
#endif
#include <linux/screen_info.h>
#include <asm/delay.h>
#include <linux/agp_backend.h>

#ifndef EXPORT_NO_SYMBOLS
#define EXPORT_NO_SYMBOLS
#endif

#include <linux/poll.h>   /* for poll() */
#include <asm/poll.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
#ifdef __x86_64__
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)
#include "linux/ioctl32.h"
#else
#include "asm/ioctl32.h"
#endif
#endif

#ifdef __x86_64__
#include "asm/compat.h"
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
#include "linux/freezer.h"
#endif

//  For 2.6.18 or higher, the UTS_RELEASE is defined in the linux/utsrelease.h. 
#ifndef UTS_RELEASE 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
#include <generated/utsrelease.h>
#else
#include <linux/utsrelease.h>
#endif
#endif

#if defined(__i386__)
#ifndef do_div
#include "asm/div64.h"
#endif
#endif

#include <linux/kmod.h>
#include <linux/sysrq.h>
#include <linux/string.h>
#include <linux/gfp.h>
#include <linux/swap.h>
#include "asm/i387.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,0)
#include <asm/fpu-internal.h>
#endif

#include "firegl_public.h"
#include "kcl_osconfig.h"
#include "kcl_io.h"
#include "kcl_debug.h"

// ============================================================

// VM_SHM is deleted in 2.6.18 or higher kernels.
#ifndef VM_SHM
#define VM_SHM 0
#endif

#ifdef FGL_LINUX253P1_VMA_API
// Linux 2.5.3-pre1 and compatibles
#define FGL_VMA_API_TYPE        struct vm_area_struct *
#define FGL_VMA_API_NAME        vma
#define FGL_VMA_API_PROTO       FGL_VMA_API_TYPE FGL_VMA_API_NAME,
#define FGL_VMA_API_PASS        FGL_VMA_API_NAME,
#else /* FGL_253P1_VMA_API */
// Linux 2.4.0 and compatibles
#define FGL_VMA_API_TYPE        /* none */
#define FGL_VMA_API_NAME        /* none */
#define FGL_VMA_API_PROTO       /* none */
#define FGL_VMA_API_PASS        /* none */
#endif /* FGL_253P1_VMA_API */

#ifndef preempt_disable
#define preempt_disable()
#define preempt_enable()
#endif

// VM_RESERVED is removed from 3.7.0
#ifndef VM_RESERVED
#define VM_RESERVED             VM_DONTEXPAND | VM_DONTDUMP
#endif

// ============================================================

#if defined(__get_cpu_var)
#define GET_CPU_VAR(var) __get_cpu_var(var)
#else
#define GET_CPU_VAR(var) (*this_cpu_ptr(&(var)))
#endif

// read_cr4() and write_cr4() has changed from 4.0.0, 3.18.17
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0) || ((LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)) && (LINUX_VERSION_CODE > KERNEL_VERSION(3,18,16)))
#define READ_CR4()      __read_cr4()
#define WRITE_CR4(x)    __write_cr4(x)
#else
#define READ_CR4()      read_cr4()
#define WRITE_CR4(x)    write_cr4(x)
#endif

// ============================================================
/* globals */

char* firegl = NULL;

static struct pci_device_id fglrx_pci_table[] = 
{
#define FGL_ASIC_ID(x)                      \
   {                           \
        .vendor      = PCI_VENDOR_ID_ATI,      \
        .device      = x,              \
        .subvendor   = PCI_ANY_ID,         \
        .subdevice   = PCI_ANY_ID,         \
    }
#include "fglrxko_pci_ids.h"
    { 0, }
};    

/* global module vars and constants - defined trough macros */
MODULE_AUTHOR("Fire GL - ATI Research GmbH, Germany");
MODULE_DESCRIPTION("ATI Fire GL");
#ifdef MODULE_PARM
MODULE_PARM(firegl, "s");
#else
module_param(firegl, charp, 0);
#endif

#ifdef MODULE_LICENSE
MODULE_LICENSE("Proprietary. (C) 2002 - ATI Technologies, Starnberg, GERMANY");
#endif
#ifdef MODULE_DEVICE_TABLE
MODULE_DEVICE_TABLE(pci, fglrx_pci_table);
#endif

MODULE_INFO(supported, "external");

/* globals constants */
const char*         KCL_SYSINFO_OsVersionString = UTS_RELEASE;
const unsigned int  KCL_SYSINFO_PageSize        = PAGE_SIZE;
const unsigned long KCL_SYSINFO_OsVersionCode   = LINUX_VERSION_CODE;

// create global constants and hint symbols (i.e. for objdump checking)
#ifdef MODVERSIONS
const unsigned long KCL_SYSINFO_BinaryModuleSupport = 1;
const char BUILD_KERNEL_HAS_MODVERSIONS_SET;
#else
const unsigned long KCL_SYSINFO_BinaryModuleSupport = 0;
const char BUILD_KERNEL_HAS_MODVERSIONS_CLEARED;
#endif

#ifdef __SMP__
const unsigned long KCL_SYSINFO_SmpSupport = 1;
const char BUILD_KERNEL_HAS_SMP_SET;
#else
const unsigned long KCL_SYSINFO_SmpSupport = 0;
const char BUILD_KERNEL_HAS_SMP_CLEARED;
#endif

/* PAE is always disabled if it's not x86_64 or CONFIG_X86_PAE is disabled on a 32 bit system.*/
#if !defined(__x86_64__) && !defined(CONFIG_X86_PAE)
const unsigned long KCL_SYSINFO_PaeSupport = 0;
#else
const unsigned long KCL_SYSINFO_PaeSupport = 1;
#endif

#if defined(CONFIG_HUGETLBFS) && defined(CONFIG_HUGETLB_PAGE)
#define FGL_LNX_SUPPORT_LARGE_PAGE
#endif

#ifdef FIREGL_USWC_SUPPORT

typedef enum
{
    KCL_MEM_PAT_DISABLED = 0,
    KCL_MEM_PAT_ENABLED_BUILTIN,
    KCL_MEM_PAT_ENABLED_KERNEL
} kcl_mem_pat_status_t;

static kcl_mem_pat_status_t kcl_mem_pat_status = KCL_MEM_PAT_DISABLED;
static u64 kcl_mem_pat_orig_val; 

static kcl_mem_pat_status_t ATI_API_CALL kcl_mem_pat_enable (unsigned int save_orig_pat);
static void ATI_API_CALL kcl_mem_pat_disable (void);

#endif //FIREGL_USWC_SUPPORT

/* globals vars that are in fact constants */
unsigned long KCL_SYSINFO_TimerTicksPerSecond;
extern int firegl_get_num_devices (void);

// ============================================================
/* global structures */
int ip_firegl_open(struct inode* inode, struct file* filp)
{
    int m;

#ifndef MINOR
    m = minor(inode->i_rdev);
#else
    m = MINOR(inode->i_rdev);
#endif

    return firegl_open(m, (KCL_IO_FILE_Handle)filp);
}

int ip_firegl_release(struct inode* inode, struct file* filp)
{
    return firegl_release((KCL_IO_FILE_Handle)filp);
}

#ifdef HAVE_UNLOCKED_IOCTL
long ip_firegl_unlocked_ioctl(struct file* filp, unsigned int cmd, unsigned long arg)
#else
int ip_firegl_ioctl(struct inode* inode, struct file* filp, unsigned int cmd, unsigned long arg)
#endif
{
    return firegl_ioctl((KCL_IO_FILE_Handle)filp, cmd, arg);
}

int ip_firegl_mmap(struct file* filp, struct vm_area_struct* vma)
{ 
    int ret;
    KCL_DEBUG_TRACEIN(FN_FIREGL_MMAP, vma, NULL);
    ret = firegl_mmap((KCL_IO_FILE_Handle)filp, vma);
    KCL_DEBUG_TRACEOUT(FN_FIREGL_MMAP, ret, NULL);
    return ret;
}

#if defined(KCL_OSCONFIG_IOCTL_COMPAT) && defined(__x86_64__)
long ip_firegl_compat_ioctl(struct file* filp, unsigned int cmd, unsigned long arg)
{ 
    long ret;
    KCL_DEBUG_TRACEIN(FN_FIREGL_COMPAT_IOCTL, cmd, NULL);
    ret = firegl_compat_ioctl((KCL_IO_FILE_Handle)filp, cmd, arg);
    KCL_DEBUG_TRACEOUT(FN_FIREGL_COMPAT_IOCTL, ret, NULL);
    return ret;
}
#endif

kcl_ssize_t ip_firegl_read( struct file *filp,
                         char *buf, 
                         kcl_size_t size,
                         kcl_loff_t *off_ptr)
{
    kcl_ssize_t ret;
    KCL_DEBUG_TRACEIN(FN_FIREGL_READ_WRITE, size, NULL);
    ret = firegl_asyncio_read((KCL_IO_FILE_Handle)filp, buf, size, off_ptr);
    KCL_DEBUG_TRACEOUT(FN_FIREGL_READ_WRITE, ret, NULL);
    return ret;   
}

kcl_ssize_t ip_firegl_write( struct file *filp,
                          const char *buf, 
                          kcl_size_t size,
                          kcl_loff_t *off_ptr)
{
    kcl_ssize_t ret;
    KCL_DEBUG_TRACEIN(FN_FIREGL_READ_WRITE, size, NULL);
    ret = firegl_asyncio_write((KCL_IO_FILE_Handle)filp, buf, size, off_ptr);
    KCL_DEBUG_TRACEOUT(FN_FIREGL_READ_WRITE, ret, NULL);
    return ret; 
}

unsigned int ip_firegl_poll(struct file* filp, struct poll_table_struct* table)
{
    unsigned  int ret;

    KCL_DEBUG_TRACEIN(FN_FIREGL_POLL, table, NULL);

    ret = firegl_asyncio_poll(
            (KCL_IO_FILE_Handle)filp, (KCL_IO_FILE_PollTableHandle)table);

    KCL_DEBUG_TRACEOUT(FN_FIREGL_POLL, ret, NULL);

    return ret;
}

int ip_firegl_fasync(int fd, struct file *filp, int mode)
{
    int ret;
    KCL_DEBUG_TRACEIN(FN_FIREGL_FASYNC, filp, NULL);
    ret = firegl_asyncio_fasync(fd, (KCL_IO_FILE_Handle)filp, mode);
    KCL_DEBUG_TRACEOUT(FN_FIREGL_FASYNC, ret,NULL);
    return ret;    
}

kcl_loff_t ip_firegl_lseek(struct file *filp, kcl_loff_t off, int whence)
{
    return __KE_ESPIPE; /* unseekable */
}

static struct semaphore fireglAsyncioSemaphore[FIREGL_ASYNCIO_MAX_SEMA];
static unsigned char    fireglAsyncioSemaphoreUsed[FIREGL_ASYNCIO_MAX_SEMA];

static struct file_operations firegl_fops =
{
#ifdef THIS_MODULE
    owner:   THIS_MODULE,
#endif
    open:    ip_firegl_open,
    release: ip_firegl_release,
#ifdef HAVE_UNLOCKED_IOCTL
    unlocked_ioctl:   ip_firegl_unlocked_ioctl,
#else
    ioctl:   ip_firegl_ioctl,
#endif
    mmap:    ip_firegl_mmap,

    write:   ip_firegl_write,
    read:    ip_firegl_read,
    fasync:  ip_firegl_fasync,
    poll:    ip_firegl_poll,
    llseek:  ip_firegl_lseek,

#if defined(KCL_OSCONFIG_IOCTL_COMPAT) && defined(__x86_64__)
    compat_ioctl: ip_firegl_compat_ioctl,
#endif
};

typedef struct {
    kcl_device_t       pubdev;     // MUST BE FIRST MEMBER, we can directly deferencee to (device_t*)pubdev
    dev_t               device;     // Device number for mknod

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    struct device       *krldev;
#endif

    /* Locking */
    spinlock_t          spinlock[__KE_MAX_SPINLOCKS];      /* For inuse, open_count, buf_use   */
    struct semaphore    struct_sem[__KE_MAX_SEMAPHORES];   /* For linked list manipulations    */
} device_t;

static device_t     firegl_public_device;   // The Fire GL public device

/*****************************************************************************/
// standard XFree86 DRM proc support

#define DRM(x) FGLDRM_##x
#include "drm.h"

// mem_info() is missing in drm_proc.h. But, it is a DRM design problem anyway!
// The first registered DRM device could never report memory statisticts of another
// DRM device, cause the DRM mem_info routine uses local variables. So, let's use a dummy.
static int DRM(mem_info)(char *buf __attribute__((unused)), char **start __attribute__((unused)), off_t offset __attribute__((unused)), int len __attribute__((unused)), int *eof, void *data __attribute__((unused)))
{
    *eof = 1;
    return 0;
}

#include "drm_proc.h"

static int major = -1;

static kcl_proc_list_t *drm_proclist = NULL;

/*****************************************************************************/
// Fire GL DRM stub support (compatible with standard DRM stub)

#define FIREGL_STUB_MAXCARDS    16

typedef struct firegl_stub_list_tag {
	const char             *name;
	struct file_operations *fops;
	struct proc_dir_entry  *dev_root;
    kcl_proc_list_t       *proclist;
} firegl_stub_list_t;
static firegl_stub_list_t firegl_stub_list[FIREGL_STUB_MAXCARDS];

static struct proc_dir_entry *firegl_stub_root;
static int firegl_minors;

typedef struct firegl_drm_stub_info_tag {
    int (*info_register)(const char *name, struct file_operations *fops, device_t *dev);
	int (*info_unregister)(int minor);
    unsigned long signature; // to check for compatible Fire GL DRM device
} firegl_drm_stub_info_t;
static firegl_drm_stub_info_t firegl_stub_info;

static char *kcl_pte_phys_addr_str(pte_t pte, char *buf, kcl_dma_addr_t* phys_address);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
#define READ_PROC_WRAP(func)                                            \
static int func##_wrap(char *buf, char **start, kcl_off_t offset,       \
                       int len, int* eof, void* data)                   \
{                                                                       \
    if (offset > 0)                                                     \
    {                                                                   \
        KCL_DEBUG1(FN_FIREGL_PROC,"partial requests not supported!\n"); \
        return 0; /* no partial requests */                             \
    }                                                                   \
    *start = buf;                                                       \
    *eof = 1;                                                           \
    return func(buf, len, data);                                \
}

#else
#define READ_PROC_WRAP(func)                                            \
static int func##_wrap(struct seq_file *m, void* data)                  \
{                                                                       \
    int len = 0;                                                        \
    len = func(m->buf+m->count, m->size-m->count, m->private); \
    if  (m->count + len < m->size)                                      \
    {                                                                   \
         m->count += len;                                               \
         return 0;                                                      \
    }                                                                   \
    else                                                                \
    {                                                                   \
         m->count = m->size;                                            \
         return -1;                                                     \
    }                                                                   \
}

#endif

READ_PROC_WRAP(drm_name_info)
READ_PROC_WRAP(drm_mem_info)
READ_PROC_WRAP(drm_mem_info1)
READ_PROC_WRAP(drm_vm_info)
READ_PROC_WRAP(drm_clients_info)
READ_PROC_WRAP(firegl_lock_info)
#ifdef DEBUG
READ_PROC_WRAP(drm_bq_info)
#endif
READ_PROC_WRAP(firegl_debug_proc_read)
READ_PROC_WRAP(firegl_bios_version)
READ_PROC_WRAP(firegl_interrupt_info)
READ_PROC_WRAP(firegl_ptm_info)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
static kcl_ssize_t firegl_debug_proc_write_wrap(struct file *file, const char *buffer, kcl_size_t count, kcl_loff_t *data)
#else
static int firegl_debug_proc_write_wrap(void* file, const char *buffer, unsigned long count, void *data)
#endif
{                                                                  
    return firegl_debug_proc_write(file, buffer, count, data);     
}

/** \brief Callback function for reading from /proc/ati/major
 *
 * Returns the major device number in the outupt buffer in decimal.
 *
 * \param buf      buffer to write into [out]
 * \param start    start of new output within the buffer [out]
 * \param offset   offset to start reading from (only 0 is supported) [in]
 * \param request  number of bytes to be read [in]
 * \param eof      indicate end-of-file [out]
 * \param data     callback data pointer (unused) [in]
 *
 * \return number of bytes written
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
static int firegl_major_proc_read(char *buf, char **start, kcl_off_t offset,
                                  int request, int* eof, void* data)
#else
static int firegl_major_proc_read(struct seq_file *m, void* data)
#endif
{
    int len = 0;    // For ProcFS: fill buf from the beginning

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    KCL_DEBUG1(FN_FIREGL_PROC, "offset %d\n", (int)offset);

    if (offset > 0) 
    {
        KCL_DEBUG1(FN_FIREGL_PROC, "no partial requests\n");
        return 0; /* no partial requests */
    }

    *start = buf;  // For ProcFS: inform procfs that we start output at the beginning of the buffer
    *eof = 1;

    len = snprintf(buf, request, "%d\n", major);
#else
    len = seq_printf(m, "%d\n", major);
#endif

    KCL_DEBUG1(FN_FIREGL_PROC, "return len=%i\n",len);

    return len;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
static int firegl_major_proc_open(struct inode *inode, struct file *file)
{
        return single_open(file, firegl_major_proc_read, PDE_DATA(inode));
}

static const struct file_operations firegl_major_fops = 
{
        .open = firegl_major_proc_open,
        .read = seq_read,
        .llseek = seq_lseek,
};

static int firegl_debug_proc_open(struct inode *inode, struct file *file)
{
        return single_open(file, firegl_debug_proc_read_wrap, PDE_DATA(inode));
}

static const struct file_operations firegl_debug_fops = 
{
        .open = firegl_debug_proc_open,
        .write = firegl_debug_proc_write_wrap,
        .read = seq_read,
        .llseek = seq_lseek,
};

static int firegl_name_proc_open(struct inode *inode, struct file *file)
{
        return single_open(file, drm_name_info_wrap, PDE_DATA(inode));
}

static const struct file_operations firegl_name_fops = 
{
        .open = firegl_name_proc_open,
        .read = seq_read,
        .llseek = seq_lseek,
};

static int firegl_mem_proc_open(struct inode *inode, struct file *file)
{
        return single_open(file, drm_mem_info_wrap, PDE_DATA(inode));
}

static const struct file_operations firegl_mem_fops = 
{
        .open = firegl_mem_proc_open,
        .read = seq_read,
        .llseek = seq_lseek,
};

static int firegl_mem1_proc_open(struct inode *inode, struct file *file)
{
        return single_open(file, drm_mem_info1_wrap, PDE_DATA(inode));
}

static const struct file_operations firegl_mem1_fops = 
{
        .open = firegl_mem1_proc_open,
        .read = seq_read,
        .llseek = seq_lseek,
};

static int firegl_vm_proc_open(struct inode *inode, struct file *file)
{
        return single_open(file, drm_vm_info_wrap, PDE_DATA(inode));
}

static const struct file_operations firegl_vm_fops = 
{
        .open = firegl_vm_proc_open,
        .read = seq_read,
        .llseek = seq_lseek,
};

static int firegl_clients_proc_open(struct inode *inode, struct file *file)
{
        return single_open(file, drm_clients_info_wrap, PDE_DATA(inode));
}

static const struct file_operations firegl_clients_fops = 
{
        .open = firegl_clients_proc_open,
        .read = seq_read,
        .llseek = seq_lseek,
};

static int firegl_lock_proc_open(struct inode *inode, struct file *file)
{
        return single_open(file, firegl_lock_info_wrap, PDE_DATA(inode));
}

static const struct file_operations firegl_lock_fops = 
{
        .open = firegl_lock_proc_open,
        .read = seq_read,
        .llseek = seq_lseek,
};

#ifdef DEBUG
static int firegl_bq_proc_open(struct inode *inode, struct file *file)
{
        return single_open(file, drm_bq_info_wrap, PDE_DATA(inode));
}

static const struct file_operations firegl_bq_fops = 
{
        .open = firegl_bq_proc_open,
        .read = seq_read,
        .llseek = seq_lseek,
};
#endif

static int firegl_bios_proc_open(struct inode *inode, struct file *file)
{
        return single_open(file, firegl_bios_version_wrap, PDE_DATA(inode));
}

static const struct file_operations firegl_bios_fops = 
{
        .open = firegl_bios_proc_open,
        .read = seq_read,
        .llseek = seq_lseek,
};

static int firegl_interrupt_proc_open(struct inode *inode, struct file *file)
{
        return single_open(file, firegl_interrupt_info_wrap, PDE_DATA(inode));
}

static const struct file_operations firegl_interrupt_fops = 
{
        .open = firegl_interrupt_proc_open,
        .read = seq_read,
        .llseek = seq_lseek,
};

static int firegl_ptm_proc_open(struct inode *inode, struct file *file)
{
        return single_open(file, firegl_ptm_info_wrap, PDE_DATA(inode));
}

static const struct file_operations firegl_ptm_fops = 
{
        .open = firegl_ptm_proc_open,
        .read = seq_read,
        .llseek = seq_lseek,
};

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
kcl_proc_list_t KCL_PROC_FileList[] = 
{
    { "name",           drm_name_info_wrap,         NULL ,NULL},
    { "mem",            drm_mem_info_wrap,          NULL ,NULL},
    { "mem1",           drm_mem_info1_wrap,         NULL ,NULL},
    { "vm",             drm_vm_info_wrap,           NULL ,NULL},
    { "clients",        drm_clients_info_wrap,      NULL ,NULL},
    { "lock",           firegl_lock_info_wrap,      NULL ,NULL},
#ifdef DEBUG
    { "bq_info",        drm_bq_info_wrap,           NULL ,NULL},
#endif
    { "biosversion",    firegl_bios_version_wrap,   NULL ,NULL},
    { "interrupt_info", firegl_interrupt_info_wrap, NULL ,NULL},
    { "ptm_info",       firegl_ptm_info_wrap,       NULL ,NULL},
    { "NULL",           NULL,                       NULL ,NULL} // Terminate List!!!
};

kcl_proc_list_t KCL_GLOBAL_PROC_FILELIST[] =
{
    { "major",          firegl_major_proc_read,      NULL ,NULL},
    { "debug",          firegl_debug_proc_read_wrap, firegl_debug_proc_write_wrap, NULL},
    { "NULL",           NULL,                        NULL ,NULL}
    
};

#else
kcl_proc_list_t KCL_PROC_FileList[] =
{
    { "name",           NULL,         NULL, (kcl_file_operations_t*)&firegl_name_fops},
    { "mem",            NULL,         NULL, (kcl_file_operations_t*)&firegl_mem_fops},
    { "mem1",           NULL,         NULL, (kcl_file_operations_t*)&firegl_mem1_fops},
    { "vm",             NULL,         NULL, (kcl_file_operations_t*)&firegl_vm_fops},
    { "clients",        NULL,         NULL, (kcl_file_operations_t*)&firegl_clients_fops},
    { "lock",           NULL,         NULL, (kcl_file_operations_t*)&firegl_lock_fops},
#ifdef DEBUG
    { "bq_info",        NULL,         NULL, (kcl_file_operations_t*)&firegl_bq_fops},
#endif
    { "biosversion",    NULL,         NULL, (kcl_file_operations_t*)&firegl_bios_fops},
    { "interrupt_info", NULL,         NULL, (kcl_file_operations_t*)&firegl_interrupt_fops},
    { "ptm_info",       NULL,         NULL, (kcl_file_operations_t*)&firegl_ptm_fops},
    { "NULL",           NULL,         NULL, NULL} // Terminate List!!!
};

kcl_proc_list_t KCL_GLOBAL_PROC_FILELIST[] =
{
    { "major",          NULL,         NULL, (kcl_file_operations_t*)&firegl_major_fops},
    { "debug",          NULL,         NULL, (kcl_file_operations_t*)&firegl_debug_fops},
    { "NULL",           NULL,         NULL, NULL}
};
#endif

static struct proc_dir_entry *firegl_proc_init( device_t *dev,
                                                int minor,
                                                struct proc_dir_entry *root,
                                                struct proc_dir_entry **dev_root,
                                                kcl_proc_list_t *proc_list ) // proc_list must be terminated!
{
    struct proc_dir_entry *ent;
    char    name[64];
    kcl_proc_list_t *list = proc_list;
    kcl_proc_list_t *globallist = &KCL_GLOBAL_PROC_FILELIST[0];
    KCL_DEBUG1(FN_FIREGL_PROC, "minor %d, proc_list 0x%08lx\n", minor, (unsigned long)proc_list);
    if (!minor)
    {
        root = KCL_create_proc_dir(NULL, "ati", S_IRUGO|S_IXUGO);
    }

    if (!root)
    {
        KCL_DEBUG_ERROR("Cannot create /proc/ati\n");
        return NULL;
    }

    if (minor == 0)
    {
        // Global major debice number entry and Global debug entry
        while (globallist->rp || globallist->fops)
        {
            ent = KCL_create_proc_entry(root, globallist->name, S_IFREG|S_IRUGO, globallist->fops, globallist->rp, globallist->wp, dev);
            if (!ent)
            {
                KCL_remove_proc_dir_entry(NULL, "ati");
                KCL_DEBUG_ERROR("Cannot create /proc/ati/major\n");
                return NULL;
            }
            globallist++;
        }
    }

    sprintf(name, "%d", minor);
    *dev_root = KCL_create_proc_dir(root, name, S_IRUGO|S_IXUGO);
    if (!*dev_root) {
        KCL_remove_proc_dir_entry(root, "major");
        KCL_remove_proc_dir_entry(NULL, "ati");
        KCL_DEBUG_ERROR("Cannot create /proc/ati/%s\n", name);
        return NULL;
    }

    while (list->rp || list->fops)
    {
        ent = KCL_create_proc_entry(*dev_root, list->name, S_IFREG|S_IRUGO, list->fops, list->rp, list->wp,
                                    ((dev->pubdev.signature == FGL_DEVICE_SIGNATURE)? firegl_find_device(minor) : (dev)));
        if (!ent)
        {
            KCL_DEBUG_ERROR("Cannot create /proc/ati/%s/%s\n", name, list->name);
            while (proc_list != list)
            {
                KCL_remove_proc_dir_entry(*dev_root, proc_list->name);
                proc_list++;
            }
            KCL_remove_proc_dir_entry(root, name);
            if (!minor)
            {
                KCL_remove_proc_dir_entry(root, "major");
                KCL_remove_proc_dir_entry(NULL, "ati");
            }
            return NULL;
        }

        list++;
    }

    return root;
}

static int firegl_proc_cleanup( int minor,
                                struct proc_dir_entry *root,
                                struct proc_dir_entry *dev_root,
                                kcl_proc_list_t *proc_list )
{
    char name[64];
    if (!root || !dev_root)
    {
        KCL_DEBUG_ERROR("no root\n");
        return 0;
    }

    while (proc_list->rp || proc_list->fops)
    {
        KCL_DEBUG1(FN_FIREGL_PROC, "proc_list : 0x%x, proc_list->name:%s\n", proc_list, proc_list->name);
        KCL_remove_proc_dir_entry(dev_root, proc_list->name);
        proc_list++;
    }

    sprintf(name, "%d", minor);

    KCL_remove_proc_dir_entry(root, name);

    if ( minor == (firegl_minors-1) )
    {
        KCL_remove_proc_dir_entry(root, "major");
        KCL_remove_proc_dir_entry(root, "debug");

        KCL_remove_proc_dir_entry(NULL, "ati");
        KCL_DEBUG1(FN_FIREGL_PROC,"remove /proc/ati. \n");
    }    
    return 0;
}

static int firegl_stub_open(struct inode *inode, struct file *filp)
{
#ifndef MINOR
	int                    minor = minor(inode->i_rdev);
#else
	int                    minor = MINOR(inode->i_rdev);
#endif
	int                    err   = -ENODEV;
	const struct file_operations *old_fops;
    KCL_DEBUG1(FN_FIREGL_INIT,"\n");

        if (minor >= FIREGL_STUB_MAXCARDS)
            return -ENODEV;
	if (!firegl_stub_list[minor].fops)
        return -ENODEV;
	old_fops   = filp->f_op;
	filp->f_op = fops_get(firegl_stub_list[minor].fops);
	if (filp->f_op->open && (err = filp->f_op->open(inode, filp))) {
		fops_put(filp->f_op);
		filp->f_op =(struct file_operations *) fops_get(old_fops);
	}
	fops_put(old_fops);
	return err;
}

static struct file_operations firegl_stub_fops = {
	owner:   THIS_MODULE,
	open:	 firegl_stub_open
};

static int firegl_stub_getminor(const char *name, struct file_operations *fops, device_t *dev)
{
	int i;
        int count = 0;
        
        KCL_DEBUG1(FN_FIREGL_INIT, "firegl_stub_getminor: name=\"%s\"\n", name);

	for( i = 0; i < FIREGL_STUB_MAXCARDS; i++ ) 
        {
	    if( !firegl_stub_list[i].fops ) 
            {
		firegl_stub_list[i].name = name;
		firegl_stub_list[i].fops = fops;
                firegl_stub_list[i].proclist = (dev->pubdev.signature == FGL_DEVICE_SIGNATURE) ? dev->pubdev.proclist : drm_proclist;
                firegl_stub_root = firegl_proc_init(dev, i, firegl_stub_root, &firegl_stub_list[i].dev_root, firegl_stub_list[i].proclist);
                KCL_DEBUG1(FN_FIREGL_INIT, "minor=%d\n", i);
                count ++;
	    }

            if (count == dev->pubdev.privdevcount)
            {
                // Return the number of minors we allocated
                return count;
            }
	}
        KCL_DEBUG1(FN_FIREGL_INIT,"no more free minor\n");
        KCL_DEBUG_ERROR("exiting\n");
	return -1;
}

static int firegl_stub_putminor(int minor)
{
    KCL_DEBUG1(FN_FIREGL_INIT,"firegl_stub_putminor: minor=%d\n", minor);
    if (minor < 0 || minor >= FIREGL_STUB_MAXCARDS)
    {
        return -1;
    }    
    firegl_proc_cleanup(minor, firegl_stub_root, firegl_stub_list[minor].dev_root, firegl_stub_list[minor].proclist);
    firegl_stub_list[minor].name = NULL;
    firegl_stub_list[minor].fops = NULL;
    firegl_stub_list[minor].proclist = NULL;

    if( minor == (firegl_minors-1) ) 
    {
        unregister_chrdev(major, "ati");
    }   
    return 0;
}

static int __init firegl_stub_register(const char *name, struct file_operations *fops, device_t *dev)
{
    int ret;
    KCL_DEBUG1(FN_FIREGL_INIT, "name=\"%s\"\n", name);

    // try to register a dynamic char device for the firegl module
    ret = register_chrdev(0, "ati", &firegl_stub_fops);
    if(ret >= 0)
    {
        KCL_DEBUG1(FN_FIREGL_INIT,"register_chrdev() succeeded\n");

        // register our own module handler will handle the DRM device
	firegl_stub_info.info_register   = firegl_stub_getminor;
	firegl_stub_info.info_unregister = firegl_stub_putminor;

        major = ret;
    }
    else
    {
        KCL_DEBUG_ERROR("register_chrdev() failed with %i\n", ret);
        return -1;
    }

    return firegl_stub_info.info_register(name, fops, dev);
}

static int __exit firegl_stub_unregister(int minor)
{
	KCL_DEBUG1(FN_FIREGL_INIT,"%d\n", minor);
	if (firegl_stub_info.info_unregister)
		return firegl_stub_info.info_unregister(minor);
	return -1;
}

#ifdef FIREGL_POWER_MANAGEMENT

static int fglrx_pci_probe(struct pci_dev *dev, const struct pci_device_id *id_table)
{
    return 0;
}

/* In 2.6.38 acquire/release_console_sem was renamed to console_lock/unlock */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38)
#define console_lock() acquire_console_sem()
#define console_unlock() release_console_sem()
#endif

/* Starting from 2.6.14, kernel has new struct defined for pm_message_t,
   we have to handle this case separately.
   2.6.11/12/13 kernels have pm_message_t defined as int and older kernels
   don't have pm_message_t defined. 
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
static int fglrx_pci_suspend(struct pci_dev *pdev, pm_message_t pm_event)
#else
static int fglrx_pci_suspend(struct pci_dev *pdev, u32 pm_event)
#endif
{
    struct drm_device* privdev;
    int ret = 0, state;
    privdev = (struct drm_device*)firegl_query_pcidev((KCL_PCI_DevHandle)pdev);

    if(privdev == NULL)
    {
        KCL_DEBUG_ERROR("fglrx_pci_suspend. Can not get drm device context .\n");
        return -EIO;
    }
    state = PMSG_EVENT(pm_event);

    if (state == PMSG_EVENT(pdev->dev.power.power_state)) return 0;

    KCL_DEBUG_TRACEIN(FN_FIREGL_ACPI,state, "power state: %d-%d\n", state, PMSG_EVENT(pdev->dev.power.power_state));


    /* lock console output to prevent kernel hang with vesafb
     * A temporal workaround for current kernel issue, the workaround
     * itself may cause a different deadlock, but it appears to
     * happen much less frequent then without this workaround.
     */
    if (state == PM_EVENT_SUSPEND)
        console_lock();

    if (libip_suspend(privdev, state))
        ret = -EIO;

    if (!ret)
    {
        
    // since privdev->pcidev is acquired in X server, use pdev 
    // directly here to allow suspend/resume without X server start. 
        firegl_pci_save_state((KCL_PCI_DevHandle)pdev, privdev);
        pci_disable_device(pdev);
        PMSG_EVENT(pdev->dev.power.power_state) = state;
    }
    else
    {
        // firegl_cail_powerdown failed. Try to restore the system to
        // a usable state.
        libip_resume(privdev);
    }

    if (state == PM_EVENT_SUSPEND)
        console_unlock();

    KCL_DEBUG_TRACEOUT(FN_FIREGL_ACPI, ret, NULL);  
    
    return ret;
}

static int fglrx_pci_resume(struct pci_dev *pdev)
{
    struct drm_device* privdev;

    privdev = (struct drm_device*)firegl_query_pcidev((KCL_PCI_DevHandle)pdev);

    if(privdev == NULL)
    {
        KCL_DEBUG_ERROR("fglrx_pci_resume. Can not get drm device context .\n");
        return -EIO;
    }

    KCL_DEBUG_TRACEIN(FN_FIREGL_ACPI, PMSG_EVENT(pdev->dev.power.power_state),"resume %d \n",PMSG_EVENT(pdev->dev.power.power_state));

    if (PMSG_EVENT(pdev->dev.power.power_state) == 0) return 0;

    if (PMSG_EVENT(pdev->dev.power.power_state) == PM_EVENT_SUSPEND)
        console_lock();

#ifdef FIREGL_USWC_SUPPORT
    // Restore the PAT after resuming from S3 or S4.

    if (kcl_mem_pat_status != KCL_MEM_PAT_DISABLED)
    {
        kcl_mem_pat_enable (0);
    }
#endif //FIREGL_USWC_SUPPORT

    // PCI config space needs to be restored very early, in particular
    // before pci_set_master!
    firegl_pci_restore_state((KCL_PCI_DevHandle)pdev, privdev);

    if (pci_enable_device(pdev)) 
    {
        KCL_DEBUG_ERROR("Cannot enable PCI device.\n");
    }    

    pci_set_master(pdev);

    libip_resume(privdev);

    if (PMSG_EVENT(pdev->dev.power.power_state) == PM_EVENT_SUSPEND)
        console_unlock();

    PMSG_EVENT(pdev->dev.power.power_state) = 0;
    KCL_DEBUG_TRACEOUT(FN_FIREGL_ACPI, 0, NULL);  

    return 0;
}

static struct pci_driver fglrx_pci_driver = 
{
    .name           = "fglrx_pci",
    .id_table       = fglrx_pci_table,
    .probe          = fglrx_pci_probe,
#ifdef CONFIG_PM
    .suspend        = fglrx_pci_suspend,
    .resume         = fglrx_pci_resume,
#endif /* CONFIG_PM */
};
#endif // FIREGL_POWER_MANAGEMENT




static int firegl_init_devices(kcl_device_t *pubdev)
{
    int num_of_devices = 0;
    struct pci_dev *pdev = NULL;
    struct pci_device_id *pid;
    int ret_code = 0;
    int i = 0;
    int j = 0;
    int iommu=0;

    for (i=0; fglrx_pci_table[i].vendor != 0; i++)
    {
        pid = (struct pci_device_id *) &fglrx_pci_table[i];
        pdev = NULL;
        while (( pdev = pci_get_subsys(pid->vendor, 
                                       pid->device, 
                                       PCI_ANY_ID, 
                                       PCI_ANY_ID, 
                                       pdev)) != NULL)
        {
            num_of_devices++;
            KCL_DEBUG_INFO("  vendor: %x device: %x revision: %hhx count: %d\n", 
                           pid->vendor, pid->device, pdev->revision, num_of_devices);
            iommu += KCL_IOMMU_CheckInfo(pdev);
        }
    }

    if (iommu)
    {
        KCL_DEBUG_INFO("IOMMU is enabled, CrossFire are not supported on this platform\n");
        KCL_DEBUG_INFO("Disable IOMMU in BIOS options or kernel boot parameters to support CF\n");
    }

    if ((ret_code = firegl_init_device_list(num_of_devices)) != 0)
    {
        return (ret_code);
    }

    for (i=0; fglrx_pci_table[i].vendor != 0; i++)
    {
        pid = (struct pci_device_id *) &fglrx_pci_table[i];

        pdev = NULL;
        while (( pdev = pci_get_subsys(pid->vendor, 
                                       pid->device, 
                                       PCI_ANY_ID, 
                                       PCI_ANY_ID, 
                                       pdev)) != NULL)
        {
            if ((ret_code = firegl_get_dev(pubdev, (KCL_PCI_DevHandle)pdev)))
            {
                return ret_code; 
            }

#ifdef FIREGL_DMA_REMAPPING
            //The GART unit of All supported ASICs has 40-bit address range.
            pci_set_dma_mask(pdev, 0xffffffffffull); 
#endif

            j++;
            if (j == num_of_devices)
            {
                break;
            }
        }
    }

    firegl_realloc_device_list(num_of_devices);
    pubdev->privdevcount = firegl_get_num_devices();
    return 0;
}

static void firegl_cleanup_devices(void)
{
    firegl_cleanup_device_heads();
}

/*****************************************************************************/
/* init_module is called when insmod is used to load the module */
static int __init firegl_init_module(void)
{
    device_t* dev = &firegl_public_device;
    unsigned int i;
    int retcode;

	EXPORT_NO_SYMBOLS;

    // init global vars that are in fact constants
    KCL_SYSINFO_TimerTicksPerSecond = HZ;

    memset(dev, 0, sizeof(*dev));

    // init DRM proc list
    drm_proclist = kmalloc((DRM_PROC_ENTRIES + 1) * sizeof(kcl_proc_list_t), GFP_KERNEL);
    if ( drm_proclist == NULL )
        return -ENOMEM;

    for ( i=0; i<DRM_PROC_ENTRIES; i++ )
    {
        drm_proclist[i].name = DRM(proc_list)[i].name;
        drm_proclist[i].rp = (void *)DRM(proc_list)[i].f;
    }
    drm_proclist[i].rp = NULL; // terminate list

    memset(&firegl_stub_list, 0, sizeof(firegl_stub_list_t) * FIREGL_STUB_MAXCARDS);
    memset(&firegl_stub_info, 0, sizeof(firegl_stub_info));
    firegl_stub_info.signature = FGL_DEVICE_SIGNATURE;

    dev->pubdev.signature = FGL_DEVICE_SIGNATURE;

    for (i = 0; i < __KE_MAX_SPINLOCKS; i++)
        spin_lock_init(&dev->spinlock[i]);

    for (i=0; i < __KE_MAX_SEMAPHORES; i++)
        sema_init(&dev->struct_sem[i], 1);

    if ((retcode = firegl_private_init (&dev->pubdev)))
    {
        KCL_DEBUG_ERROR ("firegl_private_init failed\n");
        firegl_private_cleanup (&dev->pubdev);
        return retcode;
    }

    KCL_DEBUG1(FN_FIREGL_INIT, "Loading firegl module.\n");
    
    adapter_chain_init();
    cf_object_init();


    if ((retcode = firegl_init_devices(&dev->pubdev)))
    {
        KCL_DEBUG_ERROR("firegl_init_devices failed\n");
        if (retcode != -ENODEV)
        {
            /*
             * Only clean up devices if some supported devices were found
             * during initialization.  If none were found, do nothing.
             */

            firegl_cleanup_devices();
        }
        /* If no supported devices found, then need to make some clean before to exit */
        kfree(drm_proclist);
        return retcode;
    }

    if ( (retcode = firegl_init(&dev->pubdev)) )
    {
        KCL_DEBUG_ERROR("firegl_init failed\n");
        kfree(drm_proclist);
        return retcode;
    }

#ifdef FIREGL_USWC_SUPPORT
    switch (kcl_mem_pat_enable (1))
    {
        case KCL_MEM_PAT_ENABLED_BUILTIN:
            KCL_DEBUG_INFO("Driver built-in PAT support is enabled successfully\n");
            break;

        case KCL_MEM_PAT_ENABLED_KERNEL:
            /*
             * Using kernel PAT if kernel PAT is supported.
             */
            KCL_DEBUG_INFO("Kernel PAT support is enabled\n");
            break;

        case KCL_MEM_PAT_DISABLED:
        default:
            KCL_DEBUG_INFO("Driver built-in PAT support is disabled\n");
            break;
    }
#endif // FIREGL_USWC_SUPPORT


#if !defined(KCL_OSCONFIG_IOCTL_COMPAT) && defined(__x86_64__)
    if(!firegl_init_32compat_ioctls())
    {
        kfree(drm_proclist);
	KCL_DEBUG_ERROR("Couldn't register compat32 ioctls!\n");
	return -ENODEV;
    }
#endif

    // get the minor number
    firegl_minors = firegl_stub_register(dev->pubdev.name, &firegl_fops, dev);
    if (firegl_minors < 1)
    {
        KCL_DEBUG_ERROR("firegl_stub_register failed\n");
        kfree(drm_proclist);
        return -EPERM;
    }

    // The dev->device below should be stored in an array mapping them to the index of the drm_device
    {
        int i = 0;
        for (i = 0; i < firegl_minors; i++)
        {
            dev->device = MKDEV(major, i);
        }
    }

    KCL_DEBUG_INFO("module loaded - %s %d.%d.%d [%s] with %d minors\n",
            dev->pubdev.name,
	        dev->pubdev.major_version,
	        dev->pubdev.minor_version,
	        dev->pubdev.patchlevel,
	        dev->pubdev.date,
		    firegl_minors);

    
#ifdef FIREGL_POWER_MANAGEMENT
    if (pci_register_driver (&fglrx_pci_driver) < 0)
    {
        KCL_DEBUG_ERROR("Failed to register fglrx as PCI driver\n");
    }
#endif // FIREGL_POWER_MANAGEMENT

    /* Since kernel 3.10.0, OS need device driver to send require to PM for VT-switch.
     * When one device require VT-switch, PM will send signal USER1 to XServer and do VT switch
     * Because Intel driver skips VT-swicth when S3/S4, therefore if we does not require it
     * kernel will not do VT-switch when S3/S4  
     */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    dev->krldev = kmalloc(sizeof(struct device), GFP_KERNEL);
    pm_vt_switch_required(dev->krldev, true);
#endif

    return 0; // OK!
}



/* cleanup_module is called when rmmod is used to unload the module */
static void __exit firegl_cleanup_module(void)
{
    device_t* dev = &firegl_public_device;
    int count = dev->pubdev.privdevcount;
    int i = 0;
    KCL_DEBUG1(FN_FIREGL_INIT,"module cleanup started\n");

#ifdef FIREGL_POWER_MANAGEMENT
    pci_unregister_driver (&fglrx_pci_driver);
#endif

#ifdef FIREGL_USWC_SUPPORT
    if (kcl_mem_pat_status != KCL_MEM_PAT_DISABLED)
    {
        kcl_mem_pat_disable ();
    }
#endif // FIREGL_USWC_SUPPORT

    firegl_cleanup_devices();

    for (i = 0; i < count; i++)
    {
        if ( firegl_stub_unregister(i) ) 
        {
            KCL_DEBUG_ERROR("Cannot unload module on minor: %d\n", i);
        }
    }   

#if !defined(KCL_OSCONFIG_IOCTL_COMPAT) && defined(__x86_64__)
    firegl_kill_32compat_ioctls();
#endif

    firegl_private_cleanup (&dev->pubdev);

    /* When uninstall kernel driver, we should unregister to VT-switch,
     * otherwise, PM will keep do VT-switch when S3/S4 
     */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    pm_vt_switch_unregister(dev->krldev);
    kfree(dev->krldev);
#endif

    if (drm_proclist)
        kfree(drm_proclist);

	KCL_DEBUG_INFO("module unloaded - %s %d.%d.%d [%s]\n",
            dev->pubdev.name,
	        dev->pubdev.major_version,
	        dev->pubdev.minor_version,
	        dev->pubdev.patchlevel,
	        dev->pubdev.date);

    cf_object_cleanup();
    adapter_chain_cleanup();    

    return;
}

module_init( firegl_init_module );
module_exit( firegl_cleanup_module );

int ATI_API_CALL KCL_PM_Is_SuspendToRam(int state)
{
    if (PM_EVENT_SUSPEND == state)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

void ATI_API_CALL *KCL_SEMAPHORE_ASYNCIO_Alloc()
{
    int i;
    
    for(i=0; i<FIREGL_ASYNCIO_MAX_SEMA; i++)
    {
        if(fireglAsyncioSemaphoreUsed[i] != 1)
        {
            fireglAsyncioSemaphoreUsed[i] = 1;
            
            return &(fireglAsyncioSemaphore[i]);
        }
    }
    return NULL;
}

void ATI_API_CALL KCL_SEMAPHORE_ASYNCIO_Free(struct semaphore *pSema)
{
    int i;
    
    for(i=0; i<FIREGL_ASYNCIO_MAX_SEMA; i++)
    {
        if( &(fireglAsyncioSemaphore[i]) == pSema )
        {
            fireglAsyncioSemaphoreUsed[i] = 0;
            return;
        }
    }
}

void ATI_API_CALL KCL_SEMAPHORE_ASYNCIO_Init(void)
{
    int i;
    
    for(i=0; i<FIREGL_ASYNCIO_MAX_SEMA; i++)
    {
        fireglAsyncioSemaphoreUsed[i] = 0;
    }
}    

int ATI_API_CALL KCL_SYSINFO_MapConstant(int constant)
{
    switch (constant)
    {
    case __KE_POLLIN:
        return POLLIN;
    case __KE_POLLRDNORM:
        return POLLRDNORM;
    case __KE_EAGAIN:
        return EAGAIN;
    case __KE_FASYNC_ON:
        return 1;
    case __KE_FASYNC_OFF:
        return 0;
    case __KE_SIGIO:
        return SIGIO;
    case __KE_EINTR:
        return EINTR;
    default:
        return -1;
    }
}

/** \brief Change page attribute of continuous pages 
 *  \param pt Kernel virtual address of the start page.
 *  \param pages Number of pages to change.
 *  \param enable Memory type to be set. Writeback:1. Uncached:0.
 *  \return kernel defined error code.
 */
int ATI_API_CALL KCL_SetPageCache(void* pt, int pages, int enable)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
    unsigned long prot=KCL_GetInitKerPte((unsigned long)pt) & pgprot_val(PAGE_KERNEL) ;  //PCD been cleared and keep NX setting.
    if(!enable)
        prot |= 1 <<_PAGE_BIT_PCD;
    return change_page_attr(virt_to_page(pt), pages, __pgprot(prot));
#else
    if (enable)
    {
        return set_memory_wb((unsigned long)pt, pages);
    }
    else
    {
        return set_memory_uc((unsigned long)pt, pages);
    }
#endif
}

/** \brief Change page attribute of a page array 
 *  \param pt Pointer to the array. Each element in the array contains a pointer of a page structure.
 *  \param pages Number of pages to change.
 *  \param enable Memory type to be set. Writeback:1. Uncached:0.
 *  \return kernel defined error code.
 */
int ATI_API_CALL KCL_SetPageCache_Array(unsigned long *pt, int pages, int enable)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28)
    unsigned long *pPageList=NULL;
    unsigned int i, lowPageCount = 0;
    int ret;
    pPageList = kmalloc( pages*sizeof(*pPageList), GFP_KERNEL);
    if (pPageList == NULL)
    {
        DRM_ERROR("Out of memory when allocating temporay page list\n");
        return FALSE;
    }
    for (i=0; i< pages; i++)
    {
        if(!KCL_IsPageInHighMem((void *)pt[i]))
        {
            pPageList[lowPageCount++] = (unsigned long )KCL_ConvertPageToKernelAddress((void*)pt[i]);
        }
    }
    if (enable)
    {
        ret = set_memory_array_wb(pPageList, lowPageCount);
    }   
    else                
    {                
        ret = set_memory_array_uc(pPageList, lowPageCount);
    }
    if (pPageList != NULL)
    {
        kfree(pPageList);
    }
#else               
    unsigned int i;
    int ret = 0;
    unsigned long kaddr;
    for( i = 0; i < pages; i++ )
    {
        if(!KCL_IsPageInHighMem((void *)pt[i]))
        {
            kaddr = (unsigned long)KCL_ConvertPageToKernelAddress((void *)pt[i]);
            ret = KCL_SetPageCache((void *)kaddr, 1, enable);
        }
        if (ret)
        {
            break;
        }
    }   
#endif
    /*add KCL_PageCache_Flush for highmem allocation*/
    /*The unmap operation for HIMEM would leave the accordingly PTE/TLB itmes around for a while
      until the next time flush_all_zero_pkmaps being called in order to relieve the performance hurt.
      So when we try to change such lazy tlb hignmem page's attribute, we would run into trouble.*/
    KCL_PageCache_Flush();
    return ret;
}


/** \brief Check whether the page is located within the high memory zone
 *  \return Nonzero if page is in high memory zone, zero otherwise
 */
unsigned int ATI_API_CALL KCL_IsPageInHighMem(void* page)
{
   return PageHighMem((struct page*)page);
}


/** /brief Call global kernel task/thread scheduler */
void ATI_API_CALL KCL_GlobalKernelScheduler(void)
{
	schedule();
}

/** /brief Check whether the current process is being terminated
 *  /return Nonzero if process is being terminated, zero otherwise
 */
unsigned int ATI_API_CALL KCL_CurrentProcessIsTerminating(void)
{
   return ( current->flags & PF_EXITING ? 1 : 0 );
}

/** /brief Call global OS kernel task/thread scheduler 
 *  /return Nonzero if a system call was awakened by a signal
 */
int ATI_API_CALL KCL_GetSignalStatus(void)
{
    return signal_pending(current);
}

/** /brief Vector of OS dependent values of security caps indexed by KCL_ENUM_ProcessState */
static int KCL_MAP_ProcessState[] =
{
    TASK_RUNNING,           // KCL_PROCESS_STATE_READY_TO_RUN
    TASK_UNINTERRUPTIBLE,   // KCL_PROCESS_STATE_UNINTERRUPTIBLE_SLEEP
    TASK_INTERRUPTIBLE      // KCL_PROCESS_STATE_INTERRUPTIBLE_SLEEP
};

/** \brief Set current process state
 *  \param state OS independent process state
 */
void ATI_API_CALL KCL_SetCurrentProcessState(KCL_ENUM_ProcessState state)
{
    if (state >= KCL_PROCESS_STATE_NUM)
    {
        return;
    }

    current->state = KCL_MAP_ProcessState[state];
}

#if defined(__i386__) 
#ifndef __HAVE_ARCH_CMPXCHG
static inline 
unsigned long __fgl_cmpxchg(volatile void *ptr, unsigned long old,            
                        unsigned long new, int size)                      
{                                                                                       
    unsigned long prev;                                                             
    switch (size) {                                                                 
    case 1:                                                                         
        __asm__ __volatile__(LOCK_PREFIX "cmpxchgb %b1,%2"
                             : "=a"(prev)
                             : "q"(new), "m"(*__xg(ptr)), "0"(old)
                             : "memory");
        return prev;
    case 2:
        __asm__ __volatile__(LOCK_PREFIX "cmpxchgw %w1,%2"
                             : "=a"(prev)
                             : "q"(new), "m"(*__xg(ptr)), "0"(old)
                             : "memory");
        return prev;
    case 4:
        __asm__ __volatile__(LOCK_PREFIX "cmpxchgl %1,%2"
                             : "=a"(prev)
                             : "q"(new), "m"(*__xg(ptr)), "0"(old)
                             : "memory");
        return prev;
    }
    return old;
}
#endif /* cmpxchg */
#elif defined(__alpha__)
todo !!!
#endif

unsigned long ATI_API_CALL kcl__cmpxchg(volatile void *ptr, unsigned long old,
         unsigned long new, int size)
{
#ifndef __HAVE_ARCH_CMPXCHG
    return __fgl_cmpxchg(ptr,old,new,size);
#else
    /* On kernel version 2.6.34 passing a variable or unsupported size
     * argument to the __cmpxchg macro causes the default-clause of a
     * switch statement to be compiled, which references an undefined
     * symbol __cmpxchg_wrong_size. */
    switch (size)
    {
    case 1: return __cmpxchg((uint8_t  *)ptr,old,new,1);
    case 2: return __cmpxchg((uint16_t *)ptr,old,new,2);
    case 4: return __cmpxchg((uint32_t *)ptr,old,new,4);
#ifdef __x86_64__
    case 8: return __cmpxchg((uint64_t *)ptr,old,new,8);
#endif
    default: return old;
    }
#endif
}

/*****************************************************************************/

unsigned int ATI_API_CALL KCL_DEVICE_GetNumber(kcl_device_t *dev)
{
    return ((device_t*)dev)->device;
}

/** /brief Return a string containing parameters passed to the module during loading
 *  /return Pointer to the parameter string
 */
const char* ATI_API_CALL KCL_GetModuleParamString(void)
{
    return firegl;
}

/*****************************************************************************/

/** /brief Return the current process ID
 *  /return OS dependent value of the process ID
 */
KCL_TYPE_Pid ATI_API_CALL KCL_GetPid(void)
{
    return current->pid; 
}

/** /brief Return the current Thread Group ID
 *  /return OS dependent value of the Thread Group ID
 */
KCL_TYPE_Pid ATI_API_CALL KCL_GetTgid(void)
{
    return current->tgid; 
}

/** /brief Return the current Group Thread struct
 *  /return OS dependent value of the Group Thread struct
 */
void * ATI_API_CALL KCL_GetGroupLeader(void)
{
    return current->group_leader;
}

/** /brief Return the effective user ID
 *  /return OS dependent value of the effective user ID
 */
KCL_TYPE_Uid ATI_API_CALL KCL_GetEffectiveUid(void)
{
#ifdef CONFIG_UIDGID_STRICT_TYPE_CHECKS
    return __kuid_val(current_euid());
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,00)
    return __kuid_val(current_euid());
#else
#ifdef current_euid
    return current_euid();
#else
    return current->euid;
#endif // current_euid
#endif // LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,00)
#endif // CONFIG_UIDGID_STRICT_TYPE_CHECKS
}

/** /brief Delay execution for the specified number of microseconds
 *  /param usecs Number of microseconds to delay
 */
void ATI_API_CALL KCL_DelayInMicroSeconds(unsigned long usecs)
{
    unsigned long start;
    unsigned long stop;
    unsigned long period;
    unsigned long wait_period;
    struct timespec tval;

#ifdef NDELAY_LIMIT
    // kernel provides delays with nano(=n) second accuracy
#define UDELAY_LIMIT    (NDELAY_LIMIT/1000) /* supposed to be 10 msec */
#else
    // kernel provides delays with micro(=u) second accuracy
#define UDELAY_LIMIT    (10000)             /* 10 msec */
#endif

    if (usecs > UDELAY_LIMIT)
    {
        start = jiffies;
        tval.tv_sec = usecs / 1000000;
        tval.tv_nsec = (usecs - tval.tv_sec * 1000000) * 1000;
        wait_period = timespec_to_jiffies(&tval);
        do {
            stop = jiffies;

            if (stop < start) // jiffies overflow
                period = ((unsigned long)-1 - start) + stop + 1;
            else
                period = stop - start;

        } while (period < wait_period);
    }
    else
        udelay(usecs);  /* delay value might get checked once again */
}

/** /brief Delay execution for the specified number of microseconds use TSC
 *  /param usecs Number of microseconds to delay
 */
void ATI_API_CALL KCL_DelayUseTSC(unsigned long usecs)
{
    unsigned long long start;
    unsigned long long stop;
    unsigned long long period;
    unsigned long long wait_period;
    unsigned long long cpuMhz = cpu_khz / 1000; 
        
    start = get_cycles();
    wait_period = ((unsigned long long)usecs) * cpuMhz;
    do {
        stop = get_cycles();
        if (stop < start) // jiffies overflow
              period = ((unsigned long)-1 - start) + stop + 1;
        else
              period = stop - start;

    } while (period < wait_period);
}

/** /brief Convert virtual address to physical address
 *  /param address Virtual address
 *  /return Physical address
 */
unsigned long ATI_API_CALL KCL_ConvertAddressVirtualToPhysical(void* address)
{
    return virt_to_phys(address);
}

unsigned long long ATI_API_CALL KCL_MapVirtualToPhysical(KCL_PCI_DevHandle pdev, void* address, unsigned long size)
{
#ifdef FIREGL_DMA_REMAPPING    
    return (unsigned long long)pci_map_single(pdev, address, size, PCI_DMA_BIDIRECTIONAL);
#else
    return (unsigned long long)virt_to_phys(address);
#endif
}

void ATI_API_CALL KCL_UnmapVirtualToPhysical(KCL_PCI_DevHandle pdev, unsigned long long bus_addr, unsigned long size)
{
#ifdef FIREGL_DMA_REMAPPING    
    pci_unmap_single(pdev, (dma_addr_t)bus_addr, size, PCI_DMA_BIDIRECTIONAL);
#endif
}

/** \brief Convert a page pointer to physical address index
 *  \param page pointer to a page
 *  \return Physical address index(physical address >> PAGE_SHIFT) 
 */
unsigned long ATI_API_CALL KCL_MapPageToPfn(KCL_PCI_DevHandle pdev, void* page)
{
    unsigned long page_index;
#ifdef FIREGL_DMA_REMAPPING    
    dma_addr_t bus_addr;
    bus_addr = pci_map_page ((struct pci_dev*)pdev, (struct page*)page, 0, PAGE_SIZE, PCI_DMA_BIDIRECTIONAL);
    page_index = (bus_addr >> PAGE_SHIFT);
#else
    page_index = page_to_pfn((struct page*)page);
#endif
    return page_index;
}

void ATI_API_CALL KCL_UnmapPageToPfn(KCL_PCI_DevHandle pdev, unsigned long long bus_addr)
{
#ifdef FIREGL_DMA_REMAPPING    
    pci_unmap_page ((struct pci_dev*)pdev, (dma_addr_t)bus_addr, PAGE_SIZE, PCI_DMA_BIDIRECTIONAL);
#endif
}

/** \brief Convert a page to kernel virtual address 
 *  \param page pointer to page
 *  \return kernel virtual address
 */
void* ATI_API_CALL KCL_ConvertPageToKernelAddress(void* page)
{
    return pfn_to_kaddr(page_to_pfn((struct page*)page));
}


/** /brief Return high memory value
 *  /return Pointer to high memory
 */
void* ATI_API_CALL KCL_GetHighMemory(void)
{
    return high_memory;
}

/** \brief Vector of values specifying which kernel parameters are defined
 *
 * Nonzero value means the corresponding parameter is defined, zero value means
 * undefined parameter
 *
 * The vector is indexed by KCL_ENUM_KernelConfigParam
 *
 */
static int KCL_MAP_KernelConfigParam[] =
{
    // KCL_KERNEL_CONF_PARAM_HUGE_MEM
#ifdef CONFIG_X86_4G
    1
#else
    0
#endif 
};

/** /brief Check whether a kernel configuration parameter is defined
 *  /param param OS independent value denoting the required parameter
 *  /return Nonzero if the parameter is defined, zero otherwise
 */
int ATI_API_CALL KCL_KernelConfigParamIsDefined(KCL_ENUM_KernelConfigParam param)
{
    if (param >= KCL_KERNEL_CONF_PARAM_NUM)
    {
        return 0;
    }

    return KCL_MAP_KernelConfigParam[param];
}

/** /brief Vector of OS dependent values of security caps indexed by KCL_ENUM_ErrorCode */
static int KCL_MAP_ErrorCode[] =
{
    ETIMEDOUT,      // KCL_ERROR_TIMED_OUT
    EBUSY,          // KCL_ERROR_DEVICE_RESOURCE_BUSY
    EINVAL,         // KCL_ERROR_INVALID_ARGUMENT
    EACCES,         // KCL_ERROR_PERMISSION_DENIED
    EFAULT,         // KCL_ERROR_INVALID_ADDRESS
    EIO,            // KCL_ERROR_INPUT_OUTPUT
    EBADSLT,        // KCL_ERROR_INVALID_SLOT
    ENOMEM,         // KCL_ERROR_OUT_OF_MEMORY
    EPERM,          // KCL_ERROR_OPERATION_NOT_PERMITTED
    ENODEV,         // KCL_ERROR_DEVICE_NOT_EXIST
    EINTR,          // KCL_ERROR_INTERRUPTED_SYSTEM_CALL
    ERESTARTSYS,    // KCL_ERROR_SIGNAL_INTERRUPTED_SYSTEM_CALL
    ELIBBAD         // KCL_ERROR_CORRUPTED_SHARED_LIB
};

/** \brief This function maps OS independent error conditions to OS defined error codes
 *  \param errcode OS independent error condition code
 *  \return OS kernel defined error code corresponding to the requested error condition 
 */
int ATI_API_CALL KCL_GetErrorCode(KCL_ENUM_ErrorCode errcode)
{
    if (errcode >= KCL_ERROR_NUM)
    {
        return EFAULT;
    }

    return KCL_MAP_ErrorCode[errcode];
}

/*****************************************************************************/

void ATI_API_CALL KCL_MODULE_IncUseCount(void)
{
    __module_get(THIS_MODULE);
}

void ATI_API_CALL KCL_MODULE_DecUseCount(void)
{
    module_put(THIS_MODULE);
}

/*****************************************************************************/

void ATI_API_CALL KCL_SEMAPHORE_STATIC_Down(kcl_device_t *dev, int index)
{
    down(&(((device_t*)dev)->struct_sem[index]));
}

void ATI_API_CALL KCL_SEMAPHORE_STATIC_Up(kcl_device_t *dev, int index)
{
    up(&(((device_t*)dev)->struct_sem[index]));
}

void ATI_API_CALL KCL_SEMAPHORE_Init(struct semaphore* sem, int value)
{
    sema_init(sem, value);
}

kcl_size_t ATI_API_CALL KCL_SEMAPHORE_GetObjSize(void)
{
    return sizeof(struct semaphore);
}

//PPLIB adding interruptible down for semaphore
int ATI_API_CALL KCL_SEMAPHORE_DownInterruptible(struct semaphore* sem)
{
    return down_interruptible(sem);
}
//PPLIB end

void ATI_API_CALL KCL_SEMAPHORE_DownUninterruptible(struct semaphore* sem)
{
    down(sem);
}

void ATI_API_CALL KCL_SEMAPHORE_Up(struct semaphore* sem)
{
    up(sem);
}

//rw semaphore for GPU reset
void ATI_API_CALL KCL_RW_SEMAPHORE_DownWrite(struct rw_semaphore* sem)
{
    down_write(sem);
}
void ATI_API_CALL KCL_RW_SEMAPHORE_UpWrite(struct rw_semaphore* sem)
{
    up_write(sem);
}
void ATI_API_CALL KCL_RW_SEMAPHORE_DownRead(struct rw_semaphore* sem)
{
    down_read(sem);
}
void ATI_API_CALL KCL_RW_SEMAPHORE_UpRead(struct rw_semaphore* sem)
{
    up_read(sem);
}
void ATI_API_CALL KCL_RW_SEMAPHORE_Init(struct rw_semaphore* sem)
{
    init_rwsem(sem);
}
kcl_size_t ATI_API_CALL KCL_RW_SEMAPHORE_GetObjSize(void)
{
    return sizeof(struct rw_semaphore);
}


/** Operations with atomic variables
 * These operations guaranteed to execute atomically on the CPU level
 * (memory access is blocked for other CPUs until our CPU finished the
 * atomic operation)
 */

/** \brief Increment atomic variable
 * \param v Pointer to the atomic variable
 */
void ATI_API_CALL KCL_AtomicInc(KCL_TYPE_Atomic* v)
{
    atomic_inc((atomic_t*)v);
}

/** \brief Decrement atomic variable
 * \param v Pointer to the atomic variable
 */
void ATI_API_CALL KCL_AtomicDec(KCL_TYPE_Atomic* v)
{
    atomic_dec((atomic_t*)v);
}

/** \brief Add integer to atomic variable
 * \param v Pointer to the atomic variable
 * \param val Value to add
 */
void ATI_API_CALL KCL_AtomicAdd(KCL_TYPE_Atomic* v, int val)
{
    atomic_add(val, (atomic_t*)v);
}

/** \brief Substract integer from atomic variable
 * \param v Pointer to the atomic variable
 * \param val Value to substract
 */
void ATI_API_CALL KCL_AtomicSub(KCL_TYPE_Atomic* v, int val)
{
    atomic_sub(val, (atomic_t*)v);
}

/** \brief Return value of atomic variable
 * \param v Pointer to the atomic variable
 * \return Integer value of the variable
 */
int ATI_API_CALL KCL_AtomicGet(KCL_TYPE_Atomic* v)
{
    return atomic_read((atomic_t*)v);
}

/** \brief Set value of atomic variable
 * \param v Pointer to the atomic variable
 * \param val Value to set
 */
void ATI_API_CALL KCL_AtomicSet(KCL_TYPE_Atomic* v, int val)
{
    atomic_set((atomic_t*)v, val);
}

/** \brief Increment and test atomic variable
 * \param v Pointer to the atomic variable
 * \return True (nonzero) if the result is 0 or false (zero) otherwise
 */
int ATI_API_CALL KCL_AtomicIncAndTest(KCL_TYPE_Atomic* v)
{
    return atomic_inc_and_test((atomic_t*)v);
}

/** \brief Decrement and test atomic variable
 * \param v Pointer to the atomic variable
 * \return True (nonzero) if the result is 0 or false (zero) otherwise
 */
int ATI_API_CALL KCL_AtomicDecAndTest(KCL_TYPE_Atomic* v)
{
    return atomic_dec_and_test((atomic_t*)v); 
}

/*****************************************************************************/

void ATI_API_CALL KCL_SPINLOCK_STATIC_Grab(kcl_device_t *dev, int ndx)
{
    spin_lock(&(((device_t*)dev)->spinlock[ndx]));
}

void ATI_API_CALL KCL_SPINLOCK_STATIC_Release(kcl_device_t *dev __attribute__((unused)), int ndx __attribute__((unused)))
{
    spin_unlock(&(((device_t*)dev)->spinlock[ndx]));
}

void ATI_API_CALL KCL_spin_lock(void *lock)
{
        spin_lock((spinlock_t *)lock);
}

void ATI_API_CALL KCL_spin_unlock(void *lock)
{
        spin_unlock((spinlock_t *)lock);
}

/*****************************************************************************/
int ATI_API_CALL kcl_vsprintf(char *buf, const char *fmt, va_list ap)
{
    return vsprintf(buf, fmt, ap);
}

int ATI_API_CALL kcl_vsnprintf(char *buf, size_t size, const char *fmt, va_list ap)
{
    return vsnprintf(buf, size, fmt, ap);
}

/** \brief Vector of OS dependent values of security caps indexed by KCL_ENUM_PosixSecurityCap */
static int KCL_MAP_PosixSecurityCap[] =
{
    CAP_SYS_ADMIN,  // KCL_SECURITY_CAP_GENERAL_SYS_ADMIN
    CAP_IPC_LOCK    // KCL_SECURITY_CAP_LOCK_SHARED_MEM
};

/** \brief Check whether a security capability is set
 *  \param cap POSIX security capability
 *  \return Nonzero if the capability is set, zero if not or if invalid cap value is passed
 */
int ATI_API_CALL KCL_PosixSecurityCapCheck(KCL_ENUM_PosixSecurityCap cap)
{
    if (cap >= KCL_SECURITY_CAP_NUM)
    {
        return 0;
    }

    return capable(KCL_MAP_PosixSecurityCap[cap]);
}

/** \brief set/clear  CAP_IPC_LOCK on effective security capability
 *  \param lock : 0 -- clear CAP_IPC_LOCK capability. 
 *                else -- set CAP_IPC_LOCK 
 *  \return 0 on success, negative errno on failure
 */
int ATI_API_CALL KCL_PosixSecurityCapSetIPCLock(unsigned int lock)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
#   define fglrx_commit_creds(new_creds) commit_creds(new_creds)
    struct cred *new_creds = prepare_creds();
    if (new_creds == NULL)
    {
        KCL_DEBUG_ERROR ("Could not allocate memory for new process credentials.\n");
        return -ENOMEM;
    }
#else
#   define fglrx_commit_creds(new_creds) (0)
    struct task_struct *new_creds = current;
#endif
    if (lock == 0 )
    {
        cap_lower(new_creds->cap_effective, CAP_IPC_LOCK);
    }
    else
    {
        cap_raise(new_creds->cap_effective, CAP_IPC_LOCK);
    }    
    return fglrx_commit_creds (new_creds);
#undef fglrx_commit_creds
}

/** \brief Get number of available RAM pages
 *  \return Number of available RAM pages
 */
unsigned long ATI_API_CALL KCL_GetAvailableRamPages(void)
{
	struct sysinfo si;
    si_meminfo(&si);
	return si.totalram;
}

/** \brief Get system memory usage information
 * param  val Pointer  to KCL_SYS_MEM_INFO
 */
void ATI_API_CALL KCL_GetSystemMemInfo(KCL_SYS_MEM_INFO* val)
{
    struct sysinfo si;
    si_meminfo(&si);
    val->totalram = si.totalram;
    val->freeram = si.freeram;
    val->totalhigh = si.totalhigh;
    val->freehigh = si.freehigh;
    val->mem_unit = si.mem_unit;
}


/** \brief Copy data from user space to kernel space
 * Has to be called in user context
 * May sleep
 *  \param to Pointer to destination in kernel space
 *  \param from Pointer to source in user space
 *  \param size Number of bytes to copy
 *  \return Zero on success, nonzero otherwise
 */
int ATI_API_CALL KCL_CopyFromUserSpace(void* to, const void __user * from, kcl_size_t size)
{
    return copy_from_user(to, from, size);
}

/** \brief Copy data from kernel space to user space
 * Has to be called in user context
 * May sleep
 *  \param to Pointer to destination in user space
 *  \param from Pointer to source in kernel space
 *  \param size Number of bytes to copy
 *  \return Zero on success, nonzero otherwise
 */
int ATI_API_CALL KCL_CopyToUserSpace(void __user * to, const void* from, kcl_size_t size)
{
    return copy_to_user(to, from, size);
}

void* ATI_API_CALL KCL_MEM_SmallBufferAlloc(kcl_size_t size)
{
    return kmalloc(size, GFP_KERNEL);
}

void* ATI_API_CALL KCL_MEM_SmallBufferAllocAtomic(kcl_size_t size)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
    /* atomic kmalloc would easily fall back to slowpath
     * because without sleep. Check order earlier can
     * avoid warning back trace printed by slowpath.
     * */
    if (size > (1<<(MAX_ORDER -1 + PAGE_SHIFT)))
    {
        return NULL;
    }
#endif
    return kmalloc(size, GFP_ATOMIC);
}

void ATI_API_CALL KCL_MEM_SmallBufferFree(void* p)
{
    kfree(p);
}

void* ATI_API_CALL KCL_MEM_Alloc(kcl_size_t size)
{
    return vmalloc(size);
}

void* ATI_API_CALL KCL_MEM_AllocAtomic(kcl_size_t size)
{
    return __vmalloc(size, GFP_ATOMIC, PAGE_KERNEL);
}

void ATI_API_CALL KCL_MEM_Free(void* p)
{
    return vfree(p);
}

/** \brief Allocate page for gart usage
 *  Try to allocated the page from high memory first, if failed than use low memory
 *  Note: this page not been mapped.
 *  \return pointer to a page
*/ 
void* ATI_API_CALL KCL_MEM_AllocPageForGart(void)
{
    return (void*)alloc_page(GFP_KERNEL | __GFP_HIGHMEM);
}

/** \brief free the page that originally allocated for gart usage
 *  \param pt pointer to a page
*/
 
void ATI_API_CALL KCL_MEM_FreePageForGart(void* pt)
{
    __free_page(pt);
}


void* ATI_API_CALL KCL_MEM_AllocPageFrame(void)
{
    return (void*)__get_free_page(GFP_KERNEL);
}

void* ATI_API_CALL KCL_MEM_AllocContiguousPageFrames(int order)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
    // Avoid warning back trace for slowpath of memory allocator with 2.6.31 and later
    // For kernel before 2.6.31, __get_free_pages returns NULL when order >= MAX_ORDER
    if (order >= MAX_ORDER)
    {
        return NULL;
    }
#endif

    return (void*)__get_free_pages(GFP_KERNEL|__GFP_COMP, order);
}

void ATI_API_CALL KCL_MEM_FreePageFrame(void* pt)
{
    free_page((unsigned long)pt);
}

void ATI_API_CALL KCL_MEM_FreePageFrames(void* pt, int order)
{
    free_pages((unsigned long)pt, order);
}

void ATI_API_CALL KCL_MEM_IncPageUseCount(void* pt)
{
    get_page(pt);
}

void ATI_API_CALL KCL_MEM_DecPageUseCount(void* pt)
{
    put_page(pt);
}

/** \brief Increase page count for mapping. 
 *  \param page Pointer to a page struct.
 *  \return None.
 */
void ATI_API_CALL KCL_MEM_IncPageCount_Mapping(void* page)
{
// WARNING WARNINIG WARNNING WARNNING WARNNING WARNNING WARNNING WARNNING
// Don't increment page usage count for reserved pages. Reserved
// pages' usage count is not decremented by the kernel during unmap!!!
//
// For kernel >= 2.6.15, We should reenable this, because the VM sub-system 
// will decrement the pages' usage count even for the pages marked as reserved 
//                                                          - MC.
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 15)
    if (! PageReserved((struct page*)page) )
#endif
    {
        get_page(page);
    }
}

unsigned long ATI_API_CALL KCL_MEM_AllocLinearAddrInterval(
                                        KCL_IO_FILE_Handle file,
                                        unsigned long addr,
                                        unsigned long len,
                                        unsigned long pgoff)
{
    unsigned long flags, prot;
    void *vaddr;

    flags = MAP_SHARED;
    prot  = PROT_READ|PROT_WRITE;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
    vaddr = (void *) vm_mmap(file, 0, len, prot, flags, pgoff);
#else
    down_write(&current->mm->mmap_sem);
    vaddr = (void *) do_mmap(file, 0, len, prot, flags, pgoff);
    up_write(&current->mm->mmap_sem);
#endif
    if (IS_ERR(vaddr))
       return 0;
    else
       return (unsigned long)vaddr;
}

int ATI_API_CALL KCL_MEM_ReleaseLinearAddrInterval(unsigned long addr, unsigned long len)
{
    int retcode = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
#ifdef FGL_LINUX_RHEL_MUNMAP_API
    retcode = vm_munmap(addr,
                        len,
                        1);
#else
    retcode = vm_munmap(addr,
                        len);
#endif
#else
    down_write(&current->mm->mmap_sem);
#ifdef FGL_LINUX_RHEL_MUNMAP_API
    retcode = do_munmap(current->mm,
                        addr,
                        len,
                        1);
#else
    retcode = do_munmap(current->mm,
                        addr,
                        len);
    up_write(&current->mm->mmap_sem);
#endif
#endif
    return retcode;
}

#if defined(__i386__)
/*
 * The implementation of these 64bit arithmetic functions is a clean re-implementation
 * after observing FreeBSD libkern v1.6 code.
 */
#ifdef do_div
unsigned long long ATI_API_CALL __udivdi3(unsigned long long n, unsigned long long base)
{
    // this change is to workaround the 64bit divisor on x86 system. for full update the divide interface need futher actions.
    unsigned int high = base >> 32;
    unsigned long long quot, dividend, divisor;
    unsigned int shift;

    if (high == 0) 
    {
        do_div(n, base);
        return n;
    } 
    else
    {
        shift = 1 + fls(high);
        dividend = n >> shift;
        divisor = base >> shift;

        quot = dividend;
        do_div(quot, divisor);

        if (quot != 0)
             quot--;
        if ((n - quot * base) >= base)
             quot++;

        return quot;
    }
}

unsigned long long ATI_API_CALL __umoddi3(unsigned long long n, unsigned long long base)
{
    unsigned int high = base >> 32;
    unsigned long long quot, dividend, divisor, remainder;
    unsigned int shift;

    if (high == 0) 
    {
        return do_div(n, base);
    } 
    else
    {
        shift = 1 + fls(high);
        dividend = n >> shift;
        divisor = base >> shift;

        quot = dividend;
        do_div(quot, divisor);

        if (quot != 0)
            quot--;

        remainder = n - quot * base;
        if (remainder >= base) 
        {
            quot++;
            remainder -= base;
        }

        return remainder;
    }
}

long long ATI_API_CALL __divdi3(long long n, long long base)
{
    unsigned long long un, ubase;
    int minus = 0;

    if (n < 0)
    {
       un = -n;
       minus = 1;
    }
    else
    {
       un = n;
       minus = 0;
    }

    if (base < 0)
    {
       ubase = -base;
       minus = !minus;
    }
    else
    {   
       ubase = base;
    }
    
    do_div(un, ubase);
    return (minus? -un : un);
}

long long ATI_API_CALL __moddi3(long long n, long long base)
{
    unsigned long long un, ubase;
    unsigned long long rem;
    int minus = 0;

    if (n < 0)
    {
       un = -n;
       minus = 1;
    }
    else
    {
       un = n;
       minus = 0;
    }

    if (base < 0)
    {
       ubase = -base;
       minus = !minus;
    }
    else
    {
       ubase = base;
    }   

    rem = do_div(un, ubase);
    return (minus? -rem : rem);
}
#endif
#endif

#if defined(VM_MAP) || defined(vunmap)
void* ATI_API_CALL KCL_MEM_MapPageList(unsigned long *pagelist, unsigned int count)
{
    void *vaddr;

#ifdef FGL_LINUX_SUSE90_VMAP_API
    ///Here's  a special implementation of vmap for Suse 9.0 support
    /// This will be defined in make.sh if needed
    vaddr = (void *) vmap((struct page**)pagelist, count);
#else
#ifdef VM_MAP
    vaddr = (void *) vmap((struct page**)pagelist, count, VM_MAP, PAGE_KERNEL); 
#else
    vaddr = (void *) vmap((struct page**)pagelist, count, 0, PAGE_KERNEL);
#endif
#endif
   return vaddr;
}

#ifdef FIREGL_USWC_SUPPORT
void* ATI_API_CALL KCL_MEM_MapPageListWc(unsigned long *pagelist, unsigned int count)
{
    void *vaddr;

#ifdef FGL_LINUX_SUSE90_VMAP_API
    ///Here's  a special implementation of vmap for Suse 9.0 support
    /// This will be defined in make.sh if needed
    return NULL;
#else
#ifdef VM_MAP
    vaddr = (void *) vmap((struct page**)pagelist, count, VM_MAP, pgprot_writecombine(PAGE_KERNEL));
#else
    vaddr = (void *) vmap((struct page**)pagelist, count, 0, pgprot_writecombine(PAGE_KERNEL));
#endif
#endif

    return vaddr;
}
#endif

void ATI_API_CALL KCL_MEM_Unmap(void* addr)
{
    vunmap(addr);
}
#else   // defined(VM_MAP) || defined(vunmap)
void* ATI_API_CALL KCL_MEM_MapPageList(unsigned long *pagelist, unsigned int count)
{
    return NULL;
}
void ATI_API_CALL KCL_MEM_Unmap(void* addr)
{
}
#endif  // defined(VM_MAP) || defined(vunmap)

/** \brief Reserve a memory page 
 *
 * \param pt Kernel logical address of the page
 *
 * \return None
 *
 */
void ATI_API_CALL KCL_ReserveMemPage(void* pt)
{
    SetPageReserved(virt_to_page((unsigned long)pt));
}

/** \brief Unreserve a memory page 
 *
 * \param pt Kernel logical address of the page
 *
 * \return None
 *
 */
void ATI_API_CALL KCL_UnreserveMemPage(void* pt)
{
    ClearPageReserved(virt_to_page((unsigned long)pt));
}

/** \brief Lock a memory page 
 *
 * \param pt pointer of the page
 *
 * \return None
 *
 */
void ATI_API_CALL KCL_LockMemPage(void* pt)
{
    SetPageReserved((struct page*)pt);
}

/** \brief Unlock a memory page 
 *
 * \param pt pointer of the page
 *
 * \return None
 *
 */
void ATI_API_CALL KCL_UnlockMemPage(void* pt)
{
    ClearPageReserved((struct page*)pt);
}

int ATI_API_CALL KCL_MEM_VerifyReadAccess(void* addr, kcl_size_t size)
{
    return access_ok(VERIFY_READ, addr, size) ? 0 : -EFAULT;
}

int ATI_API_CALL KCL_MEM_VerifyWriteAccess(void* addr, kcl_size_t size)
{
    return access_ok(VERIFY_WRITE, addr, size) ? 0 : -EFAULT;
}

/** \brief Get Init kernel PTE by address. Couldn't be used for kernel >= 2.6.25.
 * \param address Virtual address
 * \return Corresponding PTE on success, 0 otherwise
 */
unsigned long ATI_API_CALL KCL_GetInitKerPte(unsigned long address)
{
    pgd_t *pgd_p;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
    pud_t *pud_p;
#endif
    pmd_t *pmd_p;
    pte_t *pte_p;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
    pgd_p= pgd_offset_k(address);
#else
    KCL_DEBUG_ERROR("Function KCL_GetInitKerPte() shouldn't be used for kernel >= 2.6.25. \n");
    return 0;
#endif
    PGD_PRESENT(pgd_p);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
    PUD_OFFSET(pud_p, pgd_p, address);
    PUD_PRESENT(pud_p);
    PMD_OFFSET(pmd_p, pud_p, address);
#else
    PMD_OFFSET(pmd_p, pgd_p, address);
#endif
    PMD_PRESENT(pmd_p);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
    if (PUD_HUGE(*pud_p))
    {
#if defined(__x86_64__) 
        return ((pte_t *)pud_p)->pte;
#else
        return pte_val(*(pte_t *)pud_p);
#endif
    }
#endif

    if (pmd_large(*pmd_p))
    {
#if defined(__x86_64__) 
        return ((pte_t *)pmd_p)->pte;
#else
        return pte_val(*(pte_t *)pmd_p);
#endif
    }

    pte_p = pte_offset_kernel(pmd_p, address);

    if (pte_p && !pte_present(*pte_p))
    {
        return 0;
    }

#if defined(__x86_64__)
    return (pte_p->pte);
#else
    return pte_val(*pte_p);
#endif

}

/** \brief Get page pointer of the page table corresponding to the specified
 *  \brief virtual address
 *
 *
 * \param virtual_addr [in] User virtual address
 * \param page_addr [out] Page descriptor address of the Page Table
 *                        corresponding to virtual_addr
 * return pointer to struct page for the Page Table
 */
unsigned long ATI_API_CALL KCL_GetPageTableByVirtAddr(
        unsigned long virtual_addr,
        unsigned long * page_addr)
{
    pgd_t* pgd_p;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
    pud_t* pud_p;
#endif
    pmd_t* pmd_p;

    KCL_DEBUG2(FN_FIREGL_KCL,"virtual_addr=0x%08lx\n", virtual_addr);

    PGD_OFFSET(current->mm, pgd_p, virtual_addr);
    PGD_PRESENT(pgd_p);
    KCL_DEBUG2(FN_FIREGL_KCL,"pgd_p=0x%08lx\n", (unsigned long)pgd_p);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
    PUD_OFFSET(pud_p, pgd_p, virtual_addr);
    PUD_PRESENT(pud_p);
    KCL_DEBUG2(FN_FIREGL_KCL,"pud_p=0x%08lx\n", (unsigned long)pud_p);
    PMD_OFFSET(pmd_p, pud_p, virtual_addr);
#else
    PMD_OFFSET(pmd_p, pgd_p, virtual_addr);
#endif
    PMD_PRESENT(pmd_p);
    KCL_DEBUG2(FN_FIREGL_KCL,"pmd_p=0x%08lx\n", (unsigned long)pmd_p);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)    
    if ((pud_present(*(pud_p))) && (PUD_HUGE(*pud_p)))
    {
#ifndef FGL_LNX_SUPPORT_LARGE_PAGE
        return (unsigned long)-1L;
#else
        *page_addr = (unsigned long)pgd_page(*pgd_p);
#endif
    }
    else if (PMD_HUGE(*pmd_p))
#else
    if (PMD_HUGE(*pmd_p))
#endif
    {
#ifndef FGL_LNX_SUPPORT_LARGE_PAGE
        return (unsigned long)-1L;
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)   
        *page_addr = (unsigned long)pud_page(*pud_p);
#else
        *page_addr = (unsigned long)pgd_page(*pgd_p);
#endif
#endif    
    }
    else
    {
        *page_addr = (unsigned long)PMD_PAGE(*pmd_p);
    }

    KCL_DEBUG4(FN_FIREGL_KCL,"page_addr %lx\n", *page_addr);

    return  *page_addr;
}


/** \brief Get page size of the specified page
 *
 *
 * \param virtual_addr [in] User virtual address
 * \param page_size [out] Page size of the specific Page
 * return pointer to page_size
 */
unsigned int ATI_API_CALL KCL_GetPageSizeByVirtAddr(
        unsigned long virtual_addr,
        unsigned int  * page_size)
{
    pgd_t* pgd_p;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
    pud_t* pud_p;
#endif
    pmd_t* pmd_p;

    KCL_DEBUG2(FN_FIREGL_KCL,"virtual_addr=0x%08lx\n", virtual_addr);

    PGD_OFFSET(current->mm, pgd_p, virtual_addr);
    PGD_PRESENT(pgd_p);
    KCL_DEBUG2(FN_FIREGL_KCL,"pgd_p=0x%08lx\n", (unsigned long)pgd_p);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
    PUD_OFFSET(pud_p, pgd_p, virtual_addr);
    PUD_PRESENT(pud_p);
    KCL_DEBUG2(FN_FIREGL_KCL,"pud_p=0x%08lx\n", (unsigned long)pud_p);
    PMD_OFFSET(pmd_p, pud_p, virtual_addr);
#else
    PMD_OFFSET(pmd_p, pgd_p, virtual_addr);
#endif
    PMD_PRESENT(pmd_p);
    KCL_DEBUG2(FN_FIREGL_KCL,"pmd_p=0x%08lx\n", (unsigned long)pmd_p);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)    
    if ((pud_present(*(pud_p))) && (PUD_HUGE(*pud_p)))
    {
#ifndef FGL_LNX_SUPPORT_LARGE_PAGE
        return (unsigned int)-1;
#else
        *page_size = PAGE_SIZE_1G;
#endif
    }
    else if (PMD_HUGE(*pmd_p))
#else
    if (PMD_HUGE(*pmd_p))
#endif
    {
#ifndef FGL_LNX_SUPPORT_LARGE_PAGE
        return (unsigned int)-1;
#else
        if(KCL_SYSINFO_PaeSupport)
        {
           *page_size = PAGE_SIZE_2M;
        }
        else
        {
           *page_size = PAGE_SIZE_4M;
        }
#endif
    }
    else
    {
        *page_size = PAGE_SIZE_4K;
    }

    KCL_DEBUG4(FN_FIREGL_KCL,"page_size %lx\n", *page_size);

    return  *page_size;
}

/** /brief Flush one page on the local cpu
 *  /param va Virtual address of the page
 *  /return void
 */
static void kcl_flush_tlb_one(void *va)
{
    unsigned long *addr = (unsigned long *)va;
    __flush_tlb_one(*addr);
}

/** /brief Flush one page on all cpus
 *  /param vma Pointer to the memory region structure
 *  /param va Virtual address of the page
 *  /return void
 */
void ATI_API_CALL KCL_flush_tlb_onepage(struct vm_area_struct * vma, unsigned long va)
{
/* Some kernel developer removed the export of symbol "flush_tlb_page" on 2.6.25 x86_64 SMP kernel.
 * Define a simple version here.
 * kernel <  2.6.27, on_each_cpu has 4 parameters.
 * kernel >= 2.6.27, on_each_cpu has 3 parameters (removed the "retry" parameter)
 */
#if ( defined(__x86_64__) && (defined(__SMP__) || defined(CONFIG_SMP)) && (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25))) || \
    (!defined(__x86_64__) && (defined(__SMP__) || defined(CONFIG_SMP)) && (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)))
#   if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27))
        on_each_cpu(kcl_flush_tlb_one, &va, 1, 1);
#   else
        on_each_cpu(kcl_flush_tlb_one, &va, 1);
#   endif
#else
    flush_tlb_page(vma, va);
#endif
}

/** \brief Test and clear the "dirty" bit in the page table entry
 *
 * \param vma Pointer to the memory region structure
 * \param addr Virtual address covered by vma
 * \param ptep Pointer to the table entry structure
 *
 * \return Old value of the "dirty" flag
 *
 */
static inline int ptep_test_clear_dirty(struct vm_area_struct *vma, unsigned long addr, pte_t *ptep)
{
    int ret = 0;
    
    KCL_DEBUG1(FN_GENERIC1, "0x%lx, 0x%lx, 0x%lx->0x%08X", vma, addr, ptep, *ptep);
    
    if (pte_dirty(*ptep))
    {
#ifdef __x86_64__
        KCL_DEBUG1(FN_GENERIC1,"Test and clear bit %d in 0x%08X", _PAGE_BIT_DIRTY, ptep->pte);
        ret = test_and_clear_bit(_PAGE_BIT_DIRTY, &ptep->pte);
#else
        KCL_DEBUG1(FN_GENERIC1,"Test and clear bit %d in 0x%08X", _PAGE_BIT_DIRTY, ptep->pte_low);
        ret = test_and_clear_bit(_PAGE_BIT_DIRTY, &ptep->pte_low);
#endif        
    }

    if (ret)
    {
#if ( defined(__x86_64__) && (defined(__SMP__) || defined(CONFIG_SMP)) && (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25))) || \
    (!defined(__x86_64__) && (defined(__SMP__) || defined(CONFIG_SMP)) && (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)))
        //EPR#300662 On HP Z800 NUMA platform, SpecViewperf10 losses up to 50%
        //performance if flush TLB for all CPU. If limit flush TLB on current cpu,
        //The overall performance can increase back to normal level.
        //The impact of is when the process migrate to other CPU, 
        //TIMMO think the page is still dirty because the new CPU's TLB entry 
        //for this page is not flushed, which cause TIMMO do redundant work.
        if (num_online_nodes() > 1) 
        {
            kcl_flush_tlb_one(&addr);
        }
        else
#endif
        {
            KCL_flush_tlb_onepage(vma,addr);
            //set_page_dirty(page); // it looks good without set_page_dirty under 2.6.18
        }
    }

    KCL_DEBUG1(FN_GENERIC1,"0x%lX->0x%08X,ret %d", ptep, *ptep, ret);
    
    return ret;
}

#ifdef pte_offset_atomic
#define PTE_OFFSET_FUNC pte_offset_atomic
#define PTE_UNMAP_FUNC(p) pte_kunmap(p)
#else
#ifdef pte_offset_map
#define PTE_OFFSET_FUNC pte_offset_map_lock 
#ifndef pte_offset_map_lock
#define pte_lockptr(mm, pmd)    ({(void)(pmd); &(mm)->page_table_lock;})
#define pte_offset_map_lock(mm, pmd, address, ptlp)     \
({                                                      \
    spinlock_t *__ptl = pte_lockptr(mm, pmd);       \
    pte_t *__pte = pte_offset_map(pmd, address);    \
    *(ptlp) = __ptl;                                \
    spin_lock(__ptl);                               \
    __pte;                                          \
})
#endif
#define PTE_UNMAP_FUNC pte_unmap_unlock
#ifndef pte_unmap_unlock
#define pte_unmap_unlock(pte, ptl)      do {            \
         spin_unlock(ptl);                               \
         pte_unmap(pte);                                 \
 } while (0)
 #endif
#else
#ifdef pte_offset_kernel
#define PTE_OFFSET_FUNC pte_offset_kernel
#define PTE_UNMAP_FUNC(p) do {} while (0)
#else
#define PTE_OFFSET_FUNC pte_offset
#define PTE_UNMAP_FUNC(p) do {} while (0)
#endif
#endif
#endif

/** \brief Test and clear the "dirty" bit in the page table entry referred by
 *  \brief the virtual address
 * \param[in] virtual_addr Virtual address
 * \param[in] page_size the size of the page
 * \return Old value of the "dirty" flag on success or negative on error
 */
int ATI_API_CALL KCL_TestAndClearPageDirtyFlag(unsigned long virtual_addr, unsigned int page_size)
{
    int ret = -1; // init with page not present
    pgd_t* pgd_p;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
    pud_t* pud_p;
#endif
    pmd_t* pmd_p;
    pte_t* pte_p;
    struct vm_area_struct *vma;
    struct mm_struct* mm = current->mm;
    spinlock_t *ptl;
    int i,pages;
    unsigned long page_addr, vmaend_addr;

    KCL_DEBUG2(FN_FIREGL_KCL,"virtual_addr=0x%lx\n", virtual_addr);
    vma = find_vma(mm, virtual_addr);
    if (NULL == vma)
    {
        KCL_DEBUG1(FN_FIREGL_KCL, "%s", "ERROR: find_vma failed, virtual_addr:0x%lx\n", virtual_addr);
        return -1 ;
    }
    vmaend_addr = vma->vm_end;

    if (KCL_SYSINFO_PaeSupport)
    {
        pages=512;
    }
    else
    {
        pages=1024;
    }

    for (i=0,page_addr=virtual_addr; i<pages; i++,page_addr+=page_size)
    {
         if (page_addr >= vmaend_addr)
         {
             //research the vma only when the page_addr belongs to another VMA 
             vma = find_vma(mm, page_addr);
             if (NULL == vma)
             {
                 KCL_DEBUG1(FN_FIREGL_KCL, "%s", "ERROR: find_vma failed, virtual_addr:0x%lx\n", virtual_addr);
                 return -1;
             }
             vmaend_addr = vma->vm_end;
         }

         PGD_OFFSET(mm, pgd_p, page_addr);
         if (!pgd_present(*pgd_p))
         {
             KCL_DEBUG1(FN_FIREGL_KCL,"ERROR: !pgd_present\n");
             continue;
         }
         KCL_DEBUG1(FN_FIREGL_KCL,"pgd_p=0x%08lx\n", (unsigned long)pgd_p);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
         PUD_OFFSET(pud_p, pgd_p, page_addr);
         if (!pud_present(*pud_p))
         {
             KCL_DEBUG1(FN_FIREGL_KCL,"ERROR: !pud_present\n");
             continue;
         }
         PMD_OFFSET(pmd_p, pud_p, page_addr);
         if (!pmd_present(*pmd_p))
         {
             KCL_DEBUG1(FN_FIREGL_KCL,"ERROR: !pmd_present\n");
             continue;
         }
#else
         PMD_OFFSET(pmd_p, pgd_p, page_addr);
         if (!pmd_present(*pmd_p))
         {
             KCL_DEBUG1(FN_FIREGL_KCL,"ERROR: !pmd_present\n");
             continue;
         }
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
         if ((pud_present(*(pud_p))) && (PUD_HUGE(*pud_p)))
         {
             KCL_DEBUG1(FN_FIREGL_KCL,"Trying to clear dirty bits of 1G huge page\n");
#ifndef FGL_LNX_SUPPORT_LARGE_PAGE
             continue;
#else
             spin_lock(&(vma->vm_mm)->page_table_lock);
             pte_p = (pte_t *)pud_p;
             if (pte_present(*pte_p))
             {
                 ret = (ptep_test_clear_dirty(vma, page_addr, pte_p) ? 1 : 0);
             }
             else
             {
                 KCL_DEBUG1(FN_FIREGL_KCL,"1G large page does not exist\n");
             }
             spin_unlock(&(vma->vm_mm)->page_table_lock);
#endif
         }
         else if (PMD_HUGE(*pmd_p))
#else
         if (PMD_HUGE(*pmd_p))
#endif
         {
#ifndef FGL_LNX_SUPPORT_LARGE_PAGE
             continue;
#else
             spin_lock(&(vma->vm_mm)->page_table_lock);
             KCL_DEBUG1(FN_FIREGL_KCL,"Trying to clear dirty bits of 2M or 4M huge page\n");
             pte_p = (pte_t *)pmd_p;
             if (pte_present(*pte_p))
             {
                 ret = (ptep_test_clear_dirty(vma, page_addr, pte_p) ? 1 : 0);
             }
             else
             {
                 KCL_DEBUG1(FN_FIREGL_KCL,"2M or 4M large page does not exist\n");
             }
             spin_unlock(&(vma->vm_mm)->page_table_lock);
#endif   
         }
         else
         {
             pte_p = PTE_OFFSET_FUNC(vma->vm_mm, pmd_p, page_addr, &ptl);

             if (pte_present(*pte_p))
             {
                 ret = (ptep_test_clear_dirty(vma, page_addr, pte_p) ? 1 : 0);
             }
             else
             {
                 KCL_DEBUG1(FN_FIREGL_KCL,"page not exists!\n");
             }
             PTE_UNMAP_FUNC(pte_p,ptl);
         }
    }

    return ret;
}

/** \brief Lock down user pages
 *
 * \param vaddr User virtual address to lock
 * \param page_list Physical page address list for locked down pages
 * \param number of pages to lock
 * \return number of pages locked down 
 */
int ATI_API_CALL KCL_LockUserPages(unsigned long vaddr, unsigned long* page_list, unsigned int page_cnt)
{
    int ret;

    down_read(&current->mm->mmap_sem);
    ret = get_user_pages(current, current->mm, vaddr, page_cnt, 1, 0, (struct page **)page_list, NULL);
    up_read(&current->mm->mmap_sem);

    return ret;
}

/** \brief Lock down read only user pages
 *
 * \param vaddr User virtual address to lock
 * \param page_list Physical page address list for locked down pages
 * \param number of pages to lock
 * \return number of pages locked down 
 */
int ATI_API_CALL KCL_LockReadOnlyUserPages(unsigned long vaddr, unsigned long* page_list, unsigned int page_cnt)
{
    int ret;

    down_read(&current->mm->mmap_sem);
    ret = get_user_pages(current, current->mm, vaddr, page_cnt, 0, 0, (struct page **)page_list, NULL);
    up_read(&current->mm->mmap_sem);

    return ret;
}

void ATI_API_CALL KCL_UnlockUserPages(unsigned long* page_list, unsigned int page_cnt)
{
    unsigned int i;
    for (i=0; i<page_cnt; i++)
    {
        page_cache_release((struct page*)page_list[i]);
    }
}

/** Atomic bit manipulations
 * These operations guaranteed to execute atomically on the CPU level
 * (memory access is blocked for other CPUs until our CPU finished the
 * atomic operation)
 */

/** \brief Set bit atomically
 * \param nr Bit to manipulate
 * \param addr Address to start counting from
 */
void ATI_API_CALL KCL_AtomicSetBit(int nr, volatile void* addr)
{
    set_bit(nr, addr);
}

/** \brief Clear bit atomically
 * \param nr Bit to manipulate
 * \param addr Address to start counting from
 */
void ATI_API_CALL KCL_AtomicClearBit(int nr, volatile void* addr)
{
    clear_bit(nr, addr);
}

/** \brief Toggle bit atomically
 * \param nr Bit to manipulate
 * \param addr Address to start counting from
 */
void ATI_API_CALL KCL_AtomicToggleBit(int nr, volatile void* addr)
{
    change_bit(nr, addr);
}

/** \brief Test bit atomically
 * Since this is just a read operation, the word "atomic" is used
 * just for redundancy and unification purposes
 * \param nr Bit to manipulate
 * \param addr Address to start counting from
 * \return True (nonzero) if the bit is set and false (zero) otherwise
 */
int ATI_API_CALL KCL_AtomicTestBit(int nr, volatile void* addr)
{
    return test_bit(nr, addr);
}

/** \brief Test and set bit atomically
 * \param nr Bit to manipulate
 * \param addr Address to start counting from
 * \return Old value of the bit
 */
int ATI_API_CALL KCL_AtomicTestAndSetBit(int nr, volatile void* addr)
{
    return test_and_set_bit(nr, addr);
}

/** \brief Test and clear bit atomically
 * \param nr Bit to manipulate
 * \param addr Address to start counting from
 * \return Old value of the bit
 */
int ATI_API_CALL KCL_AtomicTestAndClearBit(int nr, volatile void* addr)
{
    return test_and_clear_bit(nr, addr);
}

/** \brief Test and toggle bit atomically
 * \param nr Bit to manipulate
 * \param addr Address to start counting from
 * \return Old value of the bit
 */
int ATI_API_CALL KCL_AtomicTestAndToggleBit(int nr, volatile void* addr)
{
    return test_and_change_bit(nr, addr);
}

/*****************************************************************************/

#ifdef __SMP__
static atomic_t cpus_waiting;

static void deferred_flush(void* contextp)
{
#if defined(__i386__) || defined(__x86_64__)
	asm volatile ("wbinvd":::"memory");
#elif defined(__alpha__) || defined(__sparc__)
	mb();
#else
#error "Please define flush_cache."
#endif
	atomic_dec(&cpus_waiting);
	while (atomic_read(&cpus_waiting) > 0)
		barrier();
}
#endif /* __SMP__ */

/** \brief Run a function on all other CPUs.
 * \param func The function to run.
 * \param info An arbitrary pointer to pass to the function.
 * \param nonatomic Currently unused.
 * \param wait If true, wait (atomically) until function has completed on other CPUs.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
#define KCL_SmpCallFunction(func, info, nonatomic, wait) smp_call_function(func, info, wait)
#else
#define KCL_SmpCallFunction(func, info, nonatomic, wait) smp_call_function(func, info, nonatomic, wait)
#endif

int ATI_API_CALL KCL_MEM_FlushCpuCaches(void)
{
#ifdef __SMP__
    /* write back invalidate all other CPUs (exported by kernel) */
	if (KCL_SmpCallFunction(deferred_flush, NULL, 1, 0) != 0)
		panic("timed out waiting for the other CPUs!\n");

    /* invalidate this CPU */
#if defined(__i386__) || defined(__x86_64__)
	asm volatile ("wbinvd":::"memory");
#elif defined(__alpha__) || defined(__sparc__)
	mb();
#else
#error "Please define flush_cache for your architecture."
#endif

	while (atomic_read(&cpus_waiting) > 0)
		barrier();
#else /* !__SMP__ */
#if defined(__i386__) || defined(__x86_64__)
	asm volatile ("wbinvd":::"memory");
#elif defined(__alpha__) || defined(__sparc__)
	mb();
#else
#error "Please define flush_cache for your architecture."
#endif
#endif /* !__SMP__ */

    return 0;
}

/** \brief Flush cpu cache and tlb. Used after changing page cache mode.
 *  \return None.
 */
void ATI_API_CALL KCL_PageCache_Flush(void)
{
    //For kernel>=2.6.25, cache and tlb flush has been included when calling set_memory_* functions.
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)    
    KCL_MEM_FlushCpuCaches();
    global_flush_tlb();  
#else 
    KCL_MEM_FlushCpuCaches();
    __flush_tlb_all(); 
#endif   
}

/*****************************************************************************/

int ATI_API_CALL KCL_MEM_MTRR_Support(void)
{
#ifdef CONFIG_MTRR
#ifdef FIREGL_USWC_SUPPORT
    return ((kcl_mem_pat_status == KCL_MEM_PAT_DISABLED) ? 1 : 0);
#else
    return 1;
#endif    
#else /* !CONFIG_MTRR */
    return 0;
#endif /* !CONFIG_MTRR */
}

int ATI_API_CALL KCL_MEM_MTRR_AddRegionWc(unsigned long base, unsigned long size)
{
#ifdef CONFIG_MTRR
    return mtrr_add(base, size, MTRR_TYPE_WRCOMB, 1);
#else /* !CONFIG_MTRR */
    return -EPERM;
#endif /* !CONFIG_MTRR */
}

int ATI_API_CALL KCL_MEM_MTRR_DeleteRegion(int reg, unsigned long base, unsigned long size)
{
#ifdef CONFIG_MTRR
    return mtrr_del(reg, base, size);
#else /* !CONFIG_MTRR */
    return -EPERM;
#endif /* !CONFIG_MTRR */
}

// UEFI specific support

int ATI_API_CALL KCL_EFI_IS_ENABLED(void)
{
#ifdef CONFIG_EFI
#ifdef EFI_BOOT
    return efi_enabled(EFI_BOOT);
#else
    return efi_enabled;
#endif
#else
    return 0;
#endif
}

void ATI_API_CALL KCL_Get_Console_Mode(kcl_console_mode_info_t *pMode)
{
    pMode->mode_width = screen_info.lfb_width;
    pMode->mode_height  = screen_info.lfb_height;
    pMode->depth  = screen_info.lfb_depth;
    pMode->pitch  = (screen_info.lfb_linelength)>>2;
    pMode->fb_base = (unsigned long)screen_info.lfb_base;
}

/*****************************************************************************/
// Interrupt support

/** \brief Pointer to the private interrupt handling function
 * Points to an interrupt handler located in the private ASIC dependent library
 * NOTE: per-device handlers are not supported
 * \param context Pointer to device specific data (whatever driver passed when
 *                registering the handler)
 */
static void ATI_API_CALL (*KCL_PRIV_InterruptHandler)(void* context);

/** \brief Interrupt handler to be called by the OS
 * Has to fit OS defined declaration
 * \param irq IRQ number
 * \param context Pointer to device specific data (whatever driver passed when
 *                registering the handler)
 * \param regs CPU registers on the moment of the interrupt
 * \return IRQ_HANDLED (TODO: return value reflecting whether the interrupt has
 *                     been actually handled)
 */
static irqreturn_t KCL_PUB_InterruptHandlerWrap(int irq, void *context
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
                                       ,struct pt_regs *regs
#endif
                                      )
{
    KCL_DEBUG5(FN_FIREGL_IRQ, NULL);
    KCL_PRIV_InterruptHandler(context);
    KCL_DEBUG5(FN_FIREGL_IRQ, NULL);
    return IRQ_HANDLED;
}

/** \brief Install interrupt handler
 * \param irq IRQ number
 * \param handler Pointer to the private ASIC dependent handler
 * \param dev_name Unique device name
 * \param context Pointer to the unique device context
 * \return 0 on success, nonzero otherwise
 */
int ATI_API_CALL KCL_InstallInterruptHandler(
    unsigned int irq,
    void (*ATI_API_CALL handler)(void*),
    const char *dev_name,
    void *context, int useMSI)
{
    KCL_PRIV_InterruptHandler = handler;

    return request_irq(
        irq,
        KCL_PUB_InterruptHandlerWrap,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
        ((useMSI) ? (SA_INTERRUPT) : (SA_SHIRQ)),
#else
        //when MSI enabled. keep irq disabled when calling the action handler,
        //exclude this IRQ from irq balancing (only on one CPU) 
        ((useMSI) ? (IRQF_DISABLED) : (IRQF_SHARED)),    
#endif
        dev_name,
        context);
}

/** \brief Uninstall interrupt handler
 * \param irq IRQ number
 * \param context Pointer to the unique device context (using this value, OS
 *                will indentify for which device the handler has to be
 *                uninstalled)
 */
void ATI_API_CALL KCL_UninstallInterruptHandler(unsigned int irq, void* context)
{
    free_irq(irq, context);
}

/** \brief Request MSI
 * \param context Pointer to the unique device context (using this value, OS
 *                will indentify for which device msi interrupts have to be
 *                enabled)
 * \return 0 on success, nonzero otherwise
 */
int ATI_API_CALL KCL_RequestMSI(void* context)
{
    return    pci_enable_msi(context);
}

/** \brief Disable MSI
 * \param context Pointer to the unique device context (using this value, OS
 *                will indentify for which device msi interrupts have to be
 *                disabled)
 */
void ATI_API_CALL KCL_DisableMSI(void* context)
{
    pci_disable_msi((struct pci_dev *)context);               //returns void
}

/*****************************************************************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)

#ifndef NOPAGE_SIGBUS
#define NOPAGE_SIGBUS 0
#endif /* !NOPAGE_SIGBUS */
#define PAGING_FAULT_SIGBUS NOPAGE_SIGBUS

#else

#define PAGING_FAULT_SIGBUS VM_FAULT_SIGBUS

#endif

typedef struct page mem_map_t;
typedef mem_map_t *vm_nopage_ret_t;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
static __inline__ vm_nopage_ret_t do_vm_nopage(struct vm_area_struct* vma,
                                                     unsigned long address)
#else
static __inline__ int do_vm_fault (struct vm_area_struct *vma, struct vm_fault *vmf)
#endif
{
    return (PAGING_FAULT_SIGBUS); /* Disallow mremap */
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
static __inline__ vm_nopage_ret_t do_vm_shm_nopage(struct vm_area_struct* vma,
                                                   unsigned long address)
#else
static __inline__ int do_vm_shm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26) */
{
    unsigned long vma_offset;
    unsigned long pte_linear;
    mem_map_t* pMmPage;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
    unsigned long address = (unsigned long) (vmf->virtual_address);
#endif

    /*
        vm_start           => start of vm-area,  regular address
        vm_end             => end of vm-area,    regular address
        vm_offset/vm_pgoff => start of area,     linear address
        address            => requested address, regular address

        Check range
        Seems the surrounding framework already does that test -
        skip it here, anyone does.
     */

    /*
        Note: vm_end is not member of range but this border
        hmm, might be used when growing the VMA, not sure - keep it as it is.
     */

    KCL_DEBUG3(FN_DRM_NOPAGE, "start=0x%08lx, "
            "end=0x%08lx, "
            "offset=0x%08lx\n",
            vma->vm_start,
            vma->vm_end,
            (unsigned long)KCL_MEM_VM_GetRegionMapOffset(vma));

    if (address > vma->vm_end)
    {
        return (PAGING_FAULT_SIGBUS); /* address is out of range */
    }

    /*  Calculate offset into VMA */
    vma_offset = address - vma->vm_start;

    /*
      Find the map with the given handle (vm_offset) and get the
      linear address.
    */
    pte_linear = firegl_get_addr_from_vm(vma);
    if (!pte_linear)
    {
        return (PAGING_FAULT_SIGBUS); /* bad address */
    }
    pte_linear += vma_offset;


    pMmPage = vmalloc_to_page((void *) pte_linear);
    KCL_MEM_IncPageCount_Mapping(pMmPage);  /* inc usage count of page */

    KCL_DEBUG3(FN_DRM_NOPAGE,"vm-address 0x%08lx => kernel-page-address 0x%p\n",
        address, page_address(pMmPage));
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
    return pMmPage;
#else
    vmf->page = pMmPage;

    return (0);
#endif
}

/*

    This routine is intended to remap addresses of a OpenGL context
      (which is one ore more pages in size)

*/
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
static __inline__ vm_nopage_ret_t do_vm_dma_nopage(struct vm_area_struct* vma, unsigned long address)
#else
static __inline__ int do_vm_dma_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26) */
{
    unsigned long kaddr;
    mem_map_t* pMmPage;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
    unsigned long address = (unsigned long) (vmf->virtual_address);
#endif

    if (address > vma->vm_end)
    {
        return (PAGING_FAULT_SIGBUS); /* Disallow mremap */
    }

    /*
        Have we ever got an acces from user land into context structure?

        Resolve the kernel (mem_map/page) address for the VMA-address
        we got queried about.
    */
    kaddr = firegl_get_addr_from_vm(vma);
    if (!kaddr)
    {
        return (PAGING_FAULT_SIGBUS); /* bad address */
    }
    kaddr += (address - vma->vm_start);

    pMmPage = virt_to_page(kaddr);

    KCL_MEM_IncPageCount_Mapping(pMmPage);

    KCL_DEBUG3(FN_DRM_NOPAGE, "vm-address 0x%08lx => kernel-page-address 0x%p\n",
        address, page_address(pMmPage));
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
    return pMmPage;
#else
    vmf->page = pMmPage;

    return (0);
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
static __inline__ vm_nopage_ret_t do_vm_kmap_nopage(struct vm_area_struct* vma, unsigned long address)
#else
static __inline__ int do_vm_kmap_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26) */
{
    unsigned long kaddr;
    mem_map_t* pMmPage;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
    unsigned long address = (unsigned long) (vmf->virtual_address);
#endif

    if (address > vma->vm_end)
    {
        return (PAGING_FAULT_SIGBUS); /* Disallow mremap */
    }

    if ((pMmPage = (mem_map_t*) firegl_get_pagetable_page_from_vm(vma)))
    {
        KCL_MEM_IncPageCount_Mapping(pMmPage);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
        return pMmPage;
#else
        vmf->page = pMmPage;
        return (0);
#endif
    }

    kaddr = firegl_get_addr_from_vm(vma);
    if (!kaddr)
    {
        return (PAGING_FAULT_SIGBUS); /* bad address */
    }
    kaddr += (address - vma->vm_start);

    KCL_DEBUG3(FN_DRM_NOPAGE,"kaddr=0x%08lx\n", kaddr);

    pMmPage = virt_to_page(kaddr);
    KCL_DEBUG3(FN_DRM_NOPAGE,"pMmPage=0x%08lx\n", (unsigned long)pMmPage);

    KCL_MEM_IncPageCount_Mapping(pMmPage);

    KCL_DEBUG3(FN_DRM_NOPAGE,"vm-address 0x%08lx => kernel-page-address 0x%p\n", address, page_address(pMmPage));

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
    return pMmPage;
#else
    vmf->page = pMmPage;

    return (0);
#endif
}

/** 
 **
 **  This routine is intented to locate the page table through the 
 **  pagelist table created earlier in dev-> pcie
 **/
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
static __inline__ vm_nopage_ret_t do_vm_pcie_nopage(struct vm_area_struct* vma,
                                                         unsigned long address)
#else
static __inline__ int do_vm_pcie_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26) */
{

    unsigned long vma_offset;
    unsigned long i; 
    mem_map_t* pMmPage;
    struct firegl_pcie_mem* pciemem;
    unsigned long* pagelist;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
    unsigned long address = (unsigned long) (vmf->virtual_address);
#endif
    
    drm_device_t *dev = (drm_device_t *)firegl_get_dev_from_vm(vma);
    if (dev == NULL)
    {
        KCL_DEBUG_ERROR("dev is NULL\n");
        return (PAGING_FAULT_SIGBUS);
    }

    if (address > vma->vm_end)
    {
        KCL_DEBUG_ERROR("address out of range\n");
        return (PAGING_FAULT_SIGBUS); /* address is out of range */
    }
    pciemem = firegl_get_pciemem_from_addr ( vma, address);
    if (pciemem == NULL)
    {
        KCL_DEBUG_ERROR("No pciemem found! \n");
        return (PAGING_FAULT_SIGBUS);
    }    
    pagelist = firegl_get_pagelist_from_vm(vma);

    if (pagelist == NULL) 
    {
        KCL_DEBUG_ERROR("No pagelist! \n");
        return (PAGING_FAULT_SIGBUS);
    }
     
    /** Find offset in  vma */
    vma_offset = address - vma->vm_start;
    /** Which entry in the pagelist */
    i = vma_offset >> PAGE_SHIFT;
    pMmPage = virt_to_page(firegl_get_pcie_pageaddr_from_vm(vma,pciemem, i));

    KCL_MEM_IncPageCount_Mapping(pMmPage);

    if (page_address(pMmPage) == 0x0)
    {
        KCL_DEBUG_ERROR("Invalid page address\n");
        return (PAGING_FAULT_SIGBUS);
    }
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
    return pMmPage;
#else
    vmf->page = pMmPage;

    return (0);
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
static __inline__ vm_nopage_ret_t do_vm_gart_nopage(struct vm_area_struct* vma,
                                                    unsigned long address)
#else
static __inline__ int do_vm_gart_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26) */
{

    unsigned long offset;
    struct page *page;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
    unsigned long address = (unsigned long) (vmf->virtual_address);
#endif

    if (address > vma->vm_end)
    {
        KCL_DEBUG_ERROR("Invalid virtual address\n");
        return (PAGING_FAULT_SIGBUS); /* Disallow mremap */
    }          

    offset      = address - vma->vm_start;
    page   = (struct page*)mc_heap_get_page(vma, offset);
    if( !page)
    {
        KCL_DEBUG_ERROR("Invalid page pointer\n");
        return (PAGING_FAULT_SIGBUS); /* Disallow mremap */
    }
    KCL_MEM_IncPageCount_Mapping(page);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
    return page;
#else
    vmf->page = page;

    return (0);
#endif
}



#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
static vm_nopage_ret_t vm_nopage(struct vm_area_struct* vma,
                                 unsigned long address,
                                 int *type)
{
    if (type) *type = VM_FAULT_MINOR;
        return do_vm_nopage(vma, address);
}

/*

    This function is called when a page of a mmap()'ed area is not currently
    visible in the specified VMA.
    Return value is the associated physical address for the requested page.
    (If not implemented, then the kernel default routine would allocate a new,
     zeroed page for servicing us)

    Possible errors: SIGBUS, OutOfMem

    This routine is intended to remap addresses of SHM SAREA
    (which is one or more pages in size)

 */
static vm_nopage_ret_t vm_shm_nopage(struct vm_area_struct* vma,
                                     unsigned long address,
                                     int *type)
{
    if (type) *type = VM_FAULT_MINOR;
        return do_vm_shm_nopage(vma, address);
}

/*

    This routine is intended to remap addresses of a OpenGL context
      (which is one ore more pages in size)

*/
static vm_nopage_ret_t vm_dma_nopage(struct vm_area_struct* vma,
                                     unsigned long address,
                                     int *type)
{
    if (type) *type = VM_FAULT_MINOR;
        return do_vm_dma_nopage(vma, address);
}

static vm_nopage_ret_t vm_kmap_nopage(struct vm_area_struct* vma,
                                     unsigned long address,
                                     int *type)
{
    if (type) *type = VM_FAULT_MINOR;
        return do_vm_kmap_nopage(vma, address);
}

static vm_nopage_ret_t vm_pcie_nopage(struct vm_area_struct* vma,
                                     unsigned long address,
                                     int *type)
{  
       return do_vm_pcie_nopage(vma, address);
}

static vm_nopage_ret_t vm_gart_nopage(struct vm_area_struct* vma,
                                      unsigned long address, 
                                      int *type)
{
       return do_vm_gart_nopage(vma, address);
}

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26) */

void* ATI_API_CALL KCL_MEM_VM_GetRegionFilePrivateData(struct vm_area_struct* vma)
{
    return vma->vm_file->private_data;
}

void* ATI_API_CALL KCL_MEM_VM_GetRegionPrivateData(struct vm_area_struct* vma)
{
    return vma->vm_private_data;
}

unsigned long ATI_API_CALL KCL_MEM_VM_GetRegionStart(struct vm_area_struct* vma)
{
    return vma->vm_start;
}

unsigned long ATI_API_CALL KCL_MEM_VM_GetRegionEnd(struct vm_area_struct* vma)
{
    return vma->vm_end;
}

unsigned long ATI_API_CALL KCL_MEM_VM_GetRegionMapOffset(struct vm_area_struct* vma)
{
    return vma->vm_pgoff << PAGE_SHIFT;
}

char* ATI_API_CALL KCL_MEM_VM_GetRegionFlagsStr(struct vm_area_struct* vma, char* buf)
{
   *(buf + 0) = vma->vm_flags & VM_READ	    ? 'r' : '-';
   *(buf + 1) = vma->vm_flags & VM_WRITE	? 'w' : '-';
   *(buf + 2) = vma->vm_flags & VM_EXEC	    ? 'x' : '-';
   *(buf + 3) = vma->vm_flags & VM_MAYSHARE ? 's' : 'p';
   *(buf + 4) = vma->vm_flags & VM_LOCKED   ? 'l' : '-';
   *(buf + 5) = vma->vm_flags & VM_IO	    ? 'i' : '-';
   *(buf + 6) = 0;
   return buf;
}

char* ATI_API_CALL KCL_MEM_VM_GetRegionProtFlagsStr(struct vm_area_struct* vma, char* buf)
{
    int i = 0;

#ifdef __i386__
	unsigned int pgprot;

    pgprot = pgprot_val(vma->vm_page_prot);
    *(buf + i++) = pgprot & _PAGE_PRESENT  ? 'p' : '-';
    *(buf + i++) = pgprot & _PAGE_RW       ? 'w' : 'r';
    *(buf + i++) = pgprot & _PAGE_USER     ? 'u' : 's';
    *(buf + i++) = pgprot & _PAGE_PWT      ? 't' : 'b';
    *(buf + i++) = pgprot & _PAGE_PCD      ? 'u' : 'c';
    *(buf + i++) = pgprot & _PAGE_ACCESSED ? 'a' : '-';
    *(buf + i++) = pgprot & _PAGE_DIRTY    ? 'd' : '-';
    *(buf + i++) = pgprot & _PAGE_PSE      ? 'm' : 'k';
    *(buf + i++) = pgprot & _PAGE_GLOBAL   ? 'g' : 'l';
#endif /* __i386__ */		
    *(buf + i++) = 0;

    return buf;
}

static
char *kcl_pte_phys_addr_str(pte_t pte, char *buf, kcl_dma_addr_t* phys_address)
{
    if (pte_present(pte))
    {
#if defined(__x86_64__) 
        *phys_address = pte.pte & PAGE_MASK;
#else
        *phys_address = pte_val(pte) & (u64)((u64)PAGE_MASK | (u64)0xf<<32);
#endif
        sprintf(buf, "0x%Lx %c%c%c%c\n",
           *phys_address,
           pte_present (pte) ? 'p' : '-',
           pte_write   (pte) ? 'w' : '-',
           pte_dirty   (pte) ? 'd' : '-',
           pte_young   (pte) ? 'a' : '-');
    }
    else
        *buf = 0;

    return buf;
}

char* ATI_API_CALL KCL_MEM_VM_GetRegionPhysAddrStr(struct vm_area_struct* vma,
                            char* buf, 
                            unsigned long virtual_addr, 
                            kcl_dma_addr_t* phys_address)
{
    pgd_t* pgd_p;
    pmd_t* pmd_p;
    pte_t  pte;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
    pud_t *pud_p;
#endif

    PGD_OFFSET(vma->vm_mm, pgd_p, virtual_addr);
    if (!pgd_present(*pgd_p))
    {
        *buf = 0;
        return buf;
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
    pud_p = pud_offset(pgd_p, virtual_addr);
    if (!pud_present(*pud_p))
    {
        *buf = 0;
        return buf;
    }
    pmd_p = pmd_offset(pud_p, virtual_addr);
#else
    pmd_p = pmd_offset(pgd_p, virtual_addr);
#endif
    if (!pmd_present(*pmd_p))
    {
        *buf = 0;
        return buf;
    }
    PTE_OFFSET(pte, pmd_p, virtual_addr);

    return kcl_pte_phys_addr_str(pte, buf, phys_address);
}

#define TRACE_VM_OPEN_CLOSE(_f, _v)                     \
   KCL_DEBUG_TRACEIN(FN_DRM_VM_OPEN_CLOSE, _v, NULL);          \
   _f(_v);                                              \
   KCL_DEBUG_TRACEOUT(FN_DRM_VM_OPEN_CLOSE, 0, NULL);      

void ip_drm_vm_open(struct vm_area_struct* vma)
{  
    TRACE_VM_OPEN_CLOSE(drm_vm_open, vma);
}
void ip_drm_vm_close(struct vm_area_struct* vma)
{
    TRACE_VM_OPEN_CLOSE(drm_vm_close, vma);  
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)  

#define TRACE_NOPAGE(_f, _v,_a,_t)                  \
   vm_nopage_ret_t  ret;                            \
   KCL_DEBUG_TRACEIN(FN_DRM_NOPAGE, _a, NULL);             \
   ret = _f(_v,_a,_t);                              \
   KCL_DEBUG_TRACEOUT(FN_DRM_NOPAGE, ret, NULL);            \
   return ret;


static vm_nopage_ret_t ip_vm_nopage(struct vm_area_struct* vma,
                                 unsigned long address,
                                 int *type)
{
    TRACE_NOPAGE(vm_nopage, vma, address,type);
}

static vm_nopage_ret_t ip_vm_shm_nopage(struct vm_area_struct* vma,
                                     unsigned long address,
                                     int *type)
{
    TRACE_NOPAGE(vm_shm_nopage,vma, address,type);
}

/*

    This routine is intended to remap addresses of a OpenGL context
      (which is one ore more pages in size)

*/
static vm_nopage_ret_t ip_vm_dma_nopage(struct vm_area_struct* vma,
                                     unsigned long address,
                                     int *type)
{
    TRACE_NOPAGE(vm_dma_nopage,vma, address,type);
}

static vm_nopage_ret_t ip_vm_kmap_nopage(struct vm_area_struct* vma,
                                     unsigned long address,
                                     int *type)
{
    TRACE_NOPAGE(vm_kmap_nopage,vma, address,type);
}

static vm_nopage_ret_t ip_vm_pcie_nopage(struct vm_area_struct* vma,
                                     unsigned long address,
                                     int *type)
{  
    TRACE_NOPAGE(vm_pcie_nopage,vma, address,type);
}

static vm_nopage_ret_t ip_vm_gart_nopage(struct vm_area_struct* vma,
                                      unsigned long address, 
                                      int *type)
{
    TRACE_NOPAGE(vm_gart_nopage,vma, address,type);
}

#else

#define TRACE_FAULT(_f, _v,_a)                                          \
   int  ret;                                                            \
   KCL_DEBUG_TRACEIN(FN_DRM_NOPAGE, (unsigned long)_a->virtual_address, NULL); \
   ret = _f(_v,_a);                                                     \
   KCL_DEBUG_TRACEOUT(FN_DRM_NOPAGE, ret, NULL);                                \
   return ret;

static int ip_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
    TRACE_FAULT(do_vm_fault, vma, vmf);
}

static int ip_vm_shm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
    TRACE_FAULT(do_vm_shm_fault, vma, vmf);
}

static int ip_vm_dma_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
    TRACE_FAULT(do_vm_dma_fault, vma, vmf);
}

static int ip_vm_kmap_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
    TRACE_FAULT(do_vm_kmap_fault, vma, vmf);
}

static int ip_vm_pcie_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{  
    TRACE_FAULT(do_vm_pcie_fault, vma, vmf);
}

static int ip_vm_gart_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
    TRACE_FAULT(do_vm_gart_fault, vma, vmf);
}

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26) */

static struct vm_operations_struct vm_ops =
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)  
    nopage:  ip_vm_nopage,
#else
    fault:   ip_vm_fault,
#endif
    open:    ip_drm_vm_open,
    close:   ip_drm_vm_close,
};

static struct vm_operations_struct vm_shm_ops =
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)  
    nopage:  ip_vm_shm_nopage,
#else
    fault:   ip_vm_shm_fault,
#endif
    open:    ip_drm_vm_open,
    close:   ip_drm_vm_close,
};

static struct vm_operations_struct vm_pci_bq_ops =
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)  
    nopage:  ip_vm_dma_nopage,
#else
    fault:   ip_vm_dma_fault,
#endif
    open:    ip_drm_vm_open,
    close:   ip_drm_vm_close,
};

static struct vm_operations_struct vm_ctx_ops =
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)  
    nopage:  ip_vm_dma_nopage,
#else
    fault:   ip_vm_dma_fault,
#endif
    open:    ip_drm_vm_open,
    close:   ip_drm_vm_close,
};

static struct vm_operations_struct vm_pcie_ops = 
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)  
    nopage:  ip_vm_pcie_nopage,
#else
    fault:   ip_vm_pcie_fault,
#endif
    open:    ip_drm_vm_open,
    close:   ip_drm_vm_close,
};

static struct vm_operations_struct vm_kmap_ops =
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)  
    nopage:  ip_vm_kmap_nopage,
#else
    fault:   ip_vm_kmap_fault,
#endif
    open:    ip_drm_vm_open,
    close:   ip_drm_vm_close,
};

static struct vm_operations_struct vm_gart_ops =
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)  
    nopage:  ip_vm_gart_nopage,
#else
    fault:   ip_vm_gart_fault,
#endif
    open:    ip_drm_vm_open,
    close:   ip_drm_vm_close,
};

#ifdef __AGP__BUILTIN__
static struct vm_operations_struct vm_agp_bq_ops =
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)  
    nopage:  ip_vm_nopage,
#else
    fault:   ip_vm_fault,
#endif
    open:    ip_drm_vm_open,
    close:   ip_drm_vm_close,
};
#endif /* __AGP__BUILTIN__ */

int ATI_API_CALL KCL_MEM_VM_MapRegion(KCL_IO_FILE_Handle filp,
                             struct vm_area_struct* vma, unsigned long long offset,
                             enum kcl_vm_maptype type,
                             int readonly,
                             void *private_data)
{
    unsigned int pages;

    KCL_DEBUG3(FN_FIREGL_MMAP, "start=0x%08lx, "
            "end=0x%08lx, "
            "offset=0x%llx\n",
            vma->vm_start,
            vma->vm_end,
            offset);

    switch (type)
    {
        case __KE_ADPT:
#if defined(__i386__) && !defined(CONFIG_X86_4G)
            if (offset >= __pa(high_memory) )
#endif
            {
                if (boot_cpu_data.x86 > 3)
                {
#ifdef FIREGL_USWC_SUPPORT                
                    if (kcl_mem_pat_status == KCL_MEM_PAT_DISABLED)
#endif                    
                    {
                        pgprot_val(vma->vm_page_prot) |= _PAGE_PCD;
                        pgprot_val(vma->vm_page_prot) &= ~_PAGE_PWT;
                    }
#ifdef FIREGL_USWC_SUPPORT                    
                    else
                    {
                        vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
                    }    
#endif 
                }
                vma->vm_flags |= VM_IO; /* not in core dump */
            }
            if (REMAP_PAGE_RANGE(vma,offset))
            {
                KCL_DEBUG_ERROR(REMAP_PAGE_RANGE_STR " failed\n");
                return -EAGAIN;
            }
            vma->vm_flags |= VM_SHM | VM_RESERVED; /* Don't swap */
            vma->vm_ops = &vm_ops;
			break;

#ifdef FIREGL_USWC_SUPPORT                
        case __KE_ADPT_REG:
			{
#if defined(__i386__) && !defined(CONFIG_X86_4G)
            if (offset >= __pa(high_memory))
#endif
            {
                if (boot_cpu_data.x86 > 3)
                {
                    if (kcl_mem_pat_status == KCL_MEM_PAT_DISABLED)
                    {
                        pgprot_val(vma->vm_page_prot) |= _PAGE_PCD;
                        pgprot_val(vma->vm_page_prot) &= ~_PAGE_PWT;
                    }
                    else
                    {
                        vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot); 
                    }
                }
                vma->vm_flags |= VM_IO; /* not in core dump */
            }
            if (REMAP_PAGE_RANGE(vma,offset))
            {
                KCL_DEBUG_ERROR(REMAP_PAGE_RANGE_STR " failed\n");
                return -EAGAIN;
            }
            vma->vm_flags |= VM_SHM | VM_RESERVED; /* Don't swap */
            vma->vm_ops = &vm_ops;
            }
			break;
#endif                    

        case __KE_SHM:
            vma->vm_flags |= VM_SHM | VM_RESERVED; /* Don't swap */
            vma->vm_ops = &vm_shm_ops;
            break;

        case __KE_SG:

            pages = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;

            vma->vm_flags |= VM_RESERVED;

            //vma->vm_flags |=  VM_SHM | VM_LOCKED; /* DDDDDDDDDDon't swap */
            //vma->vm_mm->locked_vm += pages; /* Kernel tracks aqmount of locked pages */
            vma->vm_ops = &vm_pcie_ops;
            break;

        case __KE_CTX:
            pages = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
            vma->vm_flags |= VM_LOCKED | VM_SHM | VM_RESERVED; /* Don't swap */
            vma->vm_mm->locked_vm += pages; /* Kernel tracks aqmount of locked pages */
            vma->vm_ops = &vm_ctx_ops;
            break;

        case __KE_PCI_BQS:
            pages = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
            vma->vm_flags |= VM_LOCKED | VM_SHM | VM_RESERVED; /* Don't swap */
            vma->vm_mm->locked_vm += pages; /* Kernel tracks aqmount of locked pages */
            vma->vm_ops = &vm_pci_bq_ops;
            break;

#ifdef __AGP__BUILTIN__
        case __KE_AGP:
            // if(dev->agp->cant_use_aperture == 1) 
            // else
            {
#if defined(__i386__) && !defined(CONFIG_X86_4G)
                if (offset >= __pa(high_memory))
#endif
                    vma->vm_flags |= VM_IO; /* not in core dump */

#ifdef FIREGL_USWC_SUPPORT
                if (boot_cpu_data.x86 > 3)
                {
                    if (kcl_mem_pat_status != KCL_MEM_PAT_DISABLED)
                    {
                        vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
                    }    
                }
#endif                

                if (REMAP_PAGE_RANGE(vma,offset))
                {
                    KCL_DEBUG_ERROR(REMAP_PAGE_RANGE_STR " failed\n");
                    return -EAGAIN;
                }
#ifdef __x86_64__
                vma->vm_flags |= VM_RESERVED;
#else
                vma->vm_flags |= VM_SHM | VM_RESERVED; /* Don't swap */
#endif
                vma->vm_ops = &vm_ops;
            }
            break;
        case __KE_AGP_BQS:
            // if(dev->agp->cant_use_aperture == 1) 
            {
#if defined(__i386__) && !defined(CONFIG_X86_4G)
                if (offset >= __pa(high_memory))
#endif
                    vma->vm_flags |= VM_IO; /* not in core dump */

#ifdef FIREGL_USWC_SUPPORT
                if (boot_cpu_data.x86 > 3)
                {
                    if (kcl_mem_pat_status != KCL_MEM_PAT_DISABLED)
                    {
                        vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
                    }   
                }
#endif                

                if (REMAP_PAGE_RANGE(vma,offset))
                {
                    KCL_DEBUG_ERROR(REMAP_PAGE_RANGE_STR " failed\n");
                    return -EAGAIN;
                }
#ifdef __x86_64__
                vma->vm_flags |= VM_RESERVED;
#else
                vma->vm_flags |= VM_SHM | VM_RESERVED; /* Don't swap */
#endif
                vma->vm_ops = &vm_agp_bq_ops;
            }
            break;
#endif /* __AGP__BUILTIN__ */

        case __KE_KMAP:
		    vma->vm_flags |= VM_SHM | VM_RESERVED;
            vma->vm_ops = &vm_kmap_ops;
            if (readonly && (vma->vm_flags & VM_WRITE))
            {
                KCL_DEBUG_ERROR("ERROR: cannot map a readonly map with PROT_WRITE!\n");
                return -EINVAL; // write not allowed - explicitly fail the map!
            }
            break;

         case __KE_GART_USWC:
#ifdef FIREGL_USWC_SUPPORT         
            if (boot_cpu_data.x86 > 3)
            {
                if (kcl_mem_pat_status != KCL_MEM_PAT_DISABLED)
                {
                    vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
                }    
            }
#endif            
            // fall through
         case __KE_GART_CACHEABLE:
             vma->vm_flags |= VM_RESERVED;
             vma->vm_ops = &vm_gart_ops;
             break;
        default:
            /*  This should never happen anyway! */
            KCL_DEBUG_ERROR("kcl_vm_map: Unknown type %d\n", type);
            return -EINVAL;
    }

    if (readonly)
    {
        vma->vm_flags &= ~(VM_WRITE | VM_MAYWRITE);
		pgprot_val(vma->vm_page_prot) &= ~_PAGE_RW;
    }

    vma->vm_file = (struct file*)filp;    /* Needed for drm_vm_open() */
    vma->vm_private_data = private_data;

    return 0;
}

#ifdef FIREGL_USWC_SUPPORT

/** \brief Return PAT enabled state
 *
 * External function to return the driver's PAT enabled state.
 *
 * \return 0 if disabled, nonzero if enabled.
 */

int ATI_API_CALL KCL_is_pat_enabled(void)
{
    return ((int) kcl_mem_pat_status);
}


/** \brief Setup PAT support
 *
 * Sets up driver built-in PAT support.
 *
 * \param[in] info Dummy pointer required for call.
 */

static void kcl_mem_pat_setup (void *info)
{
    unsigned long cr0=0, cr4=0;
    unsigned long flags;
    u64 pat;
  
    local_irq_save(flags);
    cr0 = read_cr0() | 0x40000000;
    write_cr0(cr0);
    wbinvd();

    if (cpu_has_pge)
    {
        cr4 = READ_CR4();
        WRITE_CR4(cr4 & ~X86_CR4_PGE);
    }
     __flush_tlb();

    rdmsrl (MSR_IA32_CR_PAT, pat);
    wrmsrl (MSR_IA32_CR_PAT, (pat & 0xFFFFFFFFFFFF00FFLL) | 0x0000000000000100LL);

    cr0 = read_cr0();
    wbinvd();
    __flush_tlb();
    write_cr0(cr0 & 0xbfffffff);
    if (cpu_has_pge)
    {
        WRITE_CR4(cr4);
    }
    local_irq_restore(flags);

    return;
}


/** \brief Restore PAT
 *
 * Shuts down driver built-in PAT support and restores original PAT state.
 *
 * \param[in] info Dummy pointer required for call.
 */

static void kcl_mem_pat_restore (void *info)
{
    unsigned long cr0 = 0, cr4 = 0;
    unsigned long flags;
  
    local_irq_save(flags);
    cr0 = read_cr0() | 0x40000000;
    write_cr0(cr0);
    wbinvd();

    if (cpu_has_pge)
    {
        cr4 = READ_CR4();
        WRITE_CR4(cr4 & ~X86_CR4_PGE);
    }
     __flush_tlb();
  
    wrmsrl (MSR_IA32_CR_PAT, kcl_mem_pat_orig_val);

    cr0 = read_cr0();
    wbinvd();
    __flush_tlb();
    write_cr0(cr0 & 0xbfffffff);
    if (cpu_has_pge)
    {
        WRITE_CR4(cr4);
    }
    local_irq_restore(flags);

    return;
}


/** \brief Get PAT write combining setting index
 *
 * Scan the PAT register settings to see if write combining has already been
 * set by the kernel and, if so, which PAT index was set.
 *
 * \param[in] pat_reg_val PAT register value.
 *
 * \return index to PAT register set for write combining or -1 if none are set.
 */

static int kcl_mem_pat_get_wc_index (u64 pat_reg_val)
{
    int i;

    for (i = 0; i < 8; i += 1)
    {
        if (((pat_reg_val >> (i*8)) & 0xFF) == 1)
        { 
            return (i);
        } 
    }

#ifdef CONFIG_X86_PAT
    KCL_DEBUG_INFO("Kernel supports PAT but it has been disabled\n");
    KCL_DEBUG_INFO("Using driver built-in PAT support instead\n");
#endif

    return (-1);
}


/** \brief Enable PAT support
 *
 * Detect to see if kernel PAT support is enabled and, if not, enable the
 * driver's built-in PAT support.
 *
 * \param[in] save_orig_pat Flag to save original PAT register value before changing
 *
 * \return PAT status, either disabled, enabled in kernel or enabled in driver.
 */

static kcl_mem_pat_status_t ATI_API_CALL kcl_mem_pat_enable (unsigned int save_orig_pat)
{
    if (firegl_uswc_user_disabled())
    {
        KCL_DEBUG_INFO("USWC is disabled in module parameters\n");
        return (KCL_MEM_PAT_DISABLED);
    }

    if (!cpu_has_pat)
    {
        KCL_DEBUG_INFO("CPU does not support PAT\n");
        return (KCL_MEM_PAT_DISABLED);
    }

    if (save_orig_pat)
    {
        rdmsrl (MSR_IA32_CR_PAT, kcl_mem_pat_orig_val);
    }    

    if (kcl_mem_pat_get_wc_index (kcl_mem_pat_orig_val) < 0)
    {
#ifdef CONFIG_SMP
        if (KCL_SmpCallFunction (kcl_mem_pat_setup, NULL, 0, 1) != 0)
        {
            return (KCL_MEM_PAT_DISABLED);
        }
#endif
        kcl_mem_pat_setup (NULL);
        kcl_mem_pat_status = KCL_MEM_PAT_ENABLED_BUILTIN;
    }
    else
    {
#ifdef CONFIG_X86_PAT
        kcl_mem_pat_status = KCL_MEM_PAT_ENABLED_KERNEL;
#else
        kcl_mem_pat_status = KCL_MEM_PAT_ENABLED_BUILTIN;
#endif
    }

    return (kcl_mem_pat_status);
}


/** \brief Disable PAT support
 *
 * Shut down driver PAT usage within the driver.
 */

static void ATI_API_CALL kcl_mem_pat_disable (void)
{
    if (!cpu_has_pat)
    {
       return;
    }

    if (kcl_mem_pat_status == KCL_MEM_PAT_ENABLED_BUILTIN)
    {
#ifdef CONFIG_SMP
        if (KCL_SmpCallFunction (kcl_mem_pat_restore, NULL, 0, 1) != 0)
        {
            return;
        }
#endif
        kcl_mem_pat_restore (NULL);
        KCL_DEBUG_INFO("Disabling driver built-in PAT support\n");
    }

    kcl_mem_pat_status = KCL_MEM_PAT_DISABLED;

    return;
}
#endif //FIREGL_USWC_SUPPORT

/** \brief Global variable controlling debug output
 *
 * When the value is nonzero tracing debug information is printed.
 * Error messages are printed always.
 * This variable is designed to be touched only by the interrupt handler.
 * If needed to touch it in other placed, please redesign considering
 * possible race conditions
 *
 */
int FIREGL_PUBLIC_DBG_STATE = 1;

/** \brief Kernel Abstraction Services (KAS)
 *
 * TODO: detailed comments, move to a separate file(s), license
 *
 */

/** \brief Naming convention
 *
 * Externally visible interfaces prefixed with 'KAS_'
 * Internal helpers prefixed with 'kas'
 *
 */

/** \brief KAS context type definition */
typedef struct tag_kasContext_t
{
    unsigned long exec_level_invalid; /* Used if execution level is unknown */
    unsigned long exec_level_regular; /* Execution level of regular thread */
    unsigned long exec_level_idh; /* Execution level of interrupt handler */
    unsigned long exec_level_ih; /* Execution level of interrupt deferred handler */
    spinlock_t lock_idh; /* Spinlock for interrupt deferred handler */
    spinlock_t lock_ih;  /* Spinlock for interrupt handler */
    KAS_CallbackWrapper_t callback_wrapper; /* Wrapper with a pointer parameter */
    KAS_CallbackWrapperRet_t callback_wrapper_ret; /* Wrapper with a pointer parameter returning unsigned int */
    unsigned long in_interrupts[NR_CPUS]; /* Used to prevent simultaneous entry of interrupt handler on some SMP systems. */
} kasContext_t;

/** \brief KAS context */
static kasContext_t kasContext; 

/** \brief Kernel support required to enable KAS */
#if defined(cmpxchg)                        && \
    defined(xchg)                           && \
    !defined(CONFIG_M386)
#define KAS_ATOMIC_OPERATIONS_SUPPORT
#endif

/** \brief Check whether current kernel fits KAS requirements and restrictions
 *
 * \return Nonzero on success, zero on fail
 *
 */
static int kasCheckKernelSupport(void)
{
#ifdef KAS_ATOMIC_OPERATIONS_SUPPORT
    /* We use cmpxchg and xchg for atomic exchange operations with pointers.
     * Since Linux implementation casts parameters to unsigned long, here we
     * are making sure casting will be safe */
    return (sizeof(void*) == sizeof(unsigned long) ? 1 : 0);
#else
    return 0;
#endif
}

/** \brief Freeze the thread if kernel requested so because of going to suspend
 *
 * \return Nonzero if freeze has been performed, zero otherwise
 *
 */
unsigned int kas_try_to_freeze(void)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,10)
    return 0;
#else
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,12)
    return try_to_freeze(PF_FREEZE);
#else
    return try_to_freeze();
#endif
#endif
}

/** \brief Storage for execution level(s) */
/* SMP support for 2.6.0 and higher */
DEFINE_PER_CPU(unsigned long, kasExecutionLevel);
#define KAS_EXECUTION_LEVEL_SUPPORT 1

/** \brief Initialize support for execution levels
 *
 * This function must be called before interrupt system is initialized.
 *
 * \param level_init Value to init execution level(s)
 *
 * \return Nonzero on success, zero on fail
 *
 */
static int kasInitExecutionLevels(unsigned long level_init)
{
    unsigned int p;
    KCL_DEBUG5(FN_FIREGL_KAS, "%d\n", level_init);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,0)
    for_each_possible_cpu(p)
#else
    for_each_cpu_mask(p, cpu_possible_map)
#endif
    {
        KCL_DEBUG1(FN_FIREGL_KAS,"Setting initial execution level for CPU # %d\n", p);
        preempt_disable();
        per_cpu(kasExecutionLevel, p) = level_init;
        preempt_enable();
    }

    KCL_DEBUG5(FN_FIREGL_KAS,"%d\n", KAS_EXECUTION_LEVEL_SUPPORT);
    return KAS_EXECUTION_LEVEL_SUPPORT;
}

/** \brief Initialize KAS
 *
 * \param pinit Pointer to KAS initalization structure
 *
 * \return Nonzero on success, 0 on fail
 *
 */
unsigned int ATI_API_CALL KAS_Initialize(KAS_Initialize_t* pinit)
{
    unsigned int ret = 0;

    KCL_DEBUG5(FN_FIREGL_KAS,"0x%08X\n", pinit);

    if (!kasCheckKernelSupport())
    {
        KCL_DEBUG5(FN_FIREGL_KAS,"kernel no tsupport.\n");
        return 0;
    }

    kasContext.callback_wrapper = pinit->callback_wrapper;
    kasContext.callback_wrapper_ret = pinit->callback_wrapper_ret;

    spin_lock_init(&kasContext.lock_idh);
    spin_lock_init(&kasContext.lock_ih);

    kasContext.exec_level_invalid = pinit->exec_level_invalid;
    kasContext.exec_level_regular = pinit->exec_level_regular;
    kasContext.exec_level_idh = pinit->exec_level_idh;
    kasContext.exec_level_ih = pinit->exec_level_ih;
    memset(kasContext.in_interrupts, 0, sizeof(kasContext.in_interrupts));

    ret =  kasInitExecutionLevels(pinit->exec_level_init);

    KCL_DEBUG5(FN_FIREGL_KAS,"%d\n", ret);
    return ret;
}

/** \brief Set execution level for the current processor
 *
 * This function is permitted to be called only from
 * an interrupt handler or from a tasklet, since these two types of callbacks
 * are guaranteed not to be rescheduled to another CPU.  We need to consider
 * this condition because we use per-CPU variables in this function without
 * disabling of preemption (to minimize performance losses)
 *
 * \param level Level to set
 *
 * \return Previous value of the execution level for the current processor
 *
 */
static unsigned long kasSetExecutionLevel(unsigned long level)
{
    unsigned long orig_level;

    orig_level = GET_CPU_VAR(kasExecutionLevel);
    GET_CPU_VAR(kasExecutionLevel) = level;

    return orig_level;
}

/** \brief Internal helper to get execution level for the current processor
 *
 * \return Execution level for the current processor
 *
 */
static unsigned long kas_GetExecutionLevel(void)
{
    return GET_CPU_VAR(kasExecutionLevel);
}

/** \brief Type definition for kas_spin_lock() parameter */
typedef struct tag_kas_spin_lock_info_t
{
    unsigned int routine_type;  /* [IN] Routine type spinlock might be acquired from */
    spinlock_t* plock;          /* [IN] Pointer to an OS spinlock object */
    unsigned int acquire_type;  /* [OUT] Type of acquired spinlock */
    unsigned long flags;        /* [OUT] CPU flags */
} kas_spin_lock_info_t;

/** \brief Type definition for kas_spin_unlock() parameter */
typedef struct tag_kas_spin_unlock_info_t
{
    spinlock_t* plock;          /* [IN] Pointer to an OS spinlock object */
    unsigned int acquire_type;  /* [IN] Type of the spinlock */
    unsigned long flags;        /* [IN] CPU flags */
} kas_spin_unlock_info_t;

/** \brief Internal helper to acquire a spin lock depending on the routine type and current execution level
 *
 * \param lock_info Pointer to the spinlock parameter/returned data structure
 *
 * \return Nonzero on success, zero on fail
 *
 */
static unsigned int kas_spin_lock(kas_spin_lock_info_t* lock_info)
{
    unsigned long flags;
    unsigned int ret = 0;
    unsigned long exec_level = kas_GetExecutionLevel();

    lock_info->acquire_type = KAS_SPINLOCK_TYPE_INVALID;
    lock_info->flags = 0;

    switch (lock_info->routine_type)
    {
        case KAS_ROUTINE_TYPE_REGULAR:
            if (exec_level == kasContext.exec_level_regular)
            {
                spin_lock(lock_info->plock);
                lock_info->acquire_type = KAS_SPINLOCK_TYPE_REGULAR;
            }
            break;

        case KAS_ROUTINE_TYPE_IDH:
            if (exec_level == kasContext.exec_level_regular)
            {
                spin_lock_bh(lock_info->plock);
                lock_info->acquire_type = KAS_SPINLOCK_TYPE_IDH;
            }
            else if (exec_level == kasContext.exec_level_idh)
            {
                spin_lock(lock_info->plock);
                lock_info->acquire_type = KAS_SPINLOCK_TYPE_REGULAR;
            }
            break;

        case KAS_ROUTINE_TYPE_IH:
            if (exec_level == kasContext.exec_level_regular ||
                exec_level == kasContext.exec_level_idh)
            {
                spin_lock_irqsave(lock_info->plock, flags);
                lock_info->acquire_type = KAS_SPINLOCK_TYPE_IH;
                lock_info->flags = flags;
            }
            else if (exec_level == kasContext.exec_level_ih)
            {
                spin_lock(lock_info->plock);
                lock_info->acquire_type = KAS_SPINLOCK_TYPE_REGULAR;
            }
            break;

        default:
            break;
    }

    if (lock_info->acquire_type != KAS_SPINLOCK_TYPE_INVALID)
    {
        ret = 1;
    }

    return ret;
}

/** \brief Internal helper to release a spin lock acquired with kas_spin_lock()
 *
 * \param unlock_info Pointer to the parameter data structure
 *
 * \return Nonzero on success, zero on fail
 *
 */
static unsigned int kas_spin_unlock(kas_spin_unlock_info_t* unlock_info)
{
    unsigned long flags;
    unsigned ret = 1;

    switch (unlock_info->acquire_type)
    {
        case KAS_SPINLOCK_TYPE_REGULAR:
            spin_unlock(unlock_info->plock);
            break;

        case KAS_SPINLOCK_TYPE_IDH:
            spin_unlock_bh(unlock_info->plock);
            break;

        case KAS_SPINLOCK_TYPE_IH:
            flags = unlock_info->flags;
            spin_unlock_irqrestore(unlock_info->plock, flags);
            break;

        default:
            ret = 0;
            break;
    }

    return ret;
}

/** \brief External interface to get execution level for the current processor
 *
 * \return Execution level for the current processor
 *
 */
unsigned long ATI_API_CALL KAS_GetExecutionLevel(void)
{
    unsigned long ret;
    ret = kas_GetExecutionLevel();
    return ret;
}

/** \brief Execute Interrupt Handling Routine
 *
 * This service is supposed to be called only during interrupt handling
 * (the device interrupt must be disabled when calling this service)
 * Interrupt Handling Routine must fit all requirements for interrupt handlers
 *
 * \param ih_routine Routine to run
 * \param if_context Pointer to context to pass to the routine
 *
 * \return Value returned by the ih_routine
 *
 */
unsigned int ATI_API_CALL KAS_Ih_Execute(KAS_IhRoutine_t ih_routine,
                                         void* ih_context)
{
    unsigned int ret;
    unsigned long orig_level;

    KCL_DEBUG5(FN_FIREGL_KAS,"0x%08X, 0x%08X\n", ih_routine, ih_context);

    //Prevent simultaneous entry on some SMP systems.
    if (test_and_set_bit(0, (void *)&(kasContext.in_interrupts[smp_processor_id()])))
    {
        KCL_DEBUG1(FN_FIREGL_KAS, "The processor is handling the interrupt\n");
        return IRQ_NONE;
    }

    spin_lock(&kasContext.lock_ih);
    orig_level = kasSetExecutionLevel(kasContext.exec_level_ih);

    ret = kasContext.callback_wrapper_ret(ih_routine, ih_context);
   KCL_DEBUG1(FN_FIREGL_KAS,"Interrupt handler returned 0x%08X\n", ret);

    kasSetExecutionLevel(orig_level);
    spin_unlock(&kasContext.lock_ih); 

    clear_bit(0, (void *)&(kasContext.in_interrupts[smp_processor_id()]));
    KCL_DEBUG5(FN_FIREGL_KAS,"%d\n", ret);

    return ret;
}

/** \brief Type definition for Interrupt Deferred Handler (IDH) helper routine
 *
 * The helper is required to deal set the required execution level for the
 * time while the routine is being executed
 *
 */
typedef void (*kasIdhRoutine_t)(void* pIdhContext);

/** \brief Type definition of the structure describing IDH object */
typedef struct tag_kasIdh_t
{
    struct tasklet_struct tasklet;
    kasIdhRoutine_t routine;
    void* context;
} kasIdh_t;

/** \brief IDH helper routine
 *
 * This function will called by the OS with the following conditions valid:
 * - interrupts are enabled
 * - this function may be interrupted by the interrupt handler for the same device
 * - this function won't be interrupted by regular threads
 * - the rest of requirements for interrupt handlers applies
 *
 * \param context pointer to the routine context
 *
 * \return None
 *
 */

static void kasIdhRoutineHelper(unsigned long context)
{
    unsigned long orig_level;
    kasIdh_t* idh_obj = (kasIdh_t*)context;

    KCL_DEBUG5(FN_FIREGL_KAS,"0x%08X\n", context);
    spin_lock(&kasContext.lock_idh);
    orig_level = kasSetExecutionLevel(kasContext.exec_level_idh);

    kasContext.callback_wrapper(idh_obj->routine, idh_obj->context);

    kasSetExecutionLevel(orig_level);
    spin_unlock(&kasContext.lock_idh);
    KCL_DEBUG5(FN_FIREGL_KAS,NULL);
}

/** \brief Return IDH object size
 *
 * \return IDH object size in bytes
 *
 */
unsigned int ATI_API_CALL KAS_Idh_GetObjectSize()
{
    unsigned int ret;
    ret = sizeof(kasIdh_t);
    return ret;
}

/** \brief Initialize IDH object
 *
 * \param hIdh handle of (pointer to) the IDH object
 * \param pfnIdhRoutine pointer to the IDH routine
 * \param pIdhContext context pointer to be passed to the IDH routine
 *
 * \return Nonzero (always success)
 *
 */
unsigned int ATI_API_CALL KAS_Idh_Initialize(void* hIdh,
                                             void* pfnIdhRoutine,
                                             void* pIdhContext)
{
    kasIdh_t* idh_obj = (kasIdh_t*)hIdh;
    KCL_DEBUG5(FN_FIREGL_KAS,"0x%08X, 0x%08X, 0x%08X\n", hIdh, pfnIdhRoutine, pIdhContext);
    idh_obj->routine = (kasIdhRoutine_t)pfnIdhRoutine;
    idh_obj->context = pIdhContext;
    tasklet_init(&(idh_obj->tasklet), kasIdhRoutineHelper, (unsigned long) idh_obj);
    KCL_DEBUG5(FN_FIREGL_KAS,NULL);
    return 1;
}

/** \brief Queue IDH
 *
 * \param hIdh handle of (pointer to) the IDH object
 *
 * \return Nonzero (always success)
 *
 */
unsigned int ATI_API_CALL KAS_Idh_Queue(void* hIdh)
{
    kasIdh_t* idh_obj = (kasIdh_t*)hIdh;
    KCL_DEBUG5(FN_FIREGL_KAS,"0x%08X\n", hIdh);
    tasklet_schedule(&(idh_obj->tasklet));
    KCL_DEBUG5(FN_FIREGL_KAS,NULL);
    return 1;
}

/** \brief Type definition for a routine to execute with level synchonization */
typedef void (*kasSyncRoutine_t)(void* pContext);

/** \brief Syncronize execution of a routine with the required level
 *
 * This service guarantees execution of the routine won't overlap with execution
 * of the interrupt handler or the interrupt deferred handler.  Also, this service
 * sets a corresponding execution level for the time the routine is being executed
 *
 * If unsupported value for sync_level is passed the routine is executed without
 * any level synchronization
 *
 * \param pSyncRoutine routine to run
 * \param pContext parameter to pass to the routine
 * \param sync_level execution level to sync the execution with
 *
 * \return Nonzero on success, zero on fail or unsupported sync_level value
 *
 */
unsigned int ATI_API_CALL KAS_ExecuteAtLevel(void* pSyncRoutine,
                                             void* pContext,
                                             unsigned long sync_level)
{
    unsigned long flags = 0;
    unsigned long orig_level = kasContext.exec_level_invalid;

    KCL_DEBUG5(FN_FIREGL_KAS,"0x%08X, 0x%08X, %d\n", pSyncRoutine, pContext, sync_level);

    if (sync_level == kasContext.exec_level_idh)
    {
        spin_lock_bh(&kasContext.lock_idh);
        orig_level = kasSetExecutionLevel(kasContext.exec_level_idh);
    }
    else if (sync_level == kasContext.exec_level_ih)
    {
        spin_lock_irqsave(&kasContext.lock_ih, flags);  // TODO: find out why compiler gives a warning here
        orig_level = kasSetExecutionLevel(kasContext.exec_level_ih);
    }
    else
    {
        KCL_DEBUG_ERROR("Invalid sync level %d -- routine has not been executed\n",
                  sync_level);
        return 0;
    }

    kasContext.callback_wrapper(pSyncRoutine, pContext);

    kasSetExecutionLevel(orig_level);

    if (sync_level == kasContext.exec_level_idh)
    {
        spin_unlock_bh(&kasContext.lock_idh);
    }
    else if (sync_level == kasContext.exec_level_ih)
    {
        spin_unlock_irqrestore(&kasContext.lock_ih, flags);
    }

    KCL_DEBUG5(FN_FIREGL_KAS,NULL);
    return 1;
}

/** \brief Type definition of the structure describing Spinlock object */
typedef struct tag_kasSpinlock_t
{
    spinlock_t lock;            /* OS spinlock object */
    unsigned int routine_type;  /* Type of routine the spinlock might be requested from */
    unsigned int acquire_type;  /* Type of OS spinlock function spinlock acquired with */
    unsigned long flags;        /* Saved CPU flags */
} kasSpinlock_t;

/** \brief Return Spinlock object size
 *
 * \return Spinlock object size in bytes
 *
 */
unsigned int ATI_API_CALL KAS_Spinlock_GetObjectSize(void)
{
    unsigned int ret;
    ret = sizeof(kasSpinlock_t);
    return ret;
}

/** \brief Initialize Spinlock object
 *
 * \param hSpinLock handle of (pointer to) the Spinlock object
 * \param spinlock_type type of routine the spinlock might be requested from
 *
 * \return Nonzero (always success)
 *
 */
unsigned int ATI_API_CALL KAS_Spinlock_Initialize(void* hSpinLock,
                                                  unsigned int spinlock_type)
{
    kasSpinlock_t* spinlock_obj = (kasSpinlock_t*)hSpinLock;
    KCL_DEBUG5(FN_FIREGL_KAS,"0x%08X, %d\n", hSpinLock, spinlock_type);
    spinlock_obj->acquire_type = KAS_SPINLOCK_TYPE_INVALID;
    spinlock_obj->routine_type = spinlock_type;
    spin_lock_init(&(spinlock_obj->lock));
    return 1;
}

/** \brief Acquire Spinlock object
 *
 * \param hSpinLock handle of (pointer to) the Spinlock object
 *
 * \return Nonzero on success, zero on fail
 *
 */
unsigned int ATI_API_CALL KAS_Spinlock_Acquire(void* hSpinLock)
{
    unsigned int ret = 0;   /* Fail by default */
    kasSpinlock_t* spinlock_obj = (kasSpinlock_t*)hSpinLock;
    kas_spin_lock_info_t spin_lock_info;

    KCL_DEBUG5(FN_FIREGL_KAS,"0x%08X\n", hSpinLock);

    spin_lock_info.routine_type = spinlock_obj->routine_type;
    spin_lock_info.plock = &(spinlock_obj->lock);

    ret = kas_spin_lock(&spin_lock_info);

    spinlock_obj->acquire_type = spin_lock_info.acquire_type;
    spinlock_obj->flags = spin_lock_info.flags;

    KCL_DEBUG5(FN_FIREGL_KAS,"%d\n", ret);
    return ret;
}

/** \brief Release Spinlock object
 *
 * \param hSpinLock handle of (pointer to) the Spinlock object
 *
 * \return Nonzero on success, zero on fail
 *
 */
unsigned int ATI_API_CALL KAS_Spinlock_Release(void* hSpinLock)
{
    unsigned int ret = 0;   /* Fail by default */
    kasSpinlock_t* spinlock_obj = (kasSpinlock_t*)hSpinLock;
    kas_spin_unlock_info_t spin_unlock_info;

    KCL_DEBUG5(FN_FIREGL_KAS,"0x%08X\n", hSpinLock);

    spin_unlock_info.plock = &(spinlock_obj->lock);
    spin_unlock_info.acquire_type = spinlock_obj->acquire_type;
    spin_unlock_info.flags = spinlock_obj->flags;

    if ((ret = kas_spin_unlock(&spin_unlock_info)))
    {
        spinlock_obj->acquire_type = KAS_SPINLOCK_TYPE_INVALID;
    }

    KCL_DEBUG5(FN_FIREGL_KAS,"%d\n", ret);
    return ret;
}

/** \brief Type definition of the structure describing Slab Cache object */
typedef struct tag_kasSlabCache_t
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
    struct kmem_cache *cache;   /* OS slab cache object */
#else
    kmem_cache_t *cache;        /* OS slab cache object */
#endif
    spinlock_t lock;            /* OS spinlock object protecting the cache */
    unsigned int routine_type;  /* Type of routine the cache might be accessed from */
    char name[20];              /* Cache object name (kernel 2.4 restricts its length to 19 chars) */
} kasSlabCache_t;

/** \brief Return Slab Cache object size
 *
 * \return Slab Cache object size in bytes
 *
 */
unsigned int ATI_API_CALL KAS_SlabCache_GetObjectSize(void)
{
    unsigned int ret;
    ret = sizeof(kasSlabCache_t);
    return ret;
}

/** \brief Initialize Slab Cache object
 *
 * \param hSlabCache handle of (pointer to) a Slab Cache object
 * \param iEntrySize size (in bytes) of each cache entry
 * \param access_type type of routine the spinlock might be requested from
 *
 * \return Nonzero on success, zero on fail
 *
 */

unsigned int ATI_API_CALL KAS_SlabCache_Initialize(void* hSlabCache,
                                                   unsigned int iEntrySize,
                                                   unsigned int access_type)
{
    unsigned int ret = 0;
    kasSlabCache_t* slabcache_obj = (kasSlabCache_t*)hSlabCache;

    KCL_DEBUG5(FN_FIREGL_KAS,"0x%08X, %d, %d\n", hSlabCache, iEntrySize, access_type);

    slabcache_obj->routine_type = access_type;
    spin_lock_init(&(slabcache_obj->lock));
    sprintf(slabcache_obj->name, "kas%p", slabcache_obj);

    KCL_DEBUG1(FN_FIREGL_KAS,"creating slab object '%s'\n", slabcache_obj->name);

    if ((slabcache_obj->cache =
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
         kmem_cache_create(slabcache_obj->name, iEntrySize, 0, 0, NULL, NULL)))
#else
         kmem_cache_create(slabcache_obj->name, iEntrySize, 0, 0, NULL)))
#endif
{
        ret = 1;
    }

    KCL_DEBUG5(FN_FIREGL_KAS,"%d\n", ret);
    return ret;
}

/** \brief Destroy Slab Cache object
 *
 * \param hSlabCache handle of (pointer to) a Slab Cache object
 *
 * \return Nonzero on success, zero on fail
 *
 */
unsigned int ATI_API_CALL KAS_SlabCache_Destroy(void* hSlabCache)
{
    unsigned int ret = 0;
    kasSlabCache_t* slabcache_obj = (kasSlabCache_t*)hSlabCache;

    KCL_DEBUG5(FN_FIREGL_KAS,"0x%08X\n", hSlabCache);

    if (!(slabcache_obj->cache))
    {
        KCL_DEBUG_ERROR("slab object '%s' is not initialized\n");
        return 0;
    }

    KCL_DEBUG1(FN_FIREGL_KAS,"destroying slab object '%s'\n", slabcache_obj->name);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
    kmem_cache_destroy(slabcache_obj->cache);
    ret = 1;
    slabcache_obj->cache = NULL;
#else
    if (kmem_cache_destroy(slabcache_obj->cache) == 0)
    {
        ret = 1;
        slabcache_obj->cache = NULL;
    }
    else
    {
        KCL_DEBUG_ERROR("destroying failed\n");
    }
#endif

    KCL_DEBUG5(FN_FIREGL_KAS,"%d\n", ret);
    return ret;
}

/** \brief Allocate an entry in a Slab Cache
 *
 * \param hSlabCache handle of (pointer to) a Slab Cache object
 *
 * \return Pointer to the allocated entry (NULL indicates an error)
 *
 */
void* ATI_API_CALL KAS_SlabCache_AllocEntry(void* hSlabCache)
{
    kas_spin_lock_info_t spin_lock_info;
    kas_spin_unlock_info_t spin_unlock_info;
    void* pentry = NULL;
    kasSlabCache_t* slabcache_obj = (kasSlabCache_t*)hSlabCache;
    int alloc_flags = 0;

    KCL_DEBUG5(FN_FIREGL_KAS, "0x%08X\n", hSlabCache);

    /* Protect the operation with spinlock */
    spin_lock_info.routine_type = slabcache_obj->routine_type;
    spin_lock_info.plock = &(slabcache_obj->lock);

    if (!kas_spin_lock(&spin_lock_info))
    {
        KCL_DEBUG_ERROR("Unable to grab cache spinlock\n");
        return NULL; /* No spinlock - no operation */
    }

    /* Allocate an entry */
    if (kas_GetExecutionLevel() == kasContext.exec_level_ih ||
        kas_GetExecutionLevel() == kasContext.exec_level_idh)
    {
        KCL_DEBUG1(FN_FIREGL_KAS,"Performing entry allocation atomically\n");
        alloc_flags |= GFP_ATOMIC;
    }

    pentry = kmem_cache_alloc(slabcache_obj->cache, alloc_flags);

    /* Release the spinlock */
    spin_unlock_info.plock = &(slabcache_obj->lock);
    spin_unlock_info.acquire_type = spin_lock_info.acquire_type;
    spin_unlock_info.flags = spin_lock_info.flags;

    if (!kas_spin_unlock(&spin_unlock_info))
    {
        /* Signal an error if there were troubles releasing the spinlock */
        KCL_DEBUG_ERROR("Unable to release cache spinlock\n");
        kmem_cache_free(slabcache_obj->cache, pentry);
        pentry = NULL;
    }

    /* Return pointer to the allocated entry */
    KCL_DEBUG5(FN_FIREGL_KAS,"0x%08X\n", pentry);
    return pentry;
}

/** \brief Release an entry from a Slab Cache
 *
 * \param hSlabCache handle of (pointer to) a Slab Cache object
 * \param pvEntry pointer to the entry to be released
 *
 * \return Nonzero on success, zero on fail
 *
 */
unsigned int ATI_API_CALL KAS_SlabCache_FreeEntry(void* hSlabCache,
                                                  void* pvEntry)
{
    kas_spin_lock_info_t spin_lock_info;
    kas_spin_unlock_info_t spin_unlock_info;
    kasSlabCache_t* slabcache_obj = (kasSlabCache_t*)hSlabCache;
    unsigned int ret = 0;

    KCL_DEBUG5(FN_FIREGL_KAS,"0x%08X, 0x%08X\n", hSlabCache, pvEntry);

    /* Protect the operation with spinlock */
    spin_lock_info.routine_type = slabcache_obj->routine_type;
    spin_lock_info.plock = &(slabcache_obj->lock);

    if (!kas_spin_lock(&spin_lock_info))
    {
        /* No spinlock - no operation (better to fail the release than to
         * deal with race condition on the cache object) */
        KCL_DEBUG_ERROR("Unable to grab cache spinlock\n");
        return 0;
    }

    /* Release the entry */
    kmem_cache_free(slabcache_obj->cache, pvEntry);

    /* Release the spinlock and return */
    spin_unlock_info.plock = &(slabcache_obj->lock);
    spin_unlock_info.acquire_type = spin_lock_info.acquire_type;
    spin_unlock_info.flags = spin_lock_info.flags;

    ret = kas_spin_unlock(&spin_unlock_info);
    KCL_DEBUG5(FN_FIREGL_KAS,"%d\n", ret);
    return ret;
}

/** \brief Type definition of the structure describing Event object */
typedef struct tag_kasEvent_t
{
    wait_queue_head_t wq_head;
    atomic_t state;
} kasEvent_t;

/** \brief Return Event object size
 *
 * \return Event object size in bytes
 *
 */
unsigned int ATI_API_CALL KAS_Event_GetObjectSize(void)
{
    unsigned int ret;
    ret = sizeof(kasEvent_t);
    return ret;
}

/** \brief Initialize Event object
 *
 * \param hEvent handle of (pointer to) an Event object
 *
 * \return Nonzero on success, zero on fail
 *
 */
unsigned int ATI_API_CALL KAS_Event_Initialize(void* hEvent)
{
    kasEvent_t* event_obj = (kasEvent_t*)hEvent;
    KCL_DEBUG5(FN_FIREGL_KAS,"0x%08X\n", hEvent);
    init_waitqueue_head(&(event_obj->wq_head));
    atomic_set(&(event_obj->state), 0);
    return 1;
}

/** \brief Set event to the signalled state and wake up all waiters
 *
 * The event stays in the signalled state until cleared explicitly
 *
 * \param hEvent handle of (pointer to) an Event object
 *
 * \return Nonzero on success, zero on fail
 *
 */
unsigned int ATI_API_CALL KAS_Event_Set(void* hEvent)
{
    kasEvent_t* event_obj = (kasEvent_t*)hEvent;
    KCL_DEBUG5(FN_FIREGL_KAS,"0x%08X\n", hEvent);
    atomic_set(&(event_obj->state), 1);
    wake_up_all(&(event_obj->wq_head));
    KCL_DEBUG5(FN_FIREGL_KAS,NULL);
    return 1;
}

/** \brief Clear the event (set it to the non-signalled state)
 *
 * \param hEvent handle of (pointer to) an Event object
 *
 * \return Nonzero on success, zero on fail
 *
 */
unsigned int ATI_API_CALL KAS_Event_Clear(void* hEvent)
{
    kasEvent_t* event_obj = (kasEvent_t*)hEvent;
    KCL_DEBUG5(FN_FIREGL_KAS,"0x%08X\n", hEvent);
    atomic_set(&(event_obj->state), 0);
    return 1;
}

/** \brief Wait for the event
 *
 * If event is already signalled, return right away.
 * Otherwise, wait until it is signalled
 *
 * \param hEvent handle of (pointer to) an Event object
 * \param timeout timeout value in nanoseconds
 * \param timeout_use 1 means wait with timeout, 0 means wait unconditionally
 *
 * \return KAS_RETCODE_OK on success
 *         KAS_RETCODE_ERROR on error
 *         KAS_RETCODE_TIMEOUT on timeout
 *         KAS_RETCODE_SIGNAL if waiting on the event was interrupted by a signal
 *
 */
unsigned int ATI_API_CALL KAS_Event_WaitForEvent(void* hEvent,
                                                 unsigned long long timeout,
                                                 unsigned int timeout_use)
{
    unsigned int ret = KAS_RETCODE_ERROR;
    kasEvent_t* event_obj = (kasEvent_t*)hEvent;

    KCL_DEBUG5(FN_FIREGL_KAS,"0x%08X, %lld, %d\n", hEvent, timeout, timeout_use);

    if (timeout_use)
    {
        unsigned long long timeout_jiffies_ull = (timeout * HZ) / 1000000000;
        KCL_DEBUG1(FN_FIREGL_KAS,"timeout jiffies = %lld(0x%08X)\n",
                      timeout_jiffies_ull,
                      timeout_jiffies_ull);

        if (timeout_jiffies_ull <= 0x7FFFFFFF)
        {
            long timeout_jiffies = (long) timeout_jiffies_ull;

            ret = KAS_RETCODE_OK;

            while (!atomic_read(&(event_obj->state)))
            {
                int freeze_ret = 0;

                KCL_DEBUG1(FN_FIREGL_KAS,"wait for the event with timeout: starting\n");
                timeout_jiffies = wait_event_interruptible_timeout(
                                        event_obj->wq_head,
                                        atomic_read(&(event_obj->state)),
                                        timeout_jiffies);
                // TODO: implement for 2.4
                KCL_DEBUG1(FN_FIREGL_KAS,"wait for the event with timeout: finished\n");
                KCL_DEBUG1(FN_FIREGL_KAS,"wait returned %d\n", timeout_jiffies);
                KCL_DEBUG1(FN_FIREGL_KAS,"event object state = %d\n", atomic_read(&(event_obj->state)));

                // Power management - kernel will require our thread to freeze
                // before it will be able to start suspend
                KCL_DEBUG1(FN_FIREGL_KAS,"try to freeze\n");
                freeze_ret = kas_try_to_freeze();
                KCL_DEBUG1(FN_FIREGL_KAS,"try to freeze returned %d\n", freeze_ret);

                if (freeze_ret)
                {
                    KCL_DEBUG1(FN_FIREGL_KAS,"wait was interrupted by freezing -- start wait over again\n");
                    timeout_jiffies = (long) timeout_jiffies_ull;
                    continue;
                }

                if (timeout_jiffies == -ERESTARTSYS)
                {
                    KCL_DEBUG1(FN_FIREGL_KAS,"wait was interrupted by a signal\n");
                    ret = KAS_RETCODE_SIGNAL;
                    break;
                }

                if (timeout_jiffies <= 0)
                {
                    KCL_DEBUG1(FN_FIREGL_KAS,"sleep finished due to timeout (timeout_jiffies = %ld)\n",
                                timeout_jiffies);
                    ret = KAS_RETCODE_TIMEOUT;
                    break;
                }
            }
        }
        else
        {
            KCL_DEBUG_ERROR("timeout value is too big (0x%08X)\n", timeout_jiffies_ull);
        }
    }
    else
    {
        ret = KAS_RETCODE_OK;

        while (!atomic_read(&(event_obj->state)))
        {
            int wait_ret = 0;
            int freeze_ret = 0;

            KCL_DEBUG1(FN_FIREGL_KAS,"wait for the event without timeout: starting\n");
            wait_ret = wait_event_interruptible(
                    event_obj->wq_head, atomic_read(&(event_obj->state)));
            KCL_DEBUG1(FN_FIREGL_KAS,"wait for the event without timeout: finished\n");
            KCL_DEBUG1(FN_FIREGL_KAS,"wait returned %d\n", wait_ret);
            KCL_DEBUG1(FN_FIREGL_KAS,"event object state = %d\n", atomic_read(&(event_obj->state)));

            // Power management - kernel will require our thread to freeze
            // before it will be able to start suspend
            KCL_DEBUG1(FN_FIREGL_KAS,"try to freeze\n");
            freeze_ret = kas_try_to_freeze();
            KCL_DEBUG1(FN_FIREGL_KAS,"try to freeze returned %d\n", freeze_ret);

            if (freeze_ret)
            {
                KCL_DEBUG1(FN_FIREGL_KAS,"wait was interrupted by freezing -- start wait over again\n");
                continue;
            }

            if (wait_ret == -ERESTARTSYS)
            {
                KCL_DEBUG1(FN_FIREGL_KAS,"wait was interrupted by a signal -- return as timeout\n");
                ret = KAS_RETCODE_SIGNAL;
                break;
            }
        }
    }

    KCL_DEBUG5(FN_FIREGL_KAS,"%d\n", ret);
    return ret;
}

/** \brief Type definition of the structure describing Mutex object */
typedef struct tag_kasMutex_t
{
    struct semaphore mutex;
    // Recursive locking semantics:
    // To prevent race conditions, these fields are only modified
    // while holding the mutex.
    unsigned count;
    pid_t pid;
} kasMutex_t;

/** \brief Return Mutex object size
 *
 * \return Mutex object size in bytes
 *
 */
unsigned int ATI_API_CALL KAS_Mutex_GetObjectSize(void)
{
    return sizeof(kasMutex_t);
}

/** \brief Initialize Mutex object
 *
 * \param hMutex handle of (pointer to) the Mutex object
 *
 * \return Nonzero (always success)
 *
 */
unsigned int ATI_API_CALL KAS_Mutex_Initialize(void* hMutex)
{
    kasMutex_t* mutex_obj = (kasMutex_t*)hMutex;
    sema_init(&(mutex_obj->mutex), 1);
    mutex_obj->count = 0;
    mutex_obj->pid = 0;
    return 1;
}

/** \brief Acquire Mutex object
 *
 * \param hMutex handle of (pointer to) the Mutex object
 * \param timeout timeout value in nanoseconds
 * \param timeout_use 1 means wait with timeout, 0 means wait unconditionally
 *
 * \return KAS_RETCODE_OK on success
 *         KAS_RETCODE_ERROR on error
 *         KAS_RETCODE_TIMEOUT on timeout
 *
 */
unsigned int ATI_API_CALL KAS_Mutex_Acquire(void* hMutex,
                                            unsigned long long timeout,
                                            unsigned int timeout_use)
{
    unsigned int ret = KAS_RETCODE_ERROR;
    kasMutex_t* mutex_obj = (kasMutex_t*)hMutex;

    if (mutex_obj->pid == current->pid)
    {
        mutex_obj->count++;
        if (mutex_obj->count == 0)
        {
            mutex_obj->count--;
            KCL_DEBUG_ERROR("Mutex counter overflow.\n");
            return KAS_RETCODE_ERROR;
        }
        return KAS_RETCODE_OK;
    }

    if (timeout_use)
    {
        unsigned long long timeout_jiffies_ull = (timeout * HZ) / 1000000000;

        if (timeout_jiffies_ull <= 0x7FFFFFFF)
        {
            unsigned long jiffies_expire =
                    jiffies + (unsigned long) timeout_jiffies_ull;

            while (time_before(jiffies, jiffies_expire))
            {
                if (down_trylock(&(mutex_obj->mutex)) == 0)
                {
                    ret = KAS_RETCODE_OK;
                }

                schedule();
            }

            ret = KAS_RETCODE_TIMEOUT;
        }
    }
    else
    {
        down(&(mutex_obj->mutex));
        ret = KAS_RETCODE_OK;
    }

    if (ret == KAS_RETCODE_OK)
    {
        // successfully acquired, start counting
        mutex_obj->pid = current->pid;
        mutex_obj->count = 1;
    }
    return ret;
}

/** \brief Release Mutex object
 *
 * \param hMutex handle of (pointer to) the Mutex object
 *
 * \return Nonzero on success, zero on fail
 *
 */
unsigned int ATI_API_CALL KAS_Mutex_Release(void* hMutex)
{
    kasMutex_t* mutex_obj = (kasMutex_t*)hMutex;

    if (mutex_obj->pid != current->pid)
    {
        KCL_DEBUG_ERROR("Mutex released without holding it.\n");
        return 0;
    }
    if (--mutex_obj->count == 0)
    {
        mutex_obj->pid = 0;
        up(&(mutex_obj->mutex));
    }
    return 1;
}

/** \brief Type definition of the structure describing Thread object
 *
 * Thread object must be used in the following scenario only:
 *
 * 1) Create a Thread object
 * 2) Start the Thread object
 * 3) Tell the thread routine it has to finish. The thread routine has to signal
 *    after it finishes
 * 4) Issue "wait for finish" operation
 *
 * Don't try to reuse a Thread object or issue multiple start operation on the same
 * object
 *
 */

/** \brief Type definition for Thread Routine */
typedef void (*KAS_ThreadRoutine_t)(void* pContext);

/** \brief Type definition of the structure describing Thread object */
typedef struct tag_kasThread_t
{
    wait_queue_head_t wq_head;
    atomic_t state;
    KAS_ThreadRoutine_t routine;
    void* pcontext;
} kasThread_t;

/** \brief Thread helper routine
 *
 * \param pcontext pointer to the routine context
 *
 * \return None
 *
 */
static int kasThreadRoutineHelper(void* pcontext)
{
    kasThread_t* thread_obj = (kasThread_t*)pcontext;
    KCL_DEBUG5(FN_FIREGL_KAS,
       "context:0x%08X, thread_obj->routine = 0x%08X, thread_obj->pcontext = 0x%08X \n",
       pcontext, thread_obj->routine, thread_obj->pcontext);
    kasContext.callback_wrapper(thread_obj->routine, thread_obj->pcontext);
    KCL_DEBUG5(FN_FIREGL_KAS, NULL);
    
    return 0;
}

/** \brief Return Thread object size
 *
 * \return Thread object size in bytes
 *
 */
unsigned int ATI_API_CALL KAS_Thread_GetObjectSize(void)
{
    unsigned int ret;
    ret = sizeof(kasThread_t);
    return ret;
}

/** \brief Start Thread
 *
 * \param hThread handle of (pointer to) a Thread object
 * \param routine pointer to a thread routine
 * \param pcontext context pointer to be passed to the thread routine
 *
 * \return Nonzero (always success)
 *
 */
unsigned int ATI_API_CALL KAS_Thread_Start(void* hThread,
                                           void* routine,
                                           void* pcontext)
{
    struct task_struct *fireglThread = NULL;
    kasThread_t* thread_obj = (kasThread_t*)hThread;

    KCL_DEBUG5(FN_FIREGL_KAS,"0x%08X, 0x%08X, 0x%08X", hThread, routine, pcontext);

    atomic_set(&(thread_obj->state), 1);
    init_waitqueue_head(&(thread_obj->wq_head));
    thread_obj->routine = (KAS_ThreadRoutine_t)routine;
    thread_obj->pcontext = pcontext;

    fireglThread = kthread_run(kasThreadRoutineHelper, thread_obj, "firegl");

    if (IS_ERR(fireglThread))
    {
        KCL_DEBUG_ERROR("Failed to start firegl kernel thread!\n");
    }
    else
    {
        KCL_DEBUG_INFO("Firegl kernel thread PID: %d\n", fireglThread->pid);
    }

    KCL_DEBUG5(FN_FIREGL_KAS,NULL);
    return 1;
}

/** \brief Wait until thread routine signals it finished
 *
 * \param hThread handle of (pointer to) a Thread object
 *
 * \return Nonzero (always success)
 *
 */
unsigned int ATI_API_CALL KAS_Thread_WaitForFinish(void* hThread)
{
    kasThread_t* thread_obj = (kasThread_t*)hThread;
    KCL_DEBUG5(FN_FIREGL_KAS,"0x%08X\n", hThread);
    wait_event_interruptible(
            thread_obj->wq_head, !atomic_read(&(thread_obj->state)));
    // TODO: add support for signals and power management
    return 1;
}

/** \brief Signal the thread finished its code path
 *
 * \param hThread handle of (pointer to) a Thread object
 *
 * \return Nonzero (always success)
 *
 */
unsigned int ATI_API_CALL KAS_Thread_Finish(void* hThread)
{
    kasThread_t* thread_obj = (kasThread_t*)hThread;
    KCL_DEBUG5(FN_FIREGL_KAS,"0x%08X\n", hThread);
    atomic_set(&(thread_obj->state), 0);
    wake_up_all(&(thread_obj->wq_head));
    return 1;
}

/** \brief Type definition of the structure describing InterlockedList head object */
typedef struct tag_kasInterlockedListHead_t
{
    struct list_head head;
    spinlock_t lock;
    unsigned int routine_type;  /* Type of routine the list might be accessed from */
} kasInterlockedListHead_t;

/** \brief Type definition of the structure describing InterlockedList entry object */
typedef struct tag_kasInterlockedListEntry_t
{
    struct list_head entry;
} kasInterlockedListEntry_t;

/** \brief Return InterlockedList head object size
 *
 * \return InterlockedList head object size in bytes
 *
 */
unsigned int ATI_API_CALL KAS_InterlockedList_GetListHeadSize(void)
{
    unsigned int ret;
    ret = sizeof(kasInterlockedListHead_t);
    return ret;
}

/** \brief Return InterlockedList entry object size
 *
 * \return InterlockedList entry object size in bytes
 *
 */
unsigned int ATI_API_CALL KAS_InterlockedList_GetListEntrySize(void)
{
    unsigned int ret;
    ret = sizeof(kasInterlockedListEntry_t);
    return ret;
}

/** \brief Initialize InterlockedList object
 *
 * \param hListHead handle of (pointer to) an InterlockedList object
 *
 * \return Nonzero (always success)
 *
 */
unsigned int ATI_API_CALL KAS_InterlockedList_Initialize(void* hListHead,
                                                    unsigned int access_type)
{
    kasInterlockedListHead_t* listhead_obj =
            (kasInterlockedListHead_t*)hListHead;
    KCL_DEBUG5(FN_FIREGL_KAS,"0x%08X, %d\n", hListHead, access_type);
    INIT_LIST_HEAD(&(listhead_obj->head));
    spin_lock_init(&(listhead_obj->lock));
    listhead_obj->routine_type = access_type;
    return 1;
}

/** \brief Insert an entry at the tail of a list
 *
 * \param hListHead handle of (pointer to) an InterlockedList head object
 * \param hListEntry handle of (pointer to) an InterlockedList entry object
 * \param phPrevEntry pointer to the handle of (pointer to) the previous tail entry
 *
 * \return Nonzero on success, zero on fail
 *
 */
unsigned int ATI_API_CALL KAS_InterlockedList_InsertAtTail(void* hListHead,
                                                           void* hListEntry,
                                                           void** phPrevEntry)
{
    kasInterlockedListHead_t* listhead_obj =
            (kasInterlockedListHead_t*)hListHead;
    kasInterlockedListEntry_t* listentry_obj =
            (kasInterlockedListEntry_t*)hListEntry;
    struct list_head *head = &(listhead_obj->head);
    struct list_head *entry = &(listentry_obj->entry);
    kas_spin_lock_info_t spin_lock_info;
    kas_spin_unlock_info_t spin_unlock_info;
    unsigned int ret = 0;

    KCL_DEBUG5(FN_FIREGL_KAS,"0x%08X, 0x%08X, 0x%08X\n", hListHead, hListEntry, phPrevEntry);

    /* Protect the operation with spinlock */
    spin_lock_info.routine_type = listhead_obj->routine_type;
    spin_lock_info.plock = &(listhead_obj->lock);

    if (!kas_spin_lock(&spin_lock_info))
    {
        KCL_DEBUG_ERROR("Unable to grab list spinlock\n");
        return 0; /* No spinlock - no operation */
    }

    /* Get pointer to the current tail entry */
    if (list_empty(head))
    {
        *phPrevEntry = NULL;
    }
    else
    {
        *phPrevEntry = list_entry(head->prev, kasInterlockedListEntry_t, entry);
    }

    KCL_DEBUG1(FN_FIREGL_KAS,"previous entry = 0x%08X\n", *phPrevEntry);

    /* Add the new entry to the tail of the list */
    list_add_tail(entry, head);

    /* Release the spinlock and return */
    spin_unlock_info.plock = &(listhead_obj->lock);
    spin_unlock_info.acquire_type = spin_lock_info.acquire_type;
    spin_unlock_info.flags = spin_lock_info.flags;

    ret = kas_spin_unlock(&spin_unlock_info);
    KCL_DEBUG5(FN_FIREGL_KAS,"%d", ret);
    return ret;
}

/** \brief Insert an entry at the head of a list
 *
 * \param hListHead handle of (pointer to) an InterlockedList head object
 * \param hListEntry handle of (pointer to) an InterlockedList entry object
 * \param phPrevEntry pointer to the handle of (pointer to) the previous head entry
 *
 * \return Nonzero on success, zero on fail
 *
 */
unsigned int ATI_API_CALL KAS_InterlockedList_InsertAtHead(void* hListHead,
                                                           void* hListEntry,
                                                           void** phPrevEntry)
{
    kasInterlockedListHead_t* listhead_obj =
            (kasInterlockedListHead_t*)hListHead;
    kasInterlockedListEntry_t* listentry_obj =
            (kasInterlockedListEntry_t*)hListEntry;
    struct list_head *head = &(listhead_obj->head);
    struct list_head *entry = &(listentry_obj->entry);
    kas_spin_lock_info_t spin_lock_info;
    kas_spin_unlock_info_t spin_unlock_info;
    unsigned int ret = 0;

    KCL_DEBUG5(FN_FIREGL_KAS,"0x%08X, 0x%08X, 0x%08X", hListHead, hListEntry, phPrevEntry);

    /* Protect the operation with spinlock */
    spin_lock_info.routine_type = listhead_obj->routine_type;
    spin_lock_info.plock = &(listhead_obj->lock);

    if (!kas_spin_lock(&spin_lock_info))
    {
        KCL_DEBUG_ERROR("Unable to grab list spinlock");
        return 0; /* No spinlock - no operation */
    }

    /* Get pointer to the current head entry */
    if (list_empty(head))
    {
        *phPrevEntry = NULL;
    }
    else
    {
        *phPrevEntry = list_entry(head->next, kasInterlockedListEntry_t, entry);
    }

    KCL_DEBUG1(FN_FIREGL_KAS,"previous entry = 0x%08X", *phPrevEntry);

    /* Add the new entry to the beginning of the list */
    list_add(entry, head);

    /* Release the spinlock and return */
    spin_unlock_info.plock = &(listhead_obj->lock);
    spin_unlock_info.acquire_type = spin_lock_info.acquire_type;
    spin_unlock_info.flags = spin_lock_info.flags;

    ret = kas_spin_unlock(&spin_unlock_info);
    KCL_DEBUG5(FN_FIREGL_KAS,"%d", ret);
    return ret;
}

/** \brief Remove the head entry from a list
 *
 * \param hListHead handle of (pointer to) an InterlockedList head object
 * \param phRemovedEntry pointer to the handle of (pointer to) the removed entry
 *
 * \return Nonzero on success, zero on fail
 *
 */
unsigned int ATI_API_CALL KAS_InterlockedList_RemoveAtHead(void* hListHead,
                                                        void** phRemovedEntry)
{
    kasInterlockedListHead_t* listhead_obj =
            (kasInterlockedListHead_t*)hListHead;
    struct list_head *head = &(listhead_obj->head);
    kas_spin_lock_info_t spin_lock_info;
    kas_spin_unlock_info_t spin_unlock_info;
    unsigned int ret = 0;

    KCL_DEBUG5(FN_FIREGL_KAS,"0x%08X, 0x%08X", hListHead, phRemovedEntry);

    /* Protect the operation with spinlock */
    spin_lock_info.routine_type = listhead_obj->routine_type;
    spin_lock_info.plock = &(listhead_obj->lock);

    if (!kas_spin_lock(&spin_lock_info))
    {
        KCL_DEBUG_ERROR("Unable to grab list spinlock");
        return 0; /* No spinlock - no operation */
    }

    /* Remove the entry at the head if the list is not empty */
    if (list_empty(head))
    {
        KCL_DEBUG1(FN_FIREGL_KAS,"list is empty -- returning NULL as removed entry");
        *phRemovedEntry = NULL;
    }
    else
    {
        *phRemovedEntry = list_entry(head->next, kasInterlockedListEntry_t, entry);
        KCL_DEBUG1(FN_FIREGL_KAS,"entry to remove = 0x%08X", *phRemovedEntry);
        list_del(head->next);
    }

    /* Release the spinlock and return */
    spin_unlock_info.plock = &(listhead_obj->lock);
    spin_unlock_info.acquire_type = spin_lock_info.acquire_type;
    spin_unlock_info.flags = spin_lock_info.flags;

    ret = kas_spin_unlock(&spin_unlock_info);
    KCL_DEBUG5(FN_FIREGL_KAS,"%d", ret);
    return ret;
}

/** \brief Atomic compare and exchange operation for unsigned int
 *
 * If uiComparand is equal to *puiDestination,
 * then *puiDestination is set equal to uiExchange.
 * Otherwise, *puiDestination is unchanged.
 *
 * \param puiDestination    Pointer to the destination operand
 * \param uiExchange        Source operand
 * \param uiComparand       Value to compare
 *
 * \return Old value of *puiDestination.
 */
unsigned int ATI_API_CALL KAS_AtomicCompareExchangeUnsignedInt(
        unsigned int *puiDestination,
        unsigned int uiExchange,
        unsigned int uiComparand)
{
#ifdef KAS_ATOMIC_OPERATIONS_SUPPORT
    return cmpxchg(puiDestination, uiComparand, uiExchange);
#else
    return 0xDEADC0DE; /* To make compiler happy */
#endif
}

/** \brief Atomic exchange operation for unsigned int
 *
 * *puiDestination is set equal to uiExchange.
 *
 * \param puiDestination    Pointer to the destination operand
 * \param uiExchange        Source operand
 *
 * \return Old value of *puiDestination.
 */
unsigned int ATI_API_CALL KAS_AtomicExchangeUnsignedInt(
        unsigned int *puiDestination,
        unsigned int uiExchange)
{
#ifdef KAS_ATOMIC_OPERATIONS_SUPPORT
    return xchg(puiDestination, uiExchange);
#else
    return 0xDEADC0DE; /* To make compiler happy */
#endif
}

/** \brief Definition for assembly lock prefix */
#ifdef CONFIG_SMP
#define KAS_LOCK_PREFIX "lock ; "
#else
#define KAS_LOCK_PREFIX ""
#endif

/** \brief Macro for assembly XADD operation */
#define kas_xadd(dest,add,ret,size) \
    __asm__ __volatile__(           \
        KAS_LOCK_PREFIX             \
        "xadd" size " %0,(%1)"      \
        : "=r" (ret)                \
        : "r" (dest), "0" (add)     \
    );

/** \brief Atomic exchange and add operation for unsigned int
 *
 * Add uiAdd to *puiDestination
 *
 * \param puiDestination    Pointer to the destination operand
 * \param uiAdd             Value to add
 *
 * \return Old value of *puiDestination
 */
unsigned int ATI_API_CALL KAS_AtomicExchangeAddUnsignedInt(
        unsigned int *puiDestination,
        unsigned int uiAdd)
{
#ifdef KAS_ATOMIC_OPERATIONS_SUPPORT
    unsigned int ret;
    kas_xadd(puiDestination, uiAdd, ret, "l");
    return ret;
#else
    return 0xDEADC0DE; /* To make compiler happy */
#endif
}

/** \brief Atomic add operation for unsigned int
 *
 * Add iAdd to *puiDestination.  iAdd can be negative, to perform atomic
 * substructions
 *
 * \param puiDestination Pointer to the destination operand
 * \param iAdd value to add
 *
 * \return New value of *puiDestination
 *
 */
unsigned int ATI_API_CALL KAS_AtomicAddInt(
        unsigned int *puiDestination,
        int iAdd)
{
#ifdef KAS_ATOMIC_OPERATIONS_SUPPORT
    unsigned int ret;

    kas_xadd(puiDestination, iAdd, ret, "l");

    return ret + iAdd; 
#else
    return 0xDEADC0DE; /* To make compiler happy */
#endif
}

/** \brief Atomic compare and exchange operation for pointers
 *
 * If pvComparand is equal to *ppvDestination,
 * then *ppvDestination is set equal to pvExchange.
 * Otherwise, *ppvDestination is unchanged.
 *
 * \param ppvDestination    Pointer to the destination operand
 * \param pvExchange        Source operand
 * \param pvComparand       Value to compare
 *
 * \return Old value of *ppvDestination.
 */
void* ATI_API_CALL KAS_AtomicCompareExchangePointer(
        void* *ppvDestination,
        void* pvExchange,
        void* pvComparand)
{
#ifdef KAS_ATOMIC_OPERATIONS_SUPPORT
    return cmpxchg(ppvDestination, pvComparand, pvExchange);
#else
    return 0xDEADC0DE; /* To make compiler happy */
#endif
}

/** \brief Atomic exchange operation for pointers
 *
 * *ppvDestination is set equal to pvExchange.
 *
 * \param ppvDestination    Pointer to the destination operand
 * \param pvExchange        Source operand
 *
 * \return Old value of *ppvDestination.
 */
void* ATI_API_CALL KAS_AtomicExchangePointer(
        void* *ppvDestination,
        void* pvExchange)
{
#ifdef KAS_ATOMIC_OPERATIONS_SUPPORT
    return xchg(ppvDestination, pvExchange);
#else
    return 0xDEADC0DE; /* To make compiler happy */
#endif
}

/** \brief Return current value of the tick counter
 *
 * Be advised that the returned value can be used only for
 * compare purposes since it is will wrap around almost for sure
 *
 * \return Current value of the tick counter
 */
unsigned long ATI_API_CALL KAS_GetTickCounter()
{
    return jiffies;
}

/** \brief Return number of ticks per second
 *
 * \return Number of ticks per second
 */
unsigned long ATI_API_CALL KAS_GetTicksPerSecond()
{
    return HZ;
}
/** \brief Sleep for specified number of ticks
 *
 * \return Time Slept if less than requested
 * \param n_jiffies Kernel ticks to sleep for
 */
long ATI_API_CALL KAS_ScheduleTimeout(long n_jiffies)
{
    return schedule_timeout(n_jiffies);
}

/** \brief Convert number in micro second to number in jiffy
 *
 * \return Number in jiffy
 * \param number in micro second
 */
unsigned long ATI_API_CALL KCL_MsecToJiffes(unsigned int ms)
{
    return msecs_to_jiffies(ms);
}


void *ATI_API_CALL KCL_lock_init()
{   
    spinlock_t *lock;

    lock = kmalloc(sizeof(*lock), GFP_KERNEL);
    if (lock != NULL)
    {
        spin_lock_init(lock);
    }
    return (void *)lock;
}

void ATI_API_CALL KCL_lock_deinit(void *plock)
{   
    if (plock == NULL)
    {
        KCL_DEBUG_ERROR("plock is NULL\n");
        return;
    }
    if (spin_is_locked((spinlock_t *)(plock)))
    {
        KCL_DEBUG_ERROR("plock is locked\n");
    }
    kfree(plock);
}

void ATI_API_CALL KCL_get_random_bytes(void *buf, int nbytes)
{
        get_random_bytes(buf, nbytes);
}

void* ATI_API_CALL KCL_get_pubdev(void)
{
    return (void*)(&(firegl_public_device.pubdev));
}

int ATI_API_CALL kcl_sscanf(const char * buf, const char * fmt, ...)
{
    va_list args;
    int i;

    va_start(args,fmt);
    i = vsscanf(buf,fmt,args);
    va_end(args);
    return i;
}

/** \brief Generate UUID
 *  \param buf pointer to the generated UUID
 *  \return None
 */
void ATI_API_CALL KCL_create_uuid(void *buf)
{
    generate_random_uuid((char *)buf);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
static int KCL_fpu_save_init(struct task_struct *tsk)
{
   struct fpu *fpu = &tsk->thread.fpu;

   if(static_cpu_has(X86_FEATURE_XSAVE)) {
      fpu_xsave(fpu);
      if (!(fpu->state->xsave.xsave_hdr.xstate_bv & XSTATE_FP))
	 return 1;
   } else if (static_cpu_has(X86_FEATURE_FXSR)) {
	 fpu_fxsave(fpu);
   } else {
	 asm volatile("fnsave %[fx]; fwait"
                  : [fx] "=m" (fpu->state->fsave));
	 return 0;
   }

   if (unlikely(fpu->state->fxsave.swd & X87_FSW_ES)) {
	asm volatile("fnclex");
	return 0;
   }
   return 1;
}
#endif

/** \brief Prepare for using FPU
 *  \param none
 *  \return None
 */
void ATI_API_CALL KCL_fpu_begin(void)
{
#ifdef CONFIG_X86_64
    kernel_fpu_begin();
#else
#ifdef TS_USEDFPU
    struct thread_info *cur_thread = current_thread_info();
    struct task_struct *cur_task = get_current();
    preempt_disable();
    if (cur_thread->status & TS_USEDFPU)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
         KCL_fpu_save_init(cur_task);
#else
         __save_init_fpu(cur_task);
#endif
    else
         clts();

#else
    /* TS_USEDFPU is removed in kernel 3.3+ and 3.2.8+ with the commit below:
     * https://github.com/torvalds/linux/commit/f94edacf998516ac9d849f7bc6949a703977a7f3
     */
    struct task_struct *cur_task = current;
    preempt_disable();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)
    /* The thread structure is changed with the commit below for kernel 3.3:
     * https://github.com/torvalds/linux/commit/7e16838d94b566a17b65231073d179bc04d590c8
     */
    if (cur_task->thread.fpu.has_fpu)
#else
    if (cur_task->thread.has_fpu)
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
        KCL_fpu_save_init(cur_task);
#else
        __save_init_fpu(cur_task);
#endif
    else
         clts();
#endif
#endif
}

/** \brief End of using FPU
 *  \param none
 *  \return None
 */
void ATI_API_CALL KCL_fpu_end(void)
{
    kernel_fpu_end();
}

/** Create new directory entry under "/proc/...."
 * Where
 * root_dir - Root directory. If NULL then we should use system default root "/proc".
 * name    - Pointer to the name of directory
 * access  - Access attribute. We could use it to disable access to the directory for everybody accept owner.
 *                By default owner is root.
 * Return NULL if failure. Pointer to proc_dir_entry otherwise
 */
void * ATI_API_CALL KCL_create_proc_dir(void *root_dir, const char *name, unsigned int access)
{
    struct proc_dir_entry *dir = NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    if (root_dir == NULL)
         dir = create_proc_entry(name, S_IFDIR | access, NULL);
    else
         dir = create_proc_entry(name, S_IFDIR | access, (struct proc_dir_entry *)root_dir);
#else
    if (root_dir == NULL)
         dir = proc_mkdir_mode(name, S_IFDIR | access, NULL);
    else
         dir = proc_mkdir_mode(name, S_IFDIR | access, (struct proc_dir_entry *)root_dir);
#endif

    return dir;
}

/* Remove proc directory entry
 * root   - Pointer to directory proc entry or NULL if for system default root "/proc"
 * name - Name to delete
 */
void ATI_API_CALL KCL_remove_proc_dir_entry(void *root, const char *name)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    if (root == NULL)
        remove_proc_entry(name, NULL);
    else
        remove_proc_entry(name, (struct proc_dir_entry *)root);
#else
    if (root == NULL)
        remove_proc_subtree(name, NULL);
    else
        remove_proc_subtree(name, (struct proc_dir_entry *)root);
#endif
}


/* Create proc_entry under "root_dir"
 * read_fn - Function which will be called on read request
 * write_fn - Function which will be called on write request
 * private_data - Pointer to private data which will be passed
 */
void * ATI_API_CALL KCL_create_proc_entry(void *root_dir, const char *name, unsigned int access_mode, kcl_file_operations_t* fops, void *read_fn, void *write_fn, void *private_data)
{
    struct proc_dir_entry *ent = NULL;

    if (root_dir == NULL || name == NULL)
        return NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    ent = create_proc_entry(name, access_mode, (struct proc_dir_entry *)root_dir);

    if (ent)
    {
        if (read_fn)
        {
            ent->read_proc = (read_proc_t *)read_fn;    
        }
        if (write_fn)
        {
            ent->write_proc = (write_proc_t *)write_fn;
        }
        if (fops)
        {
            ent->proc_fops = (struct file_operations*)fops;
        }
        ent->data = private_data;
    }
#else
    if (fops)
    {
        ent = proc_create_data(name, access_mode, (struct proc_dir_entry *)root_dir, (struct file_operations*)fops, private_data);
    }
#endif
    return ent;
}

void KCL_SetTaskNice(int nice)
{
    set_user_nice(current, nice);
    return;
}

int KCL_TaskNice(void)
{
    return task_nice(current);
}

#endif /* __KERNEL__ */
