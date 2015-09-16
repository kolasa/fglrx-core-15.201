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

#ifndef _FIREGL_PUBLIC_H_
#define _FIREGL_PUBLIC_H_

#ifndef ESX 
#include <stdarg.h>
#include "kcl_iommu.h"
#endif /*ifndef ESX*/ 

#include "kcl_pci.h"
#include "kcl_io.h"

#define FIREGL_USWC_SUPPORT     1

#define FGL_DEVICE_SIGNATURE    0x10020000

#if defined(__i386__) || defined(__x86_64__)
#define LITTLEENDIAN_CPU 1
#endif

#ifndef ESX 
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,9)

#define REMAP_PAGE_RANGE_FN remap_pfn_range
#define REMAP_PAGE_RANGE_STR "remap_pfn_range"
#define REMAP_PAGE_RANGE_OFF(offset) ((offset) >> PAGE_SHIFT)

#else /* LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,9) */

#define REMAP_PAGE_RANGE_FN remap_page_range
#define REMAP_PAGE_RANGE_STR "remap_page_range"
#define REMAP_PAGE_RANGE_OFF(offset) (offset)

#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(2,6,9) */

#define REMAP_PAGE_RANGE(vma,offset) \
    REMAP_PAGE_RANGE_FN(FGL_VMA_API_PASS \
                        (vma)->vm_start,	\
                        REMAP_PAGE_RANGE_OFF(offset), \
                        (vma)->vm_end - (vma)->vm_start, \
                        (vma)->vm_page_prot)

/* Page size*/
#ifndef PAGE_SIZE_4K
#define PAGE_SIZE_4K (4UL*1024)
#endif
#ifndef PAGE_SIZE_2M
#define PAGE_SIZE_2M (2UL*1024*1024)
#endif
#ifndef PAGE_SIZE_4M
#define PAGE_SIZE_4M (4UL*1024*1024)
#endif
#ifndef PAGE_SIZE_1G
#define PAGE_SIZE_1G (1UL*1024*1024*1024)
#endif

/* Page table macros */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
#define PAGING_FAULT_SIGBUS_INT (unsigned long)NOPAGE_SIGBUS
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26) */
#define PAGING_FAULT_SIGBUS_INT VM_FAULT_SIGBUS
#endif

#define PGD_OFFSET(mm, pgd_p, pte_linear)	\
do { \
    pgd_p = pgd_offset(mm, pte_linear); \
} while(0)

#define PGD_PRESENT(pgd_p) \
do { \
    if (!pgd_present(*(pgd_p)))	\
    { \
        return PAGING_FAULT_SIGBUS_INT;   /* Something bad happened; generate SIGBUS */ \
        /* alternatively we could generate a NOPAGE_OOM "out of memory" */ \
    } \
} while(0)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,11)
#define PUD_PRESENT(pud_p) \
do { \
    if (!pud_present(*(pud_p))) \
    { \
        return PAGING_FAULT_SIGBUS_INT;   /* Something bad happened; generate SIGBUS */ \
        /* alternatively we could generate a NOPAGE_OOM "out of memory" */ \
    } \
} while(0)

#define PUD_OFFSET(pud_p, pgd_p, pte_linear)  \
do { \
    pud_p = pud_offset(pgd_p, pte_linear); \
} while(0)

#define PUD_HUGE(pud) ((pud_val(pud) & _PAGE_PSE) != 0)

#endif

#define PMD_OFFSET(pmd_p, pgd_p, pte_linear)	\
do { \
    pmd_p = pmd_offset(pgd_p, pte_linear); \
} while(0)

#define PMD_PRESENT(pmd_p) \
do { \
    if (!pmd_present(*(pmd_p)))	\
    { \
        return PAGING_FAULT_SIGBUS_INT;   /* Something bad happened; generate SIGBUS */ \
        /* alternatively we could generate a NOPAGE_OOM "out of memory" */ \
    } \
} while(0)

#define PMD_HUGE(pmd) ((pmd_val(pmd) & _PAGE_PSE) != 0)


#ifdef pte_offset_atomic
#define PTE_OFFSET(pte, pmd_p, pte_linear) \
do { \
    pte_t* pte_p; \
    pte_p = pte_offset_atomic(pmd_p, pte_linear); \
    pte = *pte_p; \
    pte_kunmap(pte_p); \
} while(0)
#else
#ifdef pte_offset_map
#define PTE_OFFSET(pte, pmd_p, pte_linear) \
do { \
    pte_t* pte_p; \
    pte_p = pte_offset_map(pmd_p, pte_linear); \
    pte = *pte_p; \
    pte_unmap(pte_p); \
} while(0)
#else
#ifdef pte_offset_kernel
#define PTE_OFFSET(pte, pmd_p, pte_linear) \
do { \
    pte_t* pte_p; \
    pte_p = pte_offset_kernel(pmd_p, pte_linear); \
    pte = *pte_p; \
} while(0)
#else
#define PTE_OFFSET(pte, pmd_p, pte_linear) \
do { \
    pte_t* pte_p; \
    pte_p = pte_offset(pmd_p, pte_linear); \
    pte = *pte_p; \
} while(0)
#endif
#endif
#endif

#define PTE_PRESENT(pte) \
do { \
    if (!pte_present(pte)) \
    { \
        return PAGING_FAULT_SIGBUS_INT;   /* Something bad happened; generate SIGBUS */ \
        /* alternatively we could generate a NOPAGE_OOM "out of memory" */ \
    } \
} while(0)

#ifdef pfn_to_page
#define PMD_PAGE(pmd) pmd_page(pmd)
#else /* for old 2.4 kernels */
#define PMD_PAGE(pmd) (pfn_to_page(pmd_val(pmd) >> PAGE_SHIFT))
#endif

#if !defined(CONFIG_SMP) || defined(CONFIG_SUSPEND_SMP) || defined(CONFIG_PM_SLEEP_SMP) // ACPI not working on older SMP kernel (prior to 2.6.13) 
#define FIREGL_POWER_MANAGEMENT
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
#define PMSG_EVENT(pmsg_state) (pmsg_state).event
#else
#define PMSG_EVENT(pmsg_state) (pmsg_state)
/* For old kernels without PM_EVENT_xxx defines, define them 
 * in consistent with the power state used in these kernels.
 * */
#define PM_EVENT_SUSPEND 3
#endif

/*****************************************************************************/

struct vm_area_struct;
struct semaphore;
struct rw_semaphore;
struct drm_device;
struct firegl_pcie_mem;

// note: assigning uniqe types to originally non interchangeable types
typedef struct { int uniqe7; } kcl_file_operations_t;

typedef	int (*kcl_read_proc_t)(
    char* page, char** start, kcl_off_t off, int count, int* eof, void* data);

typedef int (*kcl_write_proc_t)(
    void* file, const char *buffer, unsigned long count, void *data);

typedef struct {
    const char*             name;
    kcl_read_proc_t         rp;
    kcl_write_proc_t        wp;
    kcl_file_operations_t*  fops;
} kcl_proc_list_t;

extern kcl_proc_list_t KCL_PROC_FileList[];
#endif /*ifndef ESX*/

typedef struct {
    unsigned long           signature;
    int                     privdevcount; // number of privdev structs
#ifndef ESX
    kcl_proc_list_t *      proclist;
#endif
    const char *            name;
    unsigned int	        major_version;
    unsigned int	        minor_version;
    unsigned int            patchlevel;
    const char *	        date;
    void *                  privglobal; // private global context
} kcl_device_t;

/* console mode info */
typedef struct {
    unsigned int mode_width;   /*the width of the framebuffer*/
    unsigned int mode_height;  /*the height of the framebuffer*/
    unsigned int depth;        /*the depth of the framebuffer*/
    unsigned int pitch;        /*the pitch of the framebuffer*/
    unsigned long fb_base;     /*the base address of the framebuffer*/
} kcl_console_mode_info_t;

/*****************************************************************************/

/** KCL declarations */

/** Type definitions for variables containing OS dependent data 
 *
 * These type definitions are used for data that need to be saved in the
 * proprietary code but is not interpreted by the proprietary code in any way.
 * To manipulate values of these types proprietary code must use only KCL functions
 *
 * To be of the safe side, propietary code has to use these type definitions to
 * declare local variables storing values received from KCL functions.  
 * However, legacy code is allowed to use compatible
 * types.  Compiler is supposed to catch dangerous type conversions
 *
 * In each implementation of KCL, it needs to make sure that the size of the KCL
 * defined type is greater or equal to the size of the corresponding OS type.
 * This can by done by checking which KCL functions use each particular type,
 * and what is the corresponding OS type
 * 
 */
typedef int             KCL_TYPE_Pid;       /** Process identifier */
typedef int             KCL_TYPE_Tgid;      /** Thread Group identifier */
typedef int             KCL_TYPE_Uid;       /** User identifier */

/** Atomic variables
 * This type is defined using struct to make sure compiled code will
 * always refer to the memory containing the atomic variable (prevent
 * compiler from aliasing this memory)
 * Since atomic variables are intended for using in the concurrent
 * environment, volatile is used
 */
#ifndef ESX
typedef struct { volatile unsigned int counter; } KCL_TYPE_Atomic;
#endif

/** OS independent constant definitions */

typedef enum
{
    KCL_ERROR_TIMED_OUT,
    KCL_ERROR_DEVICE_RESOURCE_BUSY,
    KCL_ERROR_INVALID_ARGUMENT,
    KCL_ERROR_PERMISSION_DENIED,
    KCL_ERROR_INVALID_ADDRESS,
    KCL_ERROR_INPUT_OUTPUT,
#ifndef ESX
    KCL_ERROR_INVALID_SLOT,
#endif /*ifndef ESX*/
    KCL_ERROR_OUT_OF_MEMORY,
    KCL_ERROR_OPERATION_NOT_PERMITTED,
    KCL_ERROR_DEVICE_NOT_EXIST,
    KCL_ERROR_INTERRUPTED_SYSTEM_CALL,
    KCL_ERROR_SIGNAL_INTERRUPTED_SYSTEM_CALL,
#ifndef ESX
    KCL_ERROR_CORRUPTED_SHARED_LIB,
#endif /*ifndef ESX*/
    KCL_ERROR_NUM
} KCL_ENUM_ErrorCode;

#ifndef ESX
typedef enum
{
    KCL_PROCESS_STATE_READY_TO_RUN,
    KCL_PROCESS_STATE_UNINTERRUPTIBLE_SLEEP,
    KCL_PROCESS_STATE_INTERRUPTIBLE_SLEEP,
    KCL_PROCESS_STATE_NUM
} KCL_ENUM_ProcessState;

typedef enum
{
    KCL_SECURITY_CAP_GENERAL_SYS_ADMIN,
    KCL_SECURITY_CAP_IPC_LOCK,
    KCL_SECURITY_CAP_NUM
} KCL_ENUM_PosixSecurityCap;

typedef enum
{
    KCL_KERNEL_CONF_PARAM_HUGE_MEM,
    KCL_KERNEL_CONF_PARAM_NUM
} KCL_ENUM_KernelConfigParam;


typedef struct {
	unsigned long totalram;		// Total usable main memory size 
	unsigned long freeram;		// Available memory size (low memory)
	unsigned long totalhigh;	// Total high memory size
	unsigned long freehigh;		// Available high memory size 
	unsigned int mem_unit;		// Memory unit size in bytes 
}KCL_SYS_MEM_INFO;
#endif /*ifndef ESX*/


#ifndef ESX 
/** KCL function declarations */
extern void          ATI_API_CALL KCL_GlobalKernelScheduler(void);
extern int           ATI_API_CALL KCL_GetSignalStatus(void);
extern unsigned int  ATI_API_CALL KCL_CurrentProcessIsTerminating(void);
extern void          ATI_API_CALL KCL_SetCurrentProcessState(KCL_ENUM_ProcessState state);
extern const char*   ATI_API_CALL KCL_GetModuleParamString(void);
extern KCL_TYPE_Pid  ATI_API_CALL KCL_GetPid(void);
extern KCL_TYPE_Tgid ATI_API_CALL KCL_GetTgid(void);
extern void *        ATI_API_CALL KCL_GetGroupLeader(void);
extern KCL_TYPE_Uid  ATI_API_CALL KCL_GetEffectiveUid(void);
extern void          ATI_API_CALL KCL_DelayInMicroSeconds(unsigned long usecs);
extern void          ATI_API_CALL KCL_DelayUseTSC(unsigned long usecs);
extern unsigned long ATI_API_CALL KCL_ConvertAddressVirtualToPhysical(void* address);
extern unsigned long long ATI_API_CALL KCL_MapVirtualToPhysical(KCL_PCI_DevHandle pdev, void* address, unsigned long size);
extern void          ATI_API_CALL KCL_UnmapVirtualToPhysical(KCL_PCI_DevHandle pdev, unsigned long long bus_addr, unsigned long size);
extern unsigned long ATI_API_CALL KCL_MapPageToPfn(KCL_PCI_DevHandle pdev, void* page);
extern void          ATI_API_CALL KCL_UnmapPageToPfn(KCL_PCI_DevHandle pdev, unsigned long long bus_addr);
extern void*         ATI_API_CALL KCL_ConvertPageToKernelAddress(void* page);
extern unsigned int  ATI_API_CALL KCL_IsPageInHighMem(void* page);

extern void*         ATI_API_CALL KCL_GetHighMemory(void);
extern int           ATI_API_CALL KCL_GetErrorCode(KCL_ENUM_ErrorCode errcode);
extern int           ATI_API_CALL KCL_PosixSecurityCapCheck(KCL_ENUM_PosixSecurityCap cap);
extern int           ATI_API_CALL KCL_PosixSecurityCapSetIPCLock(unsigned int lock);
extern unsigned long ATI_API_CALL KCL_GetAvailableRamPages(void);
extern void          ATI_API_CALL KCL_GetSystemMemInfo(KCL_SYS_MEM_INFO* info);
extern void          ATI_API_CALL KCL_ReserveMemPage(void* pt);
extern void          ATI_API_CALL KCL_UnreserveMemPage(void* pt);
extern void          ATI_API_CALL KCL_LockMemPage(void* pt);
extern void          ATI_API_CALL KCL_UnlockMemPage(void* pt);
extern int           ATI_API_CALL KCL_KernelConfigParamIsDefined(KCL_ENUM_KernelConfigParam param);
extern int           ATI_API_CALL KCL_SetPageCache(void* virt, int pages,int enable);
extern int           ATI_API_CALL KCL_SetPageCache_Array(unsigned long *pt, int pages, int enable);
extern void          ATI_API_CALL KCL_AtomicInc(KCL_TYPE_Atomic* v);
extern void          ATI_API_CALL KCL_AtomicDec(KCL_TYPE_Atomic* v);
extern void          ATI_API_CALL KCL_AtomicAdd(KCL_TYPE_Atomic* v, int val);
extern void          ATI_API_CALL KCL_AtomicSub(KCL_TYPE_Atomic* v, int val);
extern int           ATI_API_CALL KCL_AtomicGet(KCL_TYPE_Atomic* v);
extern void          ATI_API_CALL KCL_AtomicSet(KCL_TYPE_Atomic* v, int val);
extern int           ATI_API_CALL KCL_AtomicIncAndTest(KCL_TYPE_Atomic* v);
extern int           ATI_API_CALL KCL_AtomicDecAndTest(KCL_TYPE_Atomic* v);
extern void          ATI_API_CALL KCL_AtomicSetBit(int nr, volatile void * addr);
extern void          ATI_API_CALL KCL_AtomicClearBit(int nr, volatile void * addr);
extern void          ATI_API_CALL KCL_AtomicToggleBit(int nr, volatile void* addr);
extern int           ATI_API_CALL KCL_AtomicTestBit(int nr, volatile void* addr);
extern int           ATI_API_CALL KCL_AtomicTestAndSetBit(int nr, volatile void* addr);
extern int           ATI_API_CALL KCL_AtomicTestAndClearBit(int nr, volatile void* addr);
extern int           ATI_API_CALL KCL_AtomicTestAndToggleBit(int nr, volatile void* addr);
extern int           ATI_API_CALL KCL_PosixSecurityCapCheck(KCL_ENUM_PosixSecurityCap cap);

/*****************************************************************************/
extern int ATI_API_CALL drm_name_info(char* buf, int request, void* data);
extern int ATI_API_CALL firegl_bios_version(char* buf, int request, void* data);
extern int ATI_API_CALL firegl_interrupt_info(char* buf, int request, void* data);
extern int ATI_API_CALL drm_mem_info(char* buf, int request, void *data);
extern int ATI_API_CALL drm_mem_info1(char* buf, int request, void *data);
extern int ATI_API_CALL drm_vm_info(char* buf, int request, void* data);
extern int ATI_API_CALL drm_clients_info(char* buf, int request, void* data);
extern int ATI_API_CALL firegl_lock_info(char* buf, int request, void* data);
extern int ATI_API_CALL firegl_ptm_info(char* buf, int request, void *data);
#ifdef DEBUG
extern int ATI_API_CALL drm_bq_info(char* buf, int request, void* data);
#endif
extern int ATI_API_CALL firegl_debug_proc_read(char* buf, int request, void* data);

extern int ATI_API_CALL firegl_debug_proc_write(void* file, const char *buffer, unsigned long count, void *data);

extern int ATI_API_CALL firegl_interrupt_open(void* data, KCL_IO_FILE_Handle file);
extern int ATI_API_CALL firegl_interrupt_release(KCL_IO_FILE_Handle file);
extern unsigned int ATI_API_CALL firegl_interrupt_read(
                                    KCL_IO_FILE_Handle user_file, 
                                    char *user_buf, 
                                    kcl_size_t user_buf_size, 
                                    kcl_loff_t *user_file_pos);
extern unsigned int ATI_API_CALL firegl_interrupt_poll(
        KCL_IO_FILE_Handle user_file, KCL_IO_FILE_PollTableHandle pt);
extern int ATI_API_CALL firegl_interrupt_write(
                                    KCL_IO_FILE_Handle user_file,
                                    const char *user_buf, 
                                    kcl_size_t user_buf_size, 
                                    kcl_loff_t *user_file_pos);

/*****************************************************************************/

extern int ATI_API_CALL firegl_private_init (kcl_device_t *);
extern void ATI_API_CALL firegl_private_cleanup (kcl_device_t *);
extern int ATI_API_CALL firegl_init(kcl_device_t*);
extern int ATI_API_CALL firegl_open(int minor, KCL_IO_FILE_Handle filp);
extern int ATI_API_CALL firegl_release(KCL_IO_FILE_Handle filp);
extern int ATI_API_CALL firegl_ioctl(
                        KCL_IO_FILE_Handle filp,
                        unsigned int cmd,
                        unsigned long arg);

#ifdef __x86_64__
extern long ATI_API_CALL firegl_compat_ioctl(
                        KCL_IO_FILE_Handle filp,
                        unsigned int cmd,
                        unsigned long arg);
#endif

/*****************************************************************************/

extern int ATI_API_CALL firegl_mmap(KCL_IO_FILE_Handle filp, struct vm_area_struct* vma);
extern void ATI_API_CALL drm_vm_open(struct vm_area_struct* vma);
extern void ATI_API_CALL drm_vm_close(struct vm_area_struct* vma);
extern void* ATI_API_CALL firegl_get_dev_from_vm(  struct vm_area_struct* vma );
extern void* ATI_API_CALL firegl_get_pcie_from_vm(  struct vm_area_struct* vma );
extern void* ATI_API_CALL firegl_get_pciemem_from_addr( struct vm_area_struct* vma, unsigned long addr );
extern unsigned long ATI_API_CALL firegl_get_pcie_pageaddr_from_vm(  struct vm_area_struct* vma, struct firegl_pcie_mem* pciemem, unsigned long offset);
extern void* ATI_API_CALL firegl_get_pagelist_from_vm(  struct vm_area_struct* vma );
extern unsigned long ATI_API_CALL firegl_get_addr_from_vm(  struct vm_area_struct* vma);
extern unsigned long ATI_API_CALL firegl_get_pagetable_page_from_vm(struct vm_area_struct* vma);
extern void* ATI_API_CALL mc_heap_get_page(void *vma, unsigned long long offset);
extern const unsigned int* ATI_API_CALL mc_heap_get_page_idx_list(void *pointer_to_mc_heap, unsigned int *number_of_pages);

/*****************************************************************************/

extern unsigned long ATI_API_CALL kcl__cmpxchg(volatile void *ptr, unsigned long old,                      
                      unsigned long new, int size);

#define kcl_cmpxchg(ptr,o,n)                        \
  ((__typeof__(*(ptr)))kcl__cmpxchg((ptr),(unsigned long)(o),      \
                 (unsigned long)(n),sizeof(*(ptr))))
/*****************************************************************************/

extern unsigned int ATI_API_CALL KCL_DEVICE_GetNumber(kcl_device_t *dev);

extern void ATI_API_CALL KCL_MODULE_IncUseCount(void);
extern void ATI_API_CALL KCL_MODULE_DecUseCount(void);

extern void ATI_API_CALL KCL_SEMAPHORE_STATIC_Down(kcl_device_t *dev, int idx);
extern void ATI_API_CALL KCL_SEMAPHORE_STATIC_Up(kcl_device_t *dev, int idx);
#define __KE_MAX_SEMAPHORES 3
extern void ATI_API_CALL KCL_SEMAPHORE_Init(struct semaphore* sem, int value);
extern kcl_size_t ATI_API_CALL KCL_SEMAPHORE_GetObjSize(void);
extern void ATI_API_CALL KCL_SEMAPHORE_DownUninterruptible(struct semaphore* sem);
extern void ATI_API_CALL KCL_SEMAPHORE_Up(struct semaphore* sem);

//PPLIB adding interruptible down for semaphore
extern int ATI_API_CALL KCL_SEMAPHORE_DownInterruptible(struct semaphore* sem);
//PPLIB end

extern void ATI_API_CALL KCL_SPINLOCK_STATIC_Grab(kcl_device_t *dev, int ndx);
extern void ATI_API_CALL KCL_SPINLOCK_STATIC_Release(kcl_device_t *dev, int ndx);
//rw semaphore for GPU reset
extern void ATI_API_CALL KCL_RW_SEMAPHORE_DownWrite(struct rw_semaphore* sem);

extern void ATI_API_CALL KCL_RW_SEMAPHORE_UpWrite(struct rw_semaphore* sem);

extern void ATI_API_CALL KCL_RW_SEMAPHORE_DownRead(struct rw_semaphore* sem);

extern void ATI_API_CALL KCL_RW_SEMAPHORE_UpRead(struct rw_semaphore* sem);

extern void ATI_API_CALL KCL_RW_SEMAPHORE_Init(struct rw_semaphore* sem);

extern kcl_size_t ATI_API_CALL KCL_RW_SEMAPHORE_GetObjSize(void);


#ifdef VCE_SUPPORT
#define __KE_MAX_SPINLOCKS 9
#else
#define __KE_MAX_SPINLOCKS 8 
#endif

int ATI_API_CALL kcl_vsprintf(char *buf, const char *fmt, va_list ap);
int ATI_API_CALL kcl_vsnprintf(char *buf, size_t size, const char *fmt, va_list ap);

extern int ATI_API_CALL KCL_CopyFromUserSpace(void* to, const void* from, kcl_size_t size);
extern int ATI_API_CALL KCL_CopyToUserSpace(void* to, const void* from, kcl_size_t size);

extern void* ATI_API_CALL KCL_MEM_SmallBufferAlloc(kcl_size_t size);
extern void* ATI_API_CALL KCL_MEM_SmallBufferAllocAtomic(kcl_size_t size);
extern void ATI_API_CALL KCL_MEM_SmallBufferFree(void* p);
extern void* ATI_API_CALL kcl_vmalloc(kcl_size_t size);
extern void* ATI_API_CALL KCL_MEM_Alloc(kcl_size_t size);
extern void* ATI_API_CALL KCL_MEM_AllocAtomic(kcl_size_t size);
extern void ATI_API_CALL KCL_MEM_Free(void* p);
extern void* ATI_API_CALL KCL_MEM_AllocPageFrame(void);
extern void* ATI_API_CALL KCL_MEM_AllocContiguousPageFrames(int order);
extern void ATI_API_CALL KCL_MEM_FreePageFrame(void* pt);
extern void ATI_API_CALL KCL_MEM_FreePageFrames(void* pt, int order);

extern void* ATI_API_CALL KCL_MEM_AllocPageForGart(void);
extern void ATI_API_CALL KCL_MEM_FreePageForGart(void* pt);

extern void ATI_API_CALL KCL_MEM_IncPageUseCount(void* pt);
extern void ATI_API_CALL KCL_MEM_DecPageUseCount(void* pt);
extern void ATI_API_CALL KCL_MEM_IncPageCount_Mapping(void* page);
extern int ATI_API_CALL KCL_MEM_VerifyReadAccess(void* addr, kcl_size_t size);
extern int ATI_API_CALL KCL_MEM_VerifyWriteAccess(void* addr, kcl_size_t size);
extern unsigned long ATI_API_CALL KCL_GetPageTableByVirtAddr(unsigned long virtual_addr, unsigned long* page_addr);
extern unsigned int ATI_API_CALL KCL_GetPageSizeByVirtAddr(unsigned long virtual_addr, unsigned int* page_size);
extern int ATI_API_CALL KCL_LockUserPages(unsigned long vaddr, unsigned long* page_list, unsigned int page_cnt);
extern int ATI_API_CALL KCL_LockReadOnlyUserPages(unsigned long vaddr, unsigned long* page_list, unsigned int page_cnt);
extern void ATI_API_CALL KCL_UnlockUserPages(unsigned long* page_list, unsigned int page_cnt);
extern int ATI_API_CALL KCL_TestAndClearPageDirtyFlag(unsigned long virtual_addr, unsigned int page_size);
extern unsigned long ATI_API_CALL KCL_MEM_AllocLinearAddrInterval(KCL_IO_FILE_Handle  file, unsigned long addr, unsigned long len, unsigned long pgoff);
extern int ATI_API_CALL KCL_MEM_ReleaseLinearAddrInterval(unsigned long addr, unsigned long len);
extern void* ATI_API_CALL KCL_MEM_MapPageList(unsigned long *pagelist, unsigned int count);
#ifdef FIREGL_USWC_SUPPORT
extern void* ATI_API_CALL KCL_MEM_MapPageListWc(unsigned long *pagelist, unsigned int count);
#endif
extern void ATI_API_CALL KCL_MEM_Unmap(void* addr);
extern unsigned long ATI_API_CALL KCL_GetInitKerPte(unsigned long address);

//UEFI call
extern void ATI_API_CALL KCL_Get_Console_Mode(kcl_console_mode_info_t *console_mode);
extern int ATI_API_CALL KCL_EFI_IS_ENABLED(void);

/*****************************************************************************/

extern int ATI_API_CALL KCL_MEM_FlushCpuCaches(void);
extern void ATI_API_CALL KCL_PageCache_Flush(void);

/*****************************************************************************/

extern int ATI_API_CALL KCL_MEM_MTRR_Support(void);
extern int ATI_API_CALL KCL_MEM_MTRR_AddRegionWc(unsigned long base, unsigned long size);
extern int ATI_API_CALL KCL_MEM_MTRR_DeleteRegion(int reg, unsigned long base, unsigned long size);

extern int ATI_API_CALL KCL_is_pat_enabled(void);

/*****************************************************************************/

extern int ATI_API_CALL KCL_InstallInterruptHandler(unsigned int irq, void (*ATI_API_CALL handler)(void*), const char *dev_name, void *context, int useMSI);
extern void ATI_API_CALL KCL_UninstallInterruptHandler(unsigned int irq, void *context);

extern int ATI_API_CALL KCL_RequestMSI(void* context);
extern void ATI_API_CALL KCL_DisableMSI(void* context);

/*****************************************************************************/

extern void* ATI_API_CALL KCL_MEM_VM_GetRegionFilePrivateData(struct vm_area_struct* vma);
extern void* ATI_API_CALL KCL_MEM_VM_GetRegionPrivateData(struct vm_area_struct* vma);
extern unsigned long ATI_API_CALL KCL_MEM_VM_GetRegionStart(struct vm_area_struct* vma);
extern unsigned long ATI_API_CALL KCL_MEM_VM_GetRegionEnd(struct vm_area_struct* vma);
extern unsigned long ATI_API_CALL KCL_MEM_VM_GetRegionMapOffset(struct vm_area_struct* vma);
enum kcl_vm_maptype
{
    __KE_ADPT,
    __KE_SHM,
    __KE_CTX,
    __KE_PCI_BQS,
    __KE_AGP_BQS,
    __KE_AGP,
    __KE_SG,
    __KE_KMAP,
    __KE_GART_USWC,
    __KE_GART_CACHEABLE,
    __KE_ADPT_REG
};
extern char* ATI_API_CALL KCL_MEM_VM_GetRegionFlagsStr(struct vm_area_struct* vma, char* buf);
extern char* ATI_API_CALL KCL_MEM_VM_GetRegionProtFlagsStr(struct vm_area_struct* vma, char* buf);
extern char* ATI_API_CALL KCL_MEM_VM_GetRegionPhysAddrStr(struct vm_area_struct* vma,
                                   char* buf, 
                                   unsigned long linear_address, 
                                   kcl_dma_addr_t* phys_address);
extern int ATI_API_CALL KCL_MEM_VM_MapRegion(KCL_IO_FILE_Handle filp,
                                    struct vm_area_struct* vma,
                                    unsigned long long offset,
                                    enum kcl_vm_maptype type,
                                    int readonly,
                                    void *private_data);

/*****************************************************************************/

extern int ATI_API_CALL firegl_pci_save_state(KCL_PCI_DevHandle pdev, struct drm_device* dev);
extern int ATI_API_CALL firegl_pci_restore_state(KCL_PCI_DevHandle pdev, struct drm_device* dev);
extern void ATI_API_CALL firegl_pm_save_framebuffer(struct drm_device* dev);
extern void ATI_API_CALL firegl_pm_restore_framebuffer(struct drm_device* dev);
extern void ATI_API_CALL firegl_pm_save_onchip_ram(struct drm_device* dev);
extern void ATI_API_CALL firegl_pm_restore_onchip_ram(struct drm_device* dev);
extern void ATI_API_CALL firegl_pm_restore_atigart(struct drm_device* dev);
extern void ATI_API_CALL firegl_pm_disable_interrupts(struct drm_device* dev);
extern void ATI_API_CALL firegl_pm_enable_interrupts(struct drm_device* dev);
extern void ATI_API_CALL firegl_pm_lock_highmem_gart(struct drm_device* dev, int lock);

/*****************************************************************************/

extern int ATI_API_CALL KCL_PM_Is_SuspendToRam(int state);
/*****************************************************************************/

extern void KCL_SetTaskNice(int nice);
extern int KCL_TaskNice(void);

/* global constants */
extern const char*          KCL_SYSINFO_OsVersionString;
extern const unsigned long  KCL_SYSINFO_OsVersionCode;
extern const unsigned int   KCL_SYSINFO_PageSize;

extern const unsigned long  KCL_SYSINFO_BinaryModuleSupport;
extern const unsigned long  KCL_SYSINFO_SmpSupport;
extern const unsigned long  KCL_SYSINFO_PaeSupport;

/* global vars that are in fact constants */
extern unsigned long        KCL_SYSINFO_TimerTicksPerSecond;

/*****************************************************************************/

#ifndef __GFP_COMP
#define __GFP_COMP 0
#endif

#ifdef FIREGL_USWC_SUPPORT

#ifndef MSR_IA32_CR_PAT
#define MSR_IA32_CR_PAT     0x277
#endif

#ifndef cpu_has_pat
#define cpu_has_pat  test_bit(X86_FEATURE_PAT, (void *) &boot_cpu_data.x86_capability)
#endif

#ifndef cpu_has_pge
#define cpu_has_pge test_bit(X86_FEATURE_PGE, &boot_cpu_data.x86_capability)
#endif

/* 2.6.29 defines pgprot_writecombine as a macro which resolves to a
 * GPL-only function with the same name. So we always use our own
 * definition on 2.6.29 and later. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29) \
    && defined (pgprot_writecombine)
#undef pgprot_writecombine
#endif
#ifndef pgprot_writecombine
#define pgprot_writecombine(prot) __pgprot((pgprot_val(prot) & ~(_PAGE_PCD)) | _PAGE_PWT)
#endif

#ifndef pgprot_noncached
#define pgprot_noncached(prot) __pgprot(pgprot_val(prot) | _PAGE_PCD | _PAGE_PWT)
#endif

#endif //FIREGL_USWC_SUPPORT
#endif /*ifndef ESX*/

/*****************************************************************************
*                                                                            *
* Declarations for Kernel Abstraction Services                               *
*                                                                            *
******************************************************************************/
typedef void ATI_API_CALL (*KAS_CallbackWrapper_t)(void* proutine, void* pcontext);
typedef unsigned int ATI_API_CALL (*KAS_CallbackWrapperRet_t)(void* proutine, void* pcontext);

/** \brief Type definition for KAS initialization */
typedef struct tag_KAS_Initialize_t
{
    unsigned long exec_level_invalid;
    unsigned long exec_level_init;
    unsigned long exec_level_regular;
    unsigned long exec_level_idh;
    unsigned long exec_level_ih;
    KAS_CallbackWrapper_t callback_wrapper;
    KAS_CallbackWrapperRet_t callback_wrapper_ret;
} KAS_Initialize_t;

/** \brief Type definition for Interrupt Handling Routine */
typedef unsigned int (*KAS_IhRoutine_t)(void* pIhContext);

/** \brief Types of routines */
#define KAS_ROUTINE_TYPE_INVALID    0
#define KAS_ROUTINE_TYPE_REGULAR    1
#define KAS_ROUTINE_TYPE_IDH        2
#define KAS_ROUTINE_TYPE_IH         3

/** \brief Types of spinlocks */
#define KAS_SPINLOCK_TYPE_INVALID   0
#define KAS_SPINLOCK_TYPE_REGULAR   1
#define KAS_SPINLOCK_TYPE_IDH       2
#define KAS_SPINLOCK_TYPE_IH        3

/** \brief Return codes */
#define KAS_RETCODE_OK              0
#define KAS_RETCODE_ERROR           1
#define KAS_RETCODE_TIMEOUT         2
#define KAS_RETCODE_SIGNAL          3

#ifndef ESX 
/** \brief Interface functions */
extern unsigned int  ATI_API_CALL KAS_Initialize(KAS_Initialize_t* pinit);
extern unsigned int  ATI_API_CALL KAS_Ih_Execute(KAS_IhRoutine_t ih_routine,
                                                 void* ih_context);
extern unsigned int  ATI_API_CALL KAS_ExecuteAtLevel(void* pSyncRoutine,
                                                     void* pContext,
                                                     unsigned long sync_level);
extern unsigned long ATI_API_CALL KAS_GetExecutionLevel(void);

extern unsigned int  ATI_API_CALL KAS_Idh_GetObjectSize(void);
extern unsigned int  ATI_API_CALL KAS_Idh_Initialize(void* hIdh,
                                                     void* pfnIdhRoutine,
                                                     void* pIdhContext);
extern unsigned int  ATI_API_CALL KAS_Idh_Queue(void* hIdh);

extern unsigned int  ATI_API_CALL KAS_Spinlock_GetObjectSize(void);
extern unsigned int  ATI_API_CALL KAS_Spinlock_Initialize(void* hSpinLock,
                                             unsigned int spinlock_type);
extern unsigned int  ATI_API_CALL KAS_Spinlock_Acquire(void* hSpinLock);
extern unsigned int  ATI_API_CALL KAS_Spinlock_Release(void* hSpinLock);

extern unsigned int  ATI_API_CALL KAS_SlabCache_GetObjectSize(void);
extern unsigned int  ATI_API_CALL KAS_SlabCache_Initialize(void* hSlabCache,
                                                    unsigned int iEntrySize,
                                                    unsigned int access_type);
extern unsigned int  ATI_API_CALL KAS_SlabCache_Destroy(void* hSlabCache);
extern void*         ATI_API_CALL KAS_SlabCache_AllocEntry(void* hSlabCache);
extern unsigned int  ATI_API_CALL KAS_SlabCache_FreeEntry(void* hSlabCache,
                                                          void* pvEntry);

extern unsigned int  ATI_API_CALL KAS_Event_GetObjectSize(void);
extern unsigned int  ATI_API_CALL KAS_Event_Initialize(void* hEvent);
extern unsigned int  ATI_API_CALL KAS_Event_Set(void* hEvent);
extern unsigned int  ATI_API_CALL KAS_Event_Clear(void* hEvent);
extern unsigned int  ATI_API_CALL KAS_Event_WaitForEvent(void* hEvent,
                                                    unsigned long long timeout,
                                                    unsigned int timeout_use);

extern unsigned int  ATI_API_CALL KAS_Mutex_GetObjectSize(void);
extern unsigned int  ATI_API_CALL KAS_Mutex_Initialize(void* hMutex);
extern unsigned int  ATI_API_CALL KAS_Mutex_Acquire(void* hMutex,
                                                    unsigned long long timeout,
                                                    unsigned int timeout_use);
extern unsigned int  ATI_API_CALL KAS_Mutex_Release(void* hMutex);

extern unsigned int  ATI_API_CALL KAS_Thread_GetObjectSize(void);
extern unsigned int  ATI_API_CALL KAS_Thread_Start(void* hThread,
                                                   void* routine,
                                                   void* pcontext);
extern unsigned int  ATI_API_CALL KAS_Thread_WaitForFinish(void* hThread);
extern unsigned int  ATI_API_CALL KAS_Thread_Finish(void* hThread);

extern unsigned int  ATI_API_CALL KAS_InterlockedList_GetListHeadSize(void);
extern unsigned int  ATI_API_CALL KAS_InterlockedList_GetListEntrySize(void);
extern unsigned int  ATI_API_CALL KAS_InterlockedList_Initialize(
                                                    void* hListHead,
                                                    unsigned int access_type);
extern unsigned int  ATI_API_CALL KAS_InterlockedList_InsertAtTail(
                                                      void* hListHead,
                                                      void* hListEntry,
                                                      void** phPrevEntry);
extern unsigned int  ATI_API_CALL KAS_InterlockedList_InsertAtHead(
                                                      void* hListHead,
                                                      void* hListEntry,
                                                      void** phPrevEntry);
extern unsigned int  ATI_API_CALL KAS_InterlockedList_RemoveAtHead(
                                                      void* hListHead,
                                                      void** phRemovedEntry);

extern unsigned int  ATI_API_CALL KAS_AtomicCompareExchangeUnsignedInt(
                                                unsigned int *puiDestination,
                                                unsigned int uiExchange,
                                                unsigned int uiComparand);

extern unsigned int  ATI_API_CALL KAS_AtomicExchangeUnsignedInt(
                                                unsigned int *puiDestination,
                                                unsigned int uiExchange);

extern unsigned int  ATI_API_CALL KAS_AtomicExchangeAddUnsignedInt(
                                                unsigned int *puiDestination,
                                                unsigned int uiAdd);

extern unsigned int  ATI_API_CALL KAS_AtomicAddInt(
                                                unsigned int *puiDestination,
                                                int iAdd);

extern void*         ATI_API_CALL KAS_AtomicCompareExchangePointer(
                                                        void* *ppvDestination,
                                                        void* pvExchange,
                                                        void* pvComparand);

extern void*         ATI_API_CALL KAS_AtomicExchangePointer(
                                                        void* *ppvDestination,
                                                        void* pvExchange);

extern unsigned long ATI_API_CALL KAS_GetTickCounter(void);
extern unsigned long ATI_API_CALL KAS_GetTicksPerSecond(void);
extern  long ATI_API_CALL KAS_ScheduleTimeout(long n_jiffies);
extern unsigned long ATI_API_CALL KCL_MsecToJiffes(unsigned int ms);

/******************************************************************************
**
**  Interface layer to asyncIO layer
**
*******************************************************************************/
#define FIREGL_ASYNCIO_MAX_DEV      32    /* Currently hardcode to 32  */
#define FIREGL_ASYNCIO_MAX_FILE     32   /* Currently hardcode to 32 */
#define FIREGL_ASYNCIO_MAX_SEMA     ((FIREGL_ASYNCIO_MAX_FILE+1)*FIREGL_ASYNCIO_MAX_DEV)

extern void * ATI_API_CALL KCL_SEMAPHORE_ASYNCIO_Alloc(void);
extern void ATI_API_CALL KCL_SEMAPHORE_ASYNCIO_Free(struct semaphore *pSema);
extern void ATI_API_CALL KCL_SEMAPHORE_ASYNCIO_Init(void);

typedef enum {
    __KE_POLLIN = 0,
    __KE_POLLRDNORM,
    __KE_EAGAIN,
    __KE_FASYNC_ON,
    __KE_FASYNC_OFF,
    __KE_SIGIO,
    __KE_ESPIPE,
    __KE_EINTR
} kcl_asynio_contant_t;

extern int ATI_API_CALL KCL_SYSINFO_MapConstant(int contant);

extern kcl_ssize_t ATI_API_CALL firegl_asyncio_read( KCL_IO_FILE_Handle filp,
                                                      char *buf, 
                                                      kcl_size_t size,
                                                      kcl_loff_t *off_ptr);

extern kcl_ssize_t ATI_API_CALL firegl_asyncio_write( KCL_IO_FILE_Handle filp,
                                                       const char *buf, 
                                                       kcl_size_t size,
                                                       kcl_loff_t *off_ptr);

extern unsigned int ATI_API_CALL firegl_asyncio_poll(
        KCL_IO_FILE_Handle filp, KCL_IO_FILE_PollTableHandle table);

extern int ATI_API_CALL firegl_asyncio_fasync(int fd, 
                                              KCL_IO_FILE_Handle filp,
                                              int mode);

extern void *ATI_API_CALL KCL_lock_init(void);
extern void ATI_API_CALL KCL_lock_deinit(void *plock);
extern void ATI_API_CALL KCL_spin_lock(void *lock);
extern void ATI_API_CALL KCL_spin_unlock(void *lock);
extern void ATI_API_CALL KCL_get_random_bytes(void *buf, int nbytes);
extern void* ATI_API_CALL KCL_get_pubdev(void);
extern void  ATI_API_CALL KCL_fpu_begin(void);
extern void  ATI_API_CALL KCL_fpu_end(void);
extern void* ATI_API_CALL KCL_create_proc_dir(void *root_dir, const char *name, unsigned int access);
extern void ATI_API_CALL KCL_remove_proc_dir_entry(void *root, const char *name);
extern void* ATI_API_CALL KCL_create_proc_entry(void *root_dir, const char *name, unsigned int access_mode, kcl_file_operations_t* fops, void *read_fn, void* write_fn, void *private_data);

//The length of uuid, standardized by the Open Software Foundation, is 16.
//In kernel, hard coded in function generate_random_uuid(). 
#define FIREGL_UUID_LEN     16
extern void ATI_API_CALL KCL_create_uuid(void *buf);

extern void ATI_API_CALL adapter_chain_init(void);
extern void ATI_API_CALL adapter_chain_cleanup(void);
extern void ATI_API_CALL cf_object_init(void);
extern void ATI_API_CALL cf_object_cleanup(void);
extern int ATI_API_CALL firegl_init_device_list(int num_of_devices);
extern int ATI_API_CALL firegl_realloc_device_list(int num_of_devices);
extern void ATI_API_CALL firegl_cleanup_device_heads(void);
extern int ATI_API_CALL firegl_get_dev(void *pubdev, KCL_PCI_DevHandle pdev);
extern void *ATI_API_CALL firegl_find_device(int minor);
extern void* ATI_API_CALL firegl_query_pcidev(KCL_PCI_DevHandle pdev);
extern int ATI_API_CALL firegl_init_32compat_ioctls(void);
extern void ATI_API_CALL firegl_kill_32compat_ioctls(void);
extern int ATI_API_CALL firegl_uswc_user_disabled(void);

//export function prototype from libip
extern int libip_iommu_invalid_pri_request( KCL_PCI_DevHandle pdev,
                                            int  pasid,
                                            unsigned long fault_addr,
                                            KCL_IOMMU_req_perm_t perm);

extern int libip_iommu_invalidate_pasid_ctx( KCL_PCI_DevHandle pdev, int  pasid);

//libip call back entry when suspend. return 0 if success . 
extern int ATI_API_CALL libip_suspend(struct drm_device* dev, int state);

//libip call back entry when resume. return 0 if success . 
extern int ATI_API_CALL libip_resume(struct drm_device* dev);
#endif /*ifndef ESX*/

#ifdef ESX
#include "kcl_esx.h"
#endif

#endif /* _FIREGL_PUBLIC_H_ */
