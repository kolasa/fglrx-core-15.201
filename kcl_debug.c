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

/** \brief Implementation of KCL debug supporting interfaces
 *
 * CONVENTIONS
 *
 * Public symbols:
 * - prefixed with KCL_DEBUG
 * - are not static
 * - declared in the corresponding header
 *
 * Private symbols:
 * - prefixed with kcl
 * - are static
 * - not declared in the corresponding header
 *
 */
#include <asm-generic/errno-base.h> //for EINVAL definition

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/sysrq.h>
#include <linux/thread_info.h>

#include "kcl_debug.h"

extern void* ATI_API_CALL KCL_MEM_SmallBufferAllocAtomic(unsigned long size);
extern void ATI_API_CALL KCL_MEM_SmallBufferFree(void* p);

extern int ATI_API_CALL firegl_debug_dump(void);

static unsigned int prvGetCpuId(void);

static void kcl_debug_sysrq_dump_handler(int key
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
                                         , struct pt_regs* pt_regs
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
                                         , struct tty_struct* tty
#endif
)
{
    
    firegl_debug_dump();
}

static struct sysrq_key_op kcl_debug_sysrq_dump_op =
{
    .handler        = kcl_debug_sysrq_dump_handler,
    .help_msg       = "fgLdump",
    .action_msg     = "FGLDUMP",
};


const log_map module_log_map[] =
{
    {SPECIAL        ,   'S'},
    {ERROR          ,   'E'},
    {DWARN           ,   'W'},
    {INFO           ,   'I'},
    {INFOEX         ,   'X'},
    {TRACE          ,   'T'},
    {PERFORMANCE    ,   'P'},
    {DUMP           ,   'D'},
};
const module_map module_type_map[] =
{
    {LOG_M_LOG              ,DEFAULT_LOG_LEVEL,"FGL_LOG"  },
    {LOG_M_CQQ              ,DEFAULT_LOG_LEVEL,"FGL_CQQ"  },
    {LOG_M_2DD              ,DEFAULT_LOG_LEVEL,"FGL_2DD"  },
    {LOG_M_CMM              ,DEFAULT_LOG_LEVEL,"FGL_CMM"  },
    {LOG_M_CAIL             ,DEFAULT_LOG_LEVEL,"FGL_CAL"  },
    {LOG_M_XMM              ,DEFAULT_LOG_LEVEL,"FGL_XMM"  },
    {LOG_M_HAL              ,DEFAULT_LOG_LEVEL,"FGL_HAL"  },
    {LOG_M_ADL              ,DEFAULT_LOG_LEVEL,"FGL_ADL"  },
    
};
unsigned int prvGetCpuId(void)
{
    
    unsigned int regB = 0;
#ifndef _AMD64_
    unsigned int regA = 0;
    unsigned int regC = 0;
    unsigned int regD = 0;
#ifdef WIN32
    unsigned int Mode = 1;
    _asm
    {
        
        mov eax,Mode            ; set CPUID instruction Mode
            
            cpuid                   ;
        
        mov regA,eax            ; move returned values to variables
            
            mov regB,ebx            ;               ""
            
            mov regC,ecx            ;               ""
            
            mov regD,edx            ;               ""
            
    }
#else
    asm volatile
        ("cpuid" : "=a" (regA), "=b" (regB), "=c" (regC), "=d" (regD): "a" (1));
    
#endif
#endif    
    regB = (regB >> 24);
    return regB;

}
void LOG_PRINTN_FUNC(const char* module_name,char sign,const char* logMsg,...)
{
    char pBuffer[MAX_STRING_LENGTH] = {0};
    va_list marker;
    va_start(marker, logMsg);
    vsprintf(pBuffer, logMsg, marker);
    printk("<6>[-%12.12s] [%-2c] [%-2d]",module_name,sign,prvGetCpuId());
    va_end(marker);
    printk(pBuffer);
}

/** \brief Print debug information to the OS debug console
 *  \param fmt printf-like formatting string
 *  \param ... printf-like parameters
 */
void ATI_API_CALL KCL_DEBUG_Print(const char* fmt, ...)
{
    char* buffer=KCL_MEM_SmallBufferAllocAtomic(MAX_STRING_LENGTH);
    va_list marker;

    if(buffer == NULL)
        return ;

    va_start(marker, fmt);
    vsprintf(buffer, fmt, marker);
    va_end(marker);

    printk(buffer);
    KCL_MEM_SmallBufferFree(buffer);
}

/** \brief Register keyboard handler to dump module internal state
 *  \param enable 1 to register the handler, 0 to unregister it
 *  \return 0
 */
int ATI_API_CALL KCL_DEBUG_RegKbdDumpHandler(int enable)
{
    if(enable)
    {
        register_sysrq_key('l', &kcl_debug_sysrq_dump_op);
    }
    else
    {
        unregister_sysrq_key('l', &kcl_debug_sysrq_dump_op);
    }
    return 0;
}

/** \brief Dump most recent OS and CPU state to the system console
 */
void ATI_API_CALL KCL_DEBUG_OsDump(void)
{
    dump_stack();
}
/* FIXME: this is temporary workaround to support code using old naming convention */

void ATI_API_CALL __ke_printk(const char* fmt, ...)
{
    char* pBuffer =KCL_MEM_SmallBufferAllocAtomic(MAX_STRING_LENGTH);
    va_list marker;

    if(pBuffer ==NULL)
    {
        return; 
    }

    va_start(marker, fmt);
    vsprintf(pBuffer, fmt, marker);
    va_end(marker);

    printk(pBuffer);

    KCL_MEM_SmallBufferFree(pBuffer);
}

/* End of FIXME */

#ifdef CONFIG_4KSTACKS
#define STACK_SIZE_MASK 4095UL
#define STACK_SIZE (4096 - sizeof(struct thread_info))
#else
#define STACK_SIZE_MASK 8191UL
#define STACK_SIZE (8192 - sizeof(struct thread_info))
#endif

static unsigned long stackBase(void)
{
    unsigned long esp = ((unsigned long)&esp) & ~STACK_SIZE_MASK;
    return esp + sizeof(struct thread_info);
}

/* Don't inline this. The stack frame of this function provides
 * protection to the caller's stack frame. */
static noinline unsigned long stackCur(void)
{
    unsigned long esp = (unsigned long)&esp;
    return esp;
}

/** \brief Mark unused stack with a magick number
 *
 * \return  Current amount of stack used in bytes
 */
#define STACK_TAG 0x89abcdef
unsigned ATI_API_CALL KCL_DEBUG_StackTag(void)
{
    unsigned *p, *q;
    unsigned free;

    p = (unsigned *)((stackBase() + sizeof(unsigned)-1) &
                     ~(sizeof(unsigned)-1));
    q = (unsigned *)(stackCur() & ~(sizeof(unsigned)-1));
    free = (unsigned long)q - (unsigned long)p;

    while (p < q)
    {
        *p++ = STACK_TAG;
    }

    return STACK_SIZE - free;
}

/** \brief Measure maximum amount of stack usage since last call to StackTag
 *
 * \return  Maximum amount of stack usage since last call to StackTag in bytes
 */
unsigned ATI_API_CALL KCL_DEBUG_StackMeasure(void)
{
    unsigned *base, *p, *q;

    base = p = (unsigned *)((stackBase() + sizeof(unsigned)-1) &
                            ~(sizeof(unsigned)-1));
    q = (unsigned *)(stackCur() & ~(sizeof(unsigned)-1));

    while (p < q && *p == STACK_TAG)
    {
        p++;
    }

    return STACK_SIZE - ((unsigned long)p - (unsigned long)base);
}
