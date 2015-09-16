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

/** \brief Declarations for KCL debug supporting interfaces */

#ifndef KCL_DEBUG_H
#define KCL_DEBUG_H

#include "kcl_config.h"

typedef enum
{
    FN_DEBUG_LEVEL1  = 0 , 
    FN_DEBUG_LEVEL2  = 1 ,
    FN_DEBUG_LEVEL3  = 2 ,
    FN_DEBUG_LEVEL4  = 3 ,
    FN_DEBUG_LEVEL5  = 4 ,
    FN_DEBUG_LEVEL6  = 5 ,
    FN_DEBUG_TRACEOUT = 6,
    FN_DEBUG_TRACE    = 7,
    FN_DEBUG_MAXIMUM  = 0x8
} FN_DEBUG;

typedef enum
{
   FN_FIREGL_OPEN_RELEASE = 0 ,
   FN_FIREGL_IOCTL        = 1 ,
   FN_FIREGL_MMAP         = 2 ,
   FN_FIREGL_READ_WRITE   = 3 ,   
   
   FN_FIREGL_FASYNC       = 4 ,
   FN_FIREGL_POLL         = 5 ,
   FN_FIREGL_LSEEK        = 6 ,
   FN_FIREGL_COMPAT_IOCTL = 7 ,
   
   FN_DRM_VM_OPEN_CLOSE   = 8 ,
   FN_DRM_NOPAGE          = 9 ,
   FN_FIREGL_ACPI         = 10,
   FN_FIREGL_IRQ          = 11,
   
   FN_FIREGL_PROC         = 12,
   FN_FIREGL_KAS          = 13,
   FN_FIREGL_KCL          = 14,
   FN_FIREGL_INIT         = 15,
   
   FN_GENERIC1            = 16,
   FN_GENERIC2            = 17,
   FN_GENERIC3            = 18,      //Added more if  necessary to 0x1f(31)
   
   FN_FIREGL_RESERVED     = 0x20,    //0x20 -0x3f reserverd 
   FN_GENERIC_MAXIMUM     = 0x3f
} FN_TRACE;

extern void ATI_API_CALL firegl_trace(unsigned int traceMask,
                                      unsigned int debugMask,
                                      void* name,
                                      int line,
                                      long param,
                                      const char* fmt,
                                      ...);

#define MAX_STRING_LENGTH    512

void ATI_API_CALL KCL_DEBUG_Print(const char* fmt, ...);
int ATI_API_CALL KCL_DEBUG_RegKbdHandler(int enable);
int ATI_API_CALL KCL_DEBUG_RegKbdDumpHandler(int enable);
void ATI_API_CALL KCL_DEBUG_OsDump(void);
unsigned ATI_API_CALL KCL_DEBUG_StackTag(void);
unsigned ATI_API_CALL KCL_DEBUG_StackMeasure(void);

#ifdef SPECIAL
#undef SPECIAL
#endif
#ifdef ERROR
#undef ERROR
#endif
#ifdef DWARN
#undef DWARN
#endif
#ifdef INFO
#undef INFO
#endif
#ifdef INFOEX
#undef INFOEX
#endif
#ifdef TRACE
#undef TRACE
#endif
#ifdef PERFORMANCE
#undef PERFORMANCE
#endif
#ifdef DUMP
#undef DUMP
#endif
#ifdef U08
#undef U08
#endif
#ifdef U16
#undef U16
#endif
#ifdef U32
#undef U32
#endif
#ifndef U08
typedef unsigned char U08;
#endif
#ifndef U32
typedef unsigned long U32;
#endif
#ifndef U16
typedef unsigned short U16;
#endif
#define ___BIT(a) 1<<a

typedef enum _LOG_LEVEL_
{
    SPECIAL = 0,
    ERROR  ,
    DWARN  ,
    INFO ,
    INFOEX,
    TRACE,
    PERFORMANCE,
    DUMP,
    LOG_L_MAX
}LOG_LEVEL;

typedef enum _MODULE_TYPE
{
    LOG_M_LOG   = 0,
    LOG_M_CQQ,
    LOG_M_2DD,
    LOG_M_CMM,
    LOG_M_CAIL,
    LOG_M_XMM,
    LOG_M_HAL,
    LOG_M_ADL ,
    LOG_M_MAX,
}MODULE_TYPE,*PMODULE_TYPE;


typedef  struct _module_map
{
    MODULE_TYPE id;
    unsigned char logmap;
    char module_name[8];
    
}module_map,*Pmodule_map;

typedef struct _log_map
{
    LOG_LEVEL level;
    char sign;
}log_map;


#define DEFAULT_LOG_LEVEL ((U08)(___BIT(INFO) | ___BIT(INFOEX) |___BIT(ERROR) |___BIT(DWARN) | ___BIT(TRACE)| ___BIT(SPECIAL)  ))
#define INFO_LOG_LEVEL ((U08)(___BIT(INFO) | ___BIT(INFOEX)))
extern const log_map module_log_map[];
extern const module_map module_type_map[];
#define NEW_LINE "\n"

void LOG_PRINTN_FUNC(const char* module_name,char sign,const char* logMsg,...);

#define TRUE_FALSE(arg) (0 == arg : "FALSE" ? "TRUE")

#define IF_LOG_ENABLED_EX(logModule,logLevel) if(___BIT(logLevel)  & module_type_map[logModule].logmap)
#define LOG_ASSERT(a) if(!a) LOG_PRINTN_FUNC(LOG_M_LOG ,ERROR,"%s assertion failed at (%d) : assertion (%s)",__FUNCTION__,__LINE__,#a );
#define LOG_RELEASE(logModule,logLevel,logMsg,arg...)\
{\
    unsigned char logmap =  module_type_map[logModule].logmap ;\
    const char* module_name = (const char*)module_type_map[logModule].module_name;\
    char sign = module_log_map[logLevel].sign;\
    if(___BIT(logLevel) & logmap) \
    {\
        LOG_PRINTN_FUNC(module_name,sign,(const char*)(logMsg NEW_LINE),##arg);\
    }\
}
#ifdef  DEBUG
#define LOG_PRINTN(logModule,logLevel,logMsg,arg...)\
{\
    if(___BIT(logLevel) & module_type_map[logModule].logmap)\
    {\
        LOG_PRINTN_FUNC((const char*)module_type_map[logModule].module_name,module_log_map[logLevel].sign,(const char*)(logMsg NEW_LINE),##arg);\
    }\
}
#else
#define LOG_PRINTN(logModule,LogLevel,LogMsg,arg...) NULL

#endif



#define KCL_DEBUG_ERROR(fmt, arg...)                                        \
    KCL_DEBUG_Print("<3>[fglrx:%s] *ERROR* " fmt, __FUNCTION__, ##arg)

#define KCL_DEBUG_INFO(fmt, arg...)                                         \
    KCL_DEBUG_Print("<6>[fglrx] " fmt, ##arg)


#define KCL_DEBUG_TRACE(m, p, fmt, arg...)  \
    do                                      \
    {                                       \
        firegl_trace(m,                     \
                     FN_DEBUG_TRACE,        \
                     (void*)__FUNCTION__,   \
                     (int)(__LINE__),       \
                     (long)(p),             \
                     fmt,                   \
                     ##arg);                \
    } while (0)

#define KCL_DEBUG_TRACEIN  KCL_DEBUG_TRACE

#define KCL_DEBUG_TRACEOUT(m, p, fmt, arg...)                                                                     \
    do                                      \
    {                                       \
        firegl_trace(m,                     \
                     FN_DEBUG_TRACEOUT,     \
                     (void*)__FUNCTION__,   \
                     (int)(__LINE__),       \
                     (long)(p),             \
                     fmt,                   \
                     ##arg);                \
    } while (0)

#define KCL_DEBUG1(m, fmt, arg...)          \
    do                                      \
    {                                       \
        firegl_trace(m,                     \
                     FN_DEBUG_LEVEL1,       \
                     (void*)__FUNCTION__,   \
                     (int)__LINE__,         \
                     0,                     \
                     fmt,                   \
                     ##arg);                \
    } while (0)

#define KCL_DEBUG2(m, fmt, arg...)          \
    do                                      \
    {                                       \
        firegl_trace(m,                     \
                     FN_DEBUG_LEVEL2,       \
                     (void*)__FUNCTION__,   \
                     (int)__LINE__,         \
                     0,                     \
                     fmt,                   \
                     ##arg);                \
    } while (0)

#define KCL_DEBUG3(m, fmt, arg...)          \
    do                                      \
    {                                       \
        firegl_trace(m,                     \
                     FN_DEBUG_LEVEL3,       \
                     (void*)__FUNCTION__,   \
                     (int)__LINE__,         \
                     0,                     \
                     fmt,                   \
                     ##arg);                \
    } while (0)

#define KCL_DEBUG4(m, fmt, arg...)          \
    do                                      \
    {                                       \
        firegl_trace(m,                     \
                     FN_DEBUG_LEVEL4,       \
                     (void*)__FUNCTION__,   \
                     (int)__LINE__,         \
                     0,                     \
                     fmt,                   \
                     ##arg);                \
    } while (0)

#define KCL_DEBUG5(m, fmt, arg...)          \
    do                                      \
    {                                       \
        firegl_trace(m,                     \
                     FN_DEBUG_LEVEL5,       \
                     (void*)__FUNCTION__,   \
                     (int)__LINE__,         \
                     0,                     \
                     fmt,                   \
                     ##arg);                \
    } while (0)

#define KCL_DEBUG6(m, fmt, arg...)          \
    do                                      \
    {                                       \
        firegl_trace(m,                     \
                     FN_DEBUG_LEVEL6,       \
                     (void*)__FUNCTION__,   \
                     (int)__LINE__,         \
                     0,                     \
                     fmt,                   \
                     ##arg);                \
    } while (0)

#endif
