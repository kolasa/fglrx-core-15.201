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

/** \brief KCL ACPI interface declarations */

#ifndef KCL_ACPI_H
#define KCL_ACPI_H

typedef void *KCL_ACPI_DevHandle;
typedef void *KCL_ACPI_CallbackHandle;
typedef void *KCL_ACPI_ContextHandle;
typedef int  *KCL_ACPI_IntCallbackHandle;
typedef char KCL_ACPI_BusId[5];
typedef char KCL_ACPI_DeviceClass[20];

#define KCL_ACPI_OK                 0x0000
#define KCL_ACPI_ERROR              0x0001
#define KCL_ACPI_NOT_AVAILABLE      0xffff
// KCL_ACPI_AC_NOTIFY_STATUS here is defined as the same value as ACPI_AC_NOTIFY_STATUS 0x80 in kernel
#define KCL_ACPI_AC_NOTIFY_STATUS   0x80

#define KCL_ACPI_FIELD_METHOD_NAME                      0x00000001
#define KCL_ACPI_FIELD_INPUT_ARGUMENT_COUNT             0x00000002

#ifndef ACPI_VIDEO_CLASS
#define KCL_ACPI_VIDEO_CLASS                "video"
#else
#define KCL_ACPI_VIDEO_CLASS                ACPI_VIDEO_CLASS
#endif

#ifndef ACPI_AC_CLASS
#define KCL_ACPI_AC_CLASS                "ac_adapter"
#else
#define KCL_ACPI_AC_CLASS                ACPI_AC_CLASS
#endif

struct KCL_ACPI_MethodArgument
{
    unsigned int type;
    unsigned int methodLength;    
    unsigned int dataLength;
    union{
        unsigned int value;
        void *pointer;
    };
};

struct KCL_ACPI_MethodInputInfo
{
    unsigned int size;
    unsigned int field;
    unsigned int name;
    unsigned int inputCount;
    struct KCL_ACPI_MethodArgument *pInputArgument;
    unsigned int outputCount;
    struct KCL_ACPI_MethodArgument *pOutputArgument;
    unsigned int padding[9];
};

//short struct to ease parameter passing
typedef struct KCL_ACPI_MatchInfo{
     KCL_ACPI_DevHandle ac_handle; //acpi handle for ac adapter
     KCL_ACPI_DevHandle video_handle; //acpi handle for video bus
     struct pci_dev* pcidev;
} kcl_match_info_t;

extern unsigned int ATI_API_CALL KCL_ACPI_GetDevHandle(KCL_ACPI_DevHandle parent,
                                                       const char *pathname,
                                                       KCL_ACPI_DevHandle *ret_handle);

unsigned int ATI_API_CALL KCL_ACPI_GetHandles(struct KCL_ACPI_MatchInfo *pInfo);
KCL_ACPI_DevHandle ATI_API_CALL KCL_ACPI_GetAlternateHandle(KCL_ACPI_DevHandle pHandle);

extern unsigned int ATI_API_CALL KCL_ACPI_EvalObject(KCL_ACPI_DevHandle handle,
                                                     struct KCL_ACPI_MethodInputInfo *info);

extern unsigned int ATI_API_CALL KCL_ACPI_InstallHandler(KCL_ACPI_DevHandle device,
                                                         unsigned int handler_type,
                                                         KCL_ACPI_CallbackHandle handler,
                                                         KCL_ACPI_ContextHandle context,
                                                         KCL_NOTIFIER_BLOCKER *nb);

extern unsigned int ATI_API_CALL KCL_ACPI_RemoveHandler(KCL_ACPI_DevHandle device,
                                                        unsigned int handler_type,
                                                        KCL_ACPI_CallbackHandle handler,
                                                        KCL_NOTIFIER_BLOCKER *nb);
extern unsigned int ATI_API_CALL KCL_ACPI_InstallLidHandler(void);
extern unsigned int ATI_API_CALL KCL_ACPI_RemoveLidHandler(void);
extern int ATI_API_CALL KCL_ACPI_Disabled(void);
extern void ATI_API_CALL KCL_ACPI_ExecHandler(KCL_ACPI_CallbackHandle handler, KCL_ACPI_DevHandle handle, unsigned int event, KCL_ACPI_ContextHandle data);
extern KCL_ACPI_CallbackHandle ATI_API_CALL KCL_ACPI_GetNotifyHandler(KCL_ACPI_DevHandle handle);
extern KCL_ACPI_ContextHandle ATI_API_CALL KCL_ACPI_GetNotifyContext(KCL_ACPI_DevHandle handle);
extern void ATI_API_CALL KCL_ACPI_UpdateNotifyHandler(KCL_ACPI_DevHandle handle, KCL_ACPI_CallbackHandle handler);
extern void ATI_API_CALL KCL_ACPI_UpdateNotifyContext(KCL_ACPI_DevHandle handle, KCL_ACPI_ContextHandle context);
extern KCL_ACPI_DevHandle ATI_API_CALL KCL_ACPI_GetChildDevice(KCL_ACPI_DevHandle handle);
extern KCL_ACPI_DevHandle ATI_API_CALL KCL_ACPI_GetPeerDevice(KCL_ACPI_DevHandle handle);
extern void* KCL_ACPI_GetVfctBios(unsigned long *size);
extern void ATI_API_CALL KCL_ACPI_No_Hotplug(void *);

// Callback functions called by kernel
extern void KCL_ACPI_AcNotify(KCL_ACPI_DevHandle handle, unsigned int event, KCL_ACPI_ContextHandle data);
extern void KCL_ACPI_VideoNotify(KCL_ACPI_DevHandle handle, unsigned int event, KCL_ACPI_ContextHandle data);

// libip functions
extern void ATI_API_CALL libip_ac_notify(KCL_ACPI_DevHandle handle, unsigned int event, KCL_ACPI_ContextHandle data, unsigned int *newstate);
extern unsigned int ATI_API_CALL libip_video_notify(KCL_ACPI_DevHandle handle, unsigned int event, KCL_ACPI_ContextHandle data);

extern void ATI_API_CALL libip_lid_open_notify(unsigned int);

extern int ATI_API_CALL KCL_ACPI_GetFgConsole(void);
extern int ATI_API_CALL KCL_ACPI_GetNewVt(int console);
extern int ATI_API_CALL KCL_ACPI_ParseTable(char *id, KCL_ACPI_IntCallbackHandle handler);

extern unsigned int ATI_API_CALL KCL_ACPI_PowerXpressDevice(KCL_ACPI_DevHandle handle);

extern KCL_ACPI_ContextHandle ATI_API_CALL firegl_query_acpi_handle(KCL_NOTIFIER_BLOCKER nb, KCL_ACPI_DeviceClass devclass);

#endif
