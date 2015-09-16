/****************************************************************************
 *                                                                          *
 * Copyright 2010-2015 ATI Technologies Inc., Markham, Ontario, CANADA.     *
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

/** \brief KCL OS independent generic interface implementation  */

#include <linux/kernel.h>
#include <linux/sched.h>
#include "kcl_config.h"
#include "kcl_type.h"
#include "kcl.h"

#include "kcl_debug.h"
#include <linux/vt_kern.h>
#include <linux/vt_buffer.h>
#include <linux/firmware.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/pci.h>

#define SUSPEND_CONSOLE  (MAX_NR_CONSOLES-1)

/** \brief Send signal to a specified pid
 *  \param pid   thread group leader id 
 *  \param sig   signal to be send 
 *  \return None
 */
void ATI_API_CALL KCL_SEND_SIG(int pid, KCL_SIG sig)
{
    struct task_struct *group_leader = current->group_leader;
    if(pid == group_leader->pid)
    {
        send_sig((int)sig, group_leader, 1);   //1 -> SEND_SIG_PRIC 
    }    
}    


void ATI_API_CALL KCL_Init_Suspend_Console(void)
{
    if(vc_cons[SUSPEND_CONSOLE].d != NULL && vc_cons[fg_console].d->vt_newvt == SUSPEND_CONSOLE)
    {
        struct vc_data  *vc = vc_cons[SUSPEND_CONSOLE].d;
       	unsigned int    count;
        unsigned short  *start;
    
        vc->vc_x    = 0;
        vc->vc_y    = 0;
        vc->vc_pos  = vc->vc_origin + vc->vc_y * vc->vc_size_row + (vc->vc_x<<1);

        count = vc->vc_cols * vc->vc_rows;
        start = (unsigned short *)vc->vc_origin;
        scr_memsetw(start, vc->vc_video_erase_char, 2 * count);
    }
}

int  ATI_API_CALL KCL_Request_Firmware(KCL_FIRMWARE *pFirmware)
{
    const struct firmware *pfw = NULL;
    struct device *pdev = NULL;
    struct pci_dev *pdev_pci = NULL;
    
    if(NULL == pFirmware)
    {
        return -EINVAL;
    }
    
    if(NULL == pFirmware->name || NULL == pFirmware->dev)
    {
        return -EINVAL;
    }

    pdev_pci = (struct pci_dev *)(pFirmware->dev);
    pdev = (struct device *)(&pdev_pci->dev);
    
    if(NULL == pdev)
    {
        return -EINVAL;
    }
    
    pfw = (const struct firmware *)kmalloc(sizeof(struct firmware), GFP_KERNEL);
    if(NULL == pfw)
    {
        return -EINVAL;
    }

    memset((void *)pfw, 0, sizeof(struct firmware));
    if(request_firmware(&pfw, (char *)pFirmware->name, pdev) != 0)
    {
        kfree((void *)pfw);
        pfw = NULL;
        return -EINVAL;
    }
    
    pFirmware->size = pfw->size;
    pFirmware->data = (void *)pfw->data; 
    pFirmware->fw = (void *)pfw;
    
    return 0;
}

int ATI_API_CALL KCL_Release_Firmware(KCL_FIRMWARE *pFirmware)
{
    
    if(NULL == pFirmware)
    {
        return -EINVAL;
    }
    
    if(NULL == pFirmware->fw)
    {
        return -EINVAL;
    }
    
    release_firmware((struct firmware *)pFirmware->fw);
    kfree(pFirmware->fw);
    pFirmware->fw = NULL;
    
    return 0;
}