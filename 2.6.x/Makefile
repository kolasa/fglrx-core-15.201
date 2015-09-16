# Copyright (c) 2008 Advanced Micro Devices. All Rights Reserved.
# 
# Redistribution and  use  in  source  and  binary  forms,  with  or  without
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above  copyright  notice,
# this list of conditions and the following disclaimer.
# 
# 2. Redistributions in  binary  form  must  reproduce  the  above  copyright
# notice, this list  of  conditions  and  the  following  disclaimer  in  the
# documentation and/or other materials provided with the distribution.
# 
# 3. The name of the author may not be used to endorse  or  promote  products
# derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR  IMPLIED
# WARRANTIES, INCLUDING, BUT  NOT  LIMITED  TO,  THE  IMPLIED  WARRANTIES  OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN  NO
# EVENT SHALL THE AUTHOR BE LIABLE  FOR  ANY  DIRECT,  INDIRECT,  INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,  BUT  NOT  LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;  LOSS  OF  USE,  DATA,  OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED  AND  ON  ANY  THEORY  OF
# LIABILITY, WHETHER  IN  CONTRACT,  STRICT  LIABILITY,  OR  TORT  (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING  IN  ANY  WAY  OUT  OF  THE  USE  OF  THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

LIBIP_PREFIX	?= ..

obj-m           += fglrx.o
fglrx-libs      += libfglrx_ip.a

fglrx-c-objs    += firegl_public.o      \
                   kcl_acpi.o           \
                   kcl_agp.o            \
                   kcl_debug.o          \
                   kcl_ioctl.o          \
                   kcl_io.o             \
                   kcl_pci.o            \
                   kcl_str.o            \
                   kcl_iommu.o          \
                   kcl.o                \
                   kcl_wait.o

fglrx-objs      += $(fglrx-c-objs) $(fglrx-libs)

fglrx-hdrs      += firegl_public.h      \
                   fglrxko_pci_ids.h    \
                   kcl_acpi.h           \
                   kcl_agp.h            \
                   kcl_config.h         \
                   kcl_debug.h          \
                   kcl_io.h             \
                   kcl_ioctl.h          \
                   kcl_osconfig.h       \
                   kcl_pci.h            \
                   kcl_str.h            \
                   kcl.h                \
                   kcl_iommu.h          \
                   kcl_type.h           \
                   kcl_wait.h
                   
drm-hdrs        += drm.h drmP.h drm_os_linux.h drm_proc.h drm_compat.h

EXTRA_CFLAGS    += \
                -I$(PWD) \
                -DFGL \
                -DFGL_LINUX \
                -DFGL_GART_RESERVED_SLOT \
                -DFGL_LINUX253P1_VMA_API \
                -DPAGE_ATTR_FIX=$(PAGE_ATTR_FIX) \

ifeq ($(KERNELRELEASE),)
# on first call from remote location we get into this path
# whilst on second call all is managed by the embedding kernel makefile

ifeq ($(KVER),)
	KVER        = $(shell uname -r)
endif

KDIR            = /lib/modules/$(KVER)/build
PWD             = $(shell pwd)

fglrx-cfiles    = ${fglrx-c-objs:.o=.c}

# default:: kmod_build

kmod_build:: $(fglrx-libs) $(fglrx-cfiles) $(fglrx-hdrs) $(drm-hdrs)
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

%.c:
	@ln -s ../$@

%.h:
	@ln -s ../$@

%.a:
	@ln -s $(LIBIP_PREFIX)/$@

# distclean:: clean

clean::
	rm -rf *.c *.h *.o *.ko *.a .??* *.symvers

endif

# ### EOF ###
