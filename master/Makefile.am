#------------------------------------------------------------------------------
#
#  $Id: Makefile.am,v 7b77000f9764 2010/03/19 11:01:32 fp $
#
#  Copyright (C) 2006-2008  Florian Pose, Ingenieurgemeinschaft IgH
#
#  This file is part of the IgH EtherCAT Master.
#
#  The IgH EtherCAT Master is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License version 2, as
#  published by the Free Software Foundation.
#
#  The IgH EtherCAT Master is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
#  Public License for more details.
#
#  You should have received a copy of the GNU General Public License along
#  with the IgH EtherCAT Master; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#
#  ---
#  
#  The license mentioned above concerns the source code only. Using the
#  EtherCAT technology and brand is only permitted in compliance with the
#  industrial property and similar rights of Beckhoff Automation GmbH.
#
#------------------------------------------------------------------------------

# using HEADERS to enable tags target
noinst_HEADERS = \
	cdev.c cdev.h \
	datagram.c datagram.h \
	debug.c	debug.h \
	device.c device.h \
	domain.c domain.h \
	doxygen.c \
	ethernet.c ethernet.h \
	fmmu_config.c fmmu_config.h \
	foe.h \
	foe_request.c foe_request.h \
	fsm_change.c fsm_change.h \
	fsm_coe.c fsm_coe.h \
	fsm_foe.c fsm_foe.h \
	fsm_master.c fsm_master.h \
	fsm_pdo.c fsm_pdo.h \
	fsm_pdo_entry.c fsm_pdo_entry.h \
	fsm_sii.c fsm_sii.h \
	fsm_slave.c fsm_slave.h \
	fsm_slave_config.c fsm_slave_config.h \
	fsm_slave_scan.c fsm_slave_scan.h \
	fsm_soe.c fsm_soe.h \
	globals.h \
	ioctl.h \
	mailbox.c mailbox.h \
	master.c master.h \
	module.c \
	pdo.c pdo.h \
	pdo_entry.c pdo_entry.h \
	pdo_list.c pdo_list.h \
	sdo.c sdo.h \
	sdo_entry.c sdo_entry.h \
	sdo_request.c sdo_request.h \
	slave.c slave.h \
	slave_config.c slave_config.h \
	soe_errors.c \
	soe_request.c soe_request.h \
	sync.c sync.h \
	sync_config.c sync_config.h \
	voe_handler.c voe_handler.h

EXTRA_DIST = \
	Kbuild.in

BUILT_SOURCES = \
	Kbuild

modules:
	$(MAKE) -C "$(LINUX_SOURCE_DIR)" M="@abs_srcdir@" modules

modules_install:
	$(MAKE) -C "$(LINUX_SOURCE_DIR)" M="@abs_srcdir@" \
		INSTALL_MOD_DIR="$(INSTALL_MOD_DIR)" modules_install

clean-local:
	rm -f ethercat_master.1 libethercat_master.pc

#------------------------------------------------------------------------------

# user-space library

lib_LTLIBRARIES = libethercat_master.la

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libethercat_master.pc
EXTRA_DIST += libethercat_master.pc.in

libethercat_master_la_LDFLAGS = -version-info 1:0:0

libethercat_master_la_CFLAGS = -I$(srcdir)/.. \
	-I../emulation \
	-D__KERNEL__ \
	-DEC_HAVE_CYCLES \
	-DEC_USE_HRTIMER \
	-DEC_MASTER_IN_USERSPACE \
	-Wall -Werror \
	-fno-strict-aliasing

libethercat_master_la_SOURCES = \
	cdev.c \
	datagram.c \
	device.c \
	domain.c \
	fmmu_config.c \
	foe_request.c \
	fsm_change.c \
	fsm_coe.c \
	fsm_foe.c \
	fsm_master.c \
	fsm_pdo.c \
	fsm_pdo_entry.c \
	fsm_sii.c \
	fsm_slave.c \
	fsm_slave_config.c \
	fsm_slave_scan.c \
	fsm_soe.c \
	mailbox.c \
	master.c \
	module.c \
	pdo.c \
	pdo_entry.c \
	pdo_list.c \
	sdo.c \
	sdo_entry.c \
	sdo_request.c \
	slave.c \
	slave_config.c \
	soe_errors.c \
	soe_request.c \
	sync.c \
	sync_config.c \
	voe_handler.c \
	../devices/generic.c
if ENABLE_EOE
libethercat_master_la_SOURCES += ethernet.c
endif

bin_PROGRAMS = ethercat_master

dist_man_MANS = ethercat_master.1

EXTRA_ethercat_master_DEPENDENCIES = $(lib_LTLIBRARIES)

ethercat_master.1: ethercat_master$(EXEEXT)
	PATH=".:$$PATH" help2man -o "$@" "$<" -s1 -n"EtherCAT master with no application task" --no-info

ethercat_master_SOURCES = ethercat_master.c

ethercat_master_LDADD = -lethercat_master -lpthread

ethercat_master_CFLAGS = \
	-fno-strict-aliasing \
	-DEC_MASTER_IN_USERSPACE \
	-Wall -Werror
