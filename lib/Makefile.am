#------------------------------------------------------------------------------
#
#  $Id: Makefile.am,v 8e173dddd183 2010/10/25 14:45:33 fp $
# 
#  Copyright (C) 2006-2009  Florian Pose, Ingenieurgemeinschaft IgH
# 
#  This file is part of the IgH EtherCAT master userspace library.
# 
#  The IgH EtherCAT master userspace library is free software; you can
#  redistribute it and/or modify it under the terms of the GNU Lesser General
#  Public License as published by the Free Software Foundation; version 2.1 of
#  the License.
#  
#  The IgH EtherCAT master userspace library is distributed in the hope that
#  it will be useful, but WITHOUT ANY WARRANTY; without even the implied
#  warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Lesser General Public License for more details.
#  
#  You should have received a copy of the GNU Lesser General Public License
#  along with the IgH EtherCAT master userspace library. If not, see
#  <http://www.gnu.org/licenses/>.
# 
#  ---
#
#  The license mentioned above concerns the source code only. Using the
#  EtherCAT technology and brand is only permitted in compliance with the
#  industrial property and similar rights of Beckhoff Automation GmbH.
#
#------------------------------------------------------------------------------

AM_CFLAGS = -Wall

lib_LTLIBRARIES = libethercat.la

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libethercat.pc
EXTRA_DIST = libethercat.pc.in

clean-local:
	rm -f libethercat.pc

#------------------------------------------------------------------------------

libethercat_la_LDFLAGS = -version-info 1:0:0
libethercat_la_CFLAGS = -I$(srcdir)/.. -fno-strict-aliasing \
	-DEC_MASTER_IN_USERSPACE -Wall -Werror
libethercat_la_SOURCES = \
	common.c \
	domain.c \
	master.c \
	sdo_request.c \
	slave_config.c \
	voe_handler.c

noinst_HEADERS = \
	domain.h \
	master.h \
	sdo_request.h \
	slave_config.h \
	voe_handler.h

#------------------------------------------------------------------------------
