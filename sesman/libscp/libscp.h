/*
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

   xrdp: A Remote Desktop Protocol server.
   Copyright (C) Jay Sorg 2005-2008
*/

/**
 *
 * @file libscp.h
 * @brief libscp main header
 * @author Simone Fedele
 * 
 */

#ifndef LIBSCP_H
#define LIBSCP_H

#if defined(HAVE_CONFIG_H)
#include "config_ac.h"
#endif

#include "libscp_types.h"

#include "libscp_connection.h"
#include "libscp_session.h"
#include "libscp_init.h"
#include "libscp_tcp.h"
#include "libscp_lock.h"

#include "libscp_vX.h"
#include "libscp_v0.h"
#include "libscp_v1s.h"
#include "libscp_v1c.h"
#include "file_loc.h"

#endif
