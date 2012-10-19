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
   Copyright (C) Jay Sorg 2004-2008

   default file locations for log, config, etc

*/

#if !defined(FILE_LOC_H)
#define FILE_LOC_H

#if !defined(XRDP_CFG_PATH)
#define XRDP_CFG_PATH "/etc/xrdp"
#endif

#if !defined(XRDP_CFG_FILE)
#define XRDP_CFG_FILE "/etc/xrdp/xrdp.ini"
#endif

#if !defined(XRDP_KEY_FILE)
#define XRDP_KEY_FILE "/etc/xrdp/rsakeys.ini"
#endif

#if !defined(XRDP_KEYMAP_FILE)
#define XRDP_KEYMAP_FILE "/etc/xrdp/km-%4.4x.ini"
#endif

#if !defined(XRDP_PID_FILE)
#define XRDP_PID_FILE "/var/run/xrdp.pid"
#endif

#if !defined(XRDP_SBIN_PATH)
#define XRDP_SBIN_PATH "/usr/local/sbin"
#endif

#if !defined(XRDP_SHARE_PATH)
#define XRDP_SHARE_PATH "/usr/local/share/xrdp"
#endif

#if !defined(SESMAN_PID_FILE)
#define SESMAN_PID_FILE "/var/run/sesman.pid"
#endif

#if !defined(SESMAN_CFG_FILE)
#define SESMAN_CFG_FILE "/etc/xrdp/sesman.ini"
#endif

#endif
