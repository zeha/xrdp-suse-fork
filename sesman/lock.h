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

#ifndef LOCK_H
#define LOCK_H

#include "sesman.h"

/**
 *
 * @brief initializes all the locks
 *
 */
void DEFAULT_CC
lock_init(void);

/**
 *
 * @brief acquires the lock for the session chain
 *
 */
void DEFAULT_CC
lock_chain_acquire(void);

/**
 *
 * @brief releases the sessiona chain lock
 *
 */
void DEFAULT_CC
lock_chain_release(void);

/**
 *
 * @brief acquires config lock
 *
 */
void DEFAULT_CC
lock_cfg_acquire(void);

/**
 *
 * @brief releases config lock
 *
 */
void DEFAULT_CC
lock_cfg_release(void);

/**
 *
 * @brief request the socket lock
 *
 */
void DEFAULT_CC
lock_socket_acquire(void);

/**
 *
 * @brief releases the socket lock
 *
 */
void DEFAULT_CC
lock_socket_release(void);

#endif

