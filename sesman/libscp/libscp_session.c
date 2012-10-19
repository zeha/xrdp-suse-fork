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
 * @file libscp_session.c
 * @brief SCP_SESSION handling code
 * @author Simone Fedele
 *
 */

#include "libscp_session.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

extern struct log_config* s_log;

struct SCP_SESSION*
scp_session_create()
{
  struct SCP_SESSION* s;

  s = g_malloc(sizeof(struct SCP_SESSION), 0);

  if (0 == s)
  {
    log_message(s_log, LOG_LEVEL_WARNING, "[session:%d] session create: malloc error", __LINE__);
    return 0;
  }

  s->username = 0;
  s->password = 0;
  s->hostname = 0;
  s->errstr = 0;
  s->locale[0]='\0';

  return s;
}

/*******************************************************************/
int
scp_session_set_type(struct SCP_SESSION* s, tui8 type)
{
  switch (type)
  {
    case SCP_SESSION_TYPE_XVNC:
      s->type = SCP_SESSION_TYPE_XVNC;
      break;
    case SCP_SESSION_TYPE_XRDP:
      s->type = SCP_SESSION_TYPE_XRDP;
      break;
    case SCP_SESSION_TYPE_MANAGE:
      s->type = SCP_SESSION_TYPE_MANAGE;
      break;
    default:
      log_message(s_log, LOG_LEVEL_WARNING, "[session:%d] set_type: unknown type", __LINE__);
      return 1;
  }
  return 0;
}

/*******************************************************************/
int
scp_session_set_version(struct SCP_SESSION* s, tui32 version)
{
  switch (version)
  {
    case 0:
      s->version = 0;
      break;
    case 1:
      s->version = 1;
      break;
    default:
      log_message(s_log, LOG_LEVEL_WARNING, "[session:%d] set_version: unknown version", __LINE__);
      return 1;
  }
  return 0;
}

/*******************************************************************/
int
scp_session_set_height(struct SCP_SESSION* s, tui16 h)
{
  s->height = h;
  return 0;
}

/*******************************************************************/
int
scp_session_set_width(struct SCP_SESSION* s, tui16 w)
{
  s->width = w;
  return 0;
}

/*******************************************************************/
int
scp_session_set_bpp(struct SCP_SESSION* s, tui8 bpp)
{
  switch (bpp)
  {
    case 8:
    case 16:
    case 24:
      s->bpp = bpp;
    default:
      return 1;
  }
  return 0;
}

/*******************************************************************/
int
scp_session_set_rsr(struct SCP_SESSION* s, tui8 rsr)
{
  if (s->rsr)
  {
    s->rsr = 1;
  }
  else
  {
    s->rsr = 0;
  }
  return 0;
}

/*******************************************************************/
int
scp_session_set_locale(struct SCP_SESSION* s, char* str)
{
  if (0 == str)
  {
    log_message(s_log, LOG_LEVEL_WARNING, "[session:%d] set_locale: null locale", __LINE__);
    s->locale[0]='\0';
    return 1;
  }
  g_strncpy(s->locale, str, 17);
  s->locale[17]='\0';
  return 0;
}

/*******************************************************************/
int
scp_session_set_username(struct SCP_SESSION* s, char* str)
{
  if (0 == str)
  {
    log_message(s_log, LOG_LEVEL_WARNING, "[session:%d] set_username: null username", __LINE__);
    return 1;
  }
  if (0 != s->username)
  {
    g_free(s->username);
  }
  s->username = g_strdup(str);
  if (0 == s->username)
  {
    log_message(s_log, LOG_LEVEL_WARNING, "[session:%d] set_username: strdup error", __LINE__);
    return 1;
  }
  return 0;
}

/*******************************************************************/
int
scp_session_set_password(struct SCP_SESSION* s, char* str)
{
  if (0 == str)
  {
    log_message(s_log, LOG_LEVEL_WARNING, "[session:%d] set_password: null password", __LINE__);
    return 1;
  }
  if (0 != s->password)
  {
    g_free(s->password);
  }
  s->password = g_strdup(str);
  if (0 == s->password)
  {
    log_message(s_log, LOG_LEVEL_WARNING, "[session:%d] set_password: strdup error", __LINE__);
    return 1;
  }
  return 0;
}

/*******************************************************************/
int
scp_session_set_hostname(struct SCP_SESSION* s, char* str)
{
  if (0 == str)
  {
    log_message(s_log, LOG_LEVEL_WARNING, "[session:%d] set_hostname: null hostname", __LINE__);
    return 1;
  }
  if (0 != s->hostname)
  {
    g_free(s->hostname);
  }
  s->hostname = g_strdup(str);
  if (0 == s->hostname)
  {
    log_message(s_log, LOG_LEVEL_WARNING, "[session:%d] set_hostname: strdup error", __LINE__);
    return 1;
  }
  return 0;
}

/*******************************************************************/
int
scp_session_set_errstr(struct SCP_SESSION* s, char* str)
{
  if (0 == str)
  {
    log_message(s_log, LOG_LEVEL_WARNING, "[session:%d] set_errstr: null string", __LINE__);
    return 1;
  }
  if (0 != s->errstr)
  {
    g_free(s->errstr);
  }
  s->errstr = g_strdup(str);
  if (0 == s->errstr)
  {
    log_message(s_log, LOG_LEVEL_WARNING, "[session:%d] set_errstr: strdup error", __LINE__);
    return 1;
  }
  return 0;
}

/*******************************************************************/
int
scp_session_set_display(struct SCP_SESSION* s, SCP_DISPLAY display)
{
  s->display = display;
  return 0;
}

/*******************************************************************/
int
scp_session_set_addr(struct SCP_SESSION* s, int type, void* addr)
{
  struct in_addr ip4;
#ifdef IN6ADDR_ANY_INIT
  struct in6_addr ip6;
#endif
  int ret;

  switch (type)
  {
    case SCP_ADDRESS_TYPE_IPV4:
      /* convert from char to 32bit*/
      ret = inet_pton(AF_INET, addr, &ip4);
      if (0 == ret)
      {
        log_message(s_log, LOG_LEVEL_WARNING, "[session:%d] set_addr: invalid address", __LINE__);
        inet_pton(AF_INET, "127.0.0.1", &ip4);
        g_memcpy(&(s->ipv4addr), &(ip4.s_addr), 4);
        return 1;
      }
      g_memcpy(&(s->ipv4addr), &(ip4.s_addr), 4);
      break;
    case SCP_ADDRESS_TYPE_IPV4_BIN:
      g_memcpy(&(s->ipv4addr), addr, 4);
      break;
#ifdef IN6ADDR_ANY_INIT
    case SCP_ADDRESS_TYPE_IPV6:
      /* convert from char to 128bit*/
      ret = inet_pton(AF_INET6, addr, &ip6);
      if (0 == ret)
      {
        log_message(s_log, LOG_LEVEL_WARNING, "[session:%d] set_addr: invalid address", __LINE__);
        inet_pton(AF_INET, "::1", &ip6);
        g_memcpy(s->ipv6addr, &(ip6.s6_addr), 16);
        return 1;
      }
      g_memcpy(s->ipv6addr, &(ip6.s6_addr), 16);
      break;
    case SCP_ADDRESS_TYPE_IPV6_BIN:
      g_memcpy(s->ipv6addr, addr, 16);
      break;
#endif
    default:
      return 1;
  }
  return 0;
}

/*******************************************************************/
void
scp_session_destroy(struct SCP_SESSION* s)
{
  if (s->username)
  {
    g_free(s->username);
    s->username=0;
  }

  if (s->password)
  {
    g_free(s->password);
    s->password=0;
  }

  if (s->hostname)
  {
    g_free(s->hostname);
    s->hostname=0;
  }

  if (s->errstr)
  {
    g_free(s->errstr);
    s->errstr=0;
  }

  g_free(s);
}
