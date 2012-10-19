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
   Copyright (C) Novell, Inc. 2008

   libdmx main file

*/

#include "dmx.h"
#include "libxrdpinc.h"
#include "xrdp_types.h"
#include "list.h"
#include <stdlib.h>
#include <dbus/dbus.h>
#ifndef _WIN32
#include <sys/un.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <X11/Xauth.h>
#endif
#ifndef X_UNIX_PATH
#  ifdef __hpux
#    define X_UNIX_PATH "/var/spool/sockets/X11/%u"
#  else
#    define X_UNIX_PATH "/tmp/.X11-unix/X%u"
#  endif
#endif /* X_UNIX_PATH */
#define _PATH_UNIX_X X_UNIX_PATH

#define DMX_ERROR_INVALID_SCREEN "org.x.config.dmx.InvalidScreen"
#define DMX_ERROR_SCREEN_IN_USE  "org.x.config.dmx.ScreenInUse"

#define RDPX11_CHANNEL_RBUF (16 * 1024)

#define RDPX11_OPEN_REQUEST      1
#define RDPX11_OPEN_CONFIRMATION 2
#define RDPX11_OPEN_FAILURE      3

/******************************************************************************/
/* returns error */
int DEFAULT_CC
lib_recv(struct mod* mod, char* data, int len)
{
  int rcvd;

  if (mod->sck_closed)
  {
    return 1;
  }
  while (len > 0)
  {
    rcvd = g_tcp_recv(mod->sck, data, len, 0);
    if (rcvd == -1)
    {
      if (g_tcp_last_error_would_block(mod->sck))
      {
        if (mod->server_is_term(mod))
        {
          return 1;
        }
        g_tcp_can_recv(mod->sck, 10);
      }
      else
      {
        return 1;
      }
    }
    else if (rcvd == 0)
    {
      mod->sck_closed = 1;
      return 1;
    }
    else
    {
      data += rcvd;
      len -= rcvd;
    }
  }
  return 0;
}

/*****************************************************************************/
/* returns error */
int DEFAULT_CC
lib_send(struct mod* mod, char* data, int len)
{
  int sent;

  if (mod->sck_closed)
  {
    return 1;
  }
  while (len > 0)
  {
    sent = g_tcp_send(mod->sck, data, len, 0);
    if (sent == -1)
    {
      if (g_tcp_last_error_would_block(mod->sck))
      {
        if (mod->server_is_term(mod))
        {
          return 1;
        }
        g_tcp_can_send(mod->sck, 10);
      }
      else
      {
        return 1;
      }
    }
    else if (sent == 0)
    {
      mod->sck_closed = 1;
      return 1;
    }
    else
    {
      data += sent;
      len -= sent;
    }
  }
  return 0;
}

/******************************************************************************/
/* return error */
int DEFAULT_CC
lib_mod_start(struct mod* mod, int w, int h, int bpp)
{
  LIB_DEBUG(mod, "in lib_mod_start");
  mod->width = w;
  mod->height = h;
  mod->bpp = bpp;
  mod->xpid = 0;
  LIB_DEBUG(mod, "out lib_mod_start");
  return 0;
}

/******************************************************************************/
static int DEFAULT_CC
dmx_connect(DBusConnection* c,
	    char*           display,
	    char*           name,
	    char*           proto,
	    int             proto_len,
	    char*           data,
	    int             data_len,
	    int             dmxdisplay,
	    dbus_uint32_t   window,
	    DBusError       *err)
{
    DBusMessage     *message;
    DBusMessage     *reply;
    DBusMessageIter iter, subiter;
    dbus_uint32_t   screen = 0;
    dbus_bool_t     core = TRUE;
    char            dest[256];
    char            path[256];
    int		    i;
    
    g_sprintf (dest, "org.x.config.display%d", dmxdisplay);
    g_sprintf (path, "/org/x/config/dmx/%d", dmxdisplay);

    do
    {
	message = dbus_message_new_method_call (dest,
						path,
						"org.x.config.dmx",
						"attachScreen");
	if (!message)
	{
	    dbus_set_error (err, DBUS_ERROR_NO_MEMORY, "Not enough memory");
	    break;
	}

	dbus_message_iter_init_append (message, &iter);

	dbus_message_iter_append_basic (&iter,
					DBUS_TYPE_UINT32,
					&screen);
	dbus_message_iter_append_basic (&iter,
					DBUS_TYPE_STRING,
					&display);
	dbus_message_iter_append_basic (&iter,
					DBUS_TYPE_STRING,
					&name);
	dbus_message_iter_append_basic (&iter,
					DBUS_TYPE_UINT32,
					&window);
	dbus_message_iter_open_container (&iter,
					  DBUS_TYPE_ARRAY,
					  DBUS_TYPE_BYTE_AS_STRING,
					  &subiter);
	for (i = 0; i < proto_len; i++)
	    dbus_message_iter_append_basic (&subiter,
					    DBUS_TYPE_BYTE,
					    &proto[i]);
	dbus_message_iter_close_container (&iter, &subiter);
	dbus_message_iter_open_container (&iter,
					  DBUS_TYPE_ARRAY,
					  DBUS_TYPE_BYTE_AS_STRING,
					  &subiter);
	for (i = 0; i < data_len; i++)
	    dbus_message_iter_append_basic (&subiter,
					    DBUS_TYPE_BYTE,
					    &data[i]);
	dbus_message_iter_close_container (&iter, &subiter);
    
	reply = dbus_connection_send_with_reply_and_block (c,
							   message,
							   -1,
							   err);

	dbus_message_unref (message);

	if (dbus_error_is_set (err))
	{
	    if (g_strcmp (err->name, DMX_ERROR_SCREEN_IN_USE) == 0)
	    {
		dbus_error_free (err);
		dbus_error_init (err);

		screen++; /* try next screen */
	    }
	    else
	    {
		if (g_strcmp (err->name, DMX_ERROR_INVALID_SCREEN) == 0)
		{
		    dbus_error_free (err);
		    dbus_error_init (err);

		    dbus_set_error (err,
				    DMX_ERROR_SCREEN_IN_USE,
				    "No available screens on display %d",
				    dmxdisplay);
		}

		break;
	    }
	}
    } while (!reply);

    if (dbus_error_is_set (err))
	return 1;

    dbus_message_unref (reply);

    message = dbus_message_new_method_call (dest,
					    path,
					    "org.x.config.dmx",
					    "addInput");
    if (!message)
    	return 0;

    dbus_message_iter_init_append (message, &iter);

    dbus_message_iter_append_basic (&iter,
				    DBUS_TYPE_UINT32,
				    &screen);

    dbus_message_iter_append_basic (&iter,
				    DBUS_TYPE_BOOLEAN,
				    &core);

    reply = dbus_connection_send_with_reply_and_block (c,
						       message,
						       -1,
						       err);

    dbus_message_unref (message);

    if (dbus_error_is_set (err))
	return 1;

    dbus_message_unref (reply);

    message = dbus_message_new_method_call (dest,
					    path,
					    "org.x.config.dmx",
					    "enableScreen");
    if (!message)
    {
	dbus_set_error (err, DBUS_ERROR_NO_MEMORY, "Not enough memory");
	return 1;
    }

    dbus_message_iter_init_append (message, &iter);

    dbus_message_iter_append_basic (&iter,
				    DBUS_TYPE_UINT32,
				    &screen);

    if (!dbus_connection_send (c, message, NULL))
    {
	dbus_set_error (err, DBUS_ERROR_NO_MEMORY, "Not enough memory");
	dbus_message_unref (message);
	return 1;
    }

    dbus_message_unref (message);

    dbus_connection_flush (c);

    return 0;
}

#ifndef _WIN32
static int received_usr1;

static void
sig_usr1_waiting (int sig)
{
    g_signal (sig, sig_usr1_waiting);
    received_usr1++;
}

#define AUTH_DATA_LEN 16 /* bytes of authorization data */

static int
lib_mod_setup_auth (struct mod* mod,
		    char*       display,
		    char*       auth_data,
		    int         auth_fd)
{
    Xauth   auth;
    int	    random_fd, i;
    ssize_t bytes, size;
    char    auth_host[256];
    FILE    *file;

    auth.family = FamilyLocal;

    gethostname (auth_host, sizeof (auth_host));

    auth.address	= auth_host;
    auth.address_length = strlen (auth_host);

    auth.number        = display;
    auth.number_length = strlen (auth.number);

    auth.name	     = "MIT-MAGIC-COOKIE-1";
    auth.name_length = strlen (auth.name);

    random_fd = open ("/dev/urandom", O_RDONLY);
    if (random_fd == -1)
    {
	mod->server_msg(mod, "error - can't open /dev/urandom", 0);
	return 1;
    }

    bytes = 0;
    do {
	size = read (random_fd, auth_data + bytes, AUTH_DATA_LEN - bytes);
	if (size <= 0)
	    break;

	bytes += size;
    } while (bytes != AUTH_DATA_LEN);

    close (random_fd);

    if (bytes != AUTH_DATA_LEN)
    {
	mod->server_msg(mod, "error - failed when reading bytes from "
			"/dev/urandom", 0);
	return 1;
    }

    auth.data	     = auth_data;
    auth.data_length = AUTH_DATA_LEN;

    file = fdopen (auth_fd, "w");
    if (!file)
    {
	close (auth_fd);
	return 1;
    }

    XauWriteAuth (file, &auth);
    fclose (file);

    return 0;
}
#endif

/* return error */
static int DEFAULT_CC
lib_mod_connect_rdp(struct mod* mod)
{
  int error = 0;
  int len;
  int i;
  int pid;
  struct stream* s;
  char con_port[256];
  char** pp1;
  struct list* xserver_params=0;
  char screen[256];
  char geometry[256];
  char depth[256];
  char port[256];
  char name[512];
  struct xrdp_wm* wm = (struct xrdp_wm *) mod->wm;

#ifndef _WIN32
  char auth_file[256];
  const char *auth_templ = "/tmp/.Xdmx-auth-XXXXXX";
  char auth_data[AUTH_DATA_LEN];
  int auth_fd;
  int mask;
#endif

  g_sprintf(screen, ":%d", mod->display);
  g_sprintf(geometry, "%dx%d", mod->width, mod->height);
  g_sprintf(depth, "%d", mod->bpp);
  g_sprintf(port, "%d", atoi (mod->port) - 6000);
  g_sprintf(name, "%s@%s", mod->username, mod->hostname);

#ifndef _WIN32
  received_usr1 = 0;
  g_signal (SIGUSR1, sig_usr1_waiting);

  strcpy (auth_file, auth_templ);
  mask = umask (0077);
  auth_fd = mkstemp (auth_file);
  umask (mask);

  if (auth_fd == -1)
  {
      mod->server_msg(mod, "error - generating unique authorization file", 0);
      return 1;
  }

  if (lib_mod_setup_auth (mod, screen + 1, auth_data, auth_fd))
      return 1;
#endif

  mod->xpid = g_fork();
  if (mod->xpid == -1)
  {
  }
  else if (mod->xpid == 0)
  {

#ifndef _WIN32
      g_signal (SIGUSR1, SIG_IGN);
#endif

      xserver_params = list_create();
      xserver_params->auto_free = 1;
      list_add_item(xserver_params, (long)g_strdup("X11rdp"));
      list_add_item(xserver_params, (long)g_strdup(screen));
      list_add_item(xserver_params, (long)g_strdup("-geometry"));
      list_add_item(xserver_params, (long)g_strdup(geometry));
      list_add_item(xserver_params, (long)g_strdup("-depth"));
      list_add_item(xserver_params, (long)g_strdup(depth));
      list_add_item(xserver_params, (long)g_strdup("-nolisten"));
      list_add_item(xserver_params, (long)g_strdup("tcp"));
#ifdef _WIN32
      list_add_item(xserver_params, (long)g_strdup("-ac"));
#else
      list_add_item(xserver_params, (long)g_strdup("-auth"));
      list_add_item(xserver_params, (long)g_strdup(auth_file));
#endif
      list_add_item(xserver_params, (long)g_strdup("-br"));
      list_add_item(xserver_params, (long)g_strdup("-terminate"));

      /* make sure it ends with a zero */
      list_add_item(xserver_params, 0);
      pp1 = (char**)xserver_params->items;
      g_execvp("X11rdp", pp1);
      exit (1);
  }
  else
  {
      DBusConnection *c;
      int            time = 0;
      DBusError      err;

      dbus_error_init (&err);

      c = dbus_bus_get_private (DBUS_BUS_SYSTEM, &err);
      if (dbus_error_is_set (&err))
      {
	  mod->server_msg(mod, (char *) err.message, 0);
	  dbus_error_free (&err);
	  g_sigterm(mod->xpid);
	  mod->xpid = 0;
	  return 1;
      }

#ifdef _WIN32
      g_sleep (5000);
#else
      /* wait for X11rdp to start */
      while (time < 5000)
      {
	  if (received_usr1)
	      break;

	  time += 50;
	  g_sleep(time);
      }

      if (!received_usr1)
      {
	  mod->server_msg(mod, "error - starting X11 RDP server", 0);
	  g_sigterm(mod->xpid);
	  mod->xpid = 0;
	  return 1;
      }
#endif

      mod->server_msg(mod, "X11 RDP server started", 0);

      if (dmx_connect (c,
		       screen,
		       name,
		       "MIT-MAGIC-COOKIE-1",
		       strlen ("MIT-MAGIC-COOKIE-1"),
		       auth_data,
		       AUTH_DATA_LEN,
		       atoi (mod->port) - 6000,
		       0,
		       &err))
      {
	  if (dbus_error_is_set (&err))
	  {
	      mod->server_msg(mod, (char *) err.message, 0);
	      dbus_error_free (&err);
	  }

	  dbus_connection_close (c);
	  g_sigterm(mod->xpid);
	  mod->xpid = 0;
	  return 1;
      }

      dbus_connection_close (c);

      g_sprintf(con_port, "62%2.2d", mod->display);
      mod->server_msg(mod, "DMX connection established", 0);
      make_stream(s);

      mod->sck = g_tcp_socket();
      mod->sck_obj = g_create_wait_obj_from_socket(mod->sck, 0);
      mod->sck_closed = 0;
      error = g_tcp_connect(mod->sck, mod->ip, con_port);
      if (error == 0)
      {
	  g_tcp_set_non_blocking(mod->sck);
	  g_tcp_set_no_delay(mod->sck);
      }
      if (error == 0)
      {
	  init_stream(s, 8192);
	  s_push_layer(s, iso_hdr, 4);
	  out_uint16_le(s, 103);
	  out_uint32_le(s, 200);
	  /* x and y */
	  i = 0;
	  out_uint32_le(s, i);
	  /* width and height */
	  i = ((mod->width & 0xffff) << 16) | mod->height;
	  out_uint32_le(s, i);
	  out_uint32_le(s, 0);
	  out_uint32_le(s, 0);
	  s_mark_end(s);
	  len = (int)(s->end - s->data);
	  s_pop_layer(s, iso_hdr);
	  out_uint32_le(s, len);
	  lib_send(mod, s->data, len);
      }
      else
      {
          mod->server_msg(mod,
                          "error - couldn't connect to X11 RDP server",
                          0); 
      }
      free_stream(s);
  }

  return error;
}

/* return 0 if there isn't a display running, nonzero otherwise */
static int DEFAULT_CC
x_server_running(int display)
{
    char text[256];
    int x_running;

    g_sprintf(text, "/tmp/.X11-unix/X%d", display);
    x_running = g_file_exist(text);
    if (!x_running)
    {
        g_sprintf(text, "/tmp/.X%d-lock", display);
	x_running = g_file_exist(text);
    }
    return x_running;
}

/* return error */
int DEFAULT_CC
lib_mod_connect(struct mod* mod)
{
  int error = 0;

  LIB_DEBUG(mod, "in lib_mod_connect");
  /* clear screen */
  mod->server_begin_update(mod);
  mod->server_set_fgcolor(mod, 0);
  mod->server_fill_rect(mod, 0, 0, mod->width, mod->height);
  mod->server_end_update(mod);
  mod->server_msg(mod, "started connecting", 0);
  /* only support 8, 16 and 24 bpp connections from rdp client */
  if (mod->bpp != 8 && mod->bpp != 16 && mod->bpp != 24)
  {
    mod->server_msg(mod,
      "error - only supporting 8, 16 and 24 bpp rdp connections", 0);
    LIB_DEBUG(mod, "out lib_mod_connect error");
    return 1;
  }
  if (g_strcmp(mod->ip, "") == 0)
  {
    mod->server_msg(mod, "error - no ip set", 0);
    LIB_DEBUG(mod, "out lib_mod_connect error");
    return 1;
  }
  if (g_strcmp(mod->ip, "127.0.0.1") != 0)
  {
    mod->server_msg(mod, "error - dmx ip is not 127.0.0.1", 0);
    LIB_DEBUG(mod, "out lib_mod_connect error");
    return 1;
  }

  mod->display = atoi (mod->port) + (MAX_SESSIONS_LIMIT * 2) - 6000;

  while (mod->display <= (MAX_SESSIONS_LIMIT * 4))
  {
      if (!x_server_running (mod->display))
	  break;
      
      mod->display++;
  }

  if (mod->display > (MAX_SESSIONS_LIMIT * 4))
  {
    mod->server_msg(mod, "error - no available display offset", 0);
    LIB_DEBUG(mod, "out lib_mod_connect error");
    return 1;
  }
  
  mod->xpid = 0;
  mod->sck = 0;
  mod->sck_obj = 0;
  mod->sck_closed = 1;
  mod->x11_client_sck = 0;
  mod->x11_client_sck_obj = 0;
  mod->x11_client_sck_closed = 1;
  mod->pipefd = 0;

  mod->x11_chanid = mod->server_get_channel_id(mod, "rdpx11");
  if (mod->x11_chanid >= 0)
  {
      char init_data[4] = { RDPX11_OPEN_REQUEST, 0, 0, 0 };

      mod->server_msg(mod, "rdpx11 channel is present", 0);
      mod->server_send_to_channel(mod, mod->x11_chanid, init_data, 4);
      mod->server_set_login_mode(mod, 4);
  }
  else
  {
      mod->server_msg(mod, "rdpx11 channel is not present", 0);
      error = lib_mod_connect_rdp(mod);
  }

  LIB_DEBUG(mod, "out lib_mod_connect");
  return error;
}

/******************************************************************************/
/* return error */
static int DEFAULT_CC
lib_mod_rdpx11_channel_send(struct mod* mod)
{
    char stack_buf[RDPX11_CHANNEL_RBUF];
    char *buf = stack_buf;
    int  buf_avail;
    int  size = sizeof (stack_buf);
    int  buf_offset = 0;
    int  len;
    int  rv = 0;

    do
    {
	buf_avail = size - buf_offset;

#ifndef _WIN32
	len = read (mod->x11_client_sck, buf + buf_offset, buf_avail);
	if (len == -1)
	{
	    if (errno == EINTR || errno == EAGAIN ||
		errno == EWOULDBLOCK)
	    {
		len = 0;
	    }
	    else
	    {
		rv = 1;
		break;
	    }
	}
#else	
	len = g_tcp_recv(mod->x11_client_sck, buf + buf_offset, buf_avail, 0);
	if (len == -1)
	{
	    if (g_tcp_last_error_would_block(mod->x11_client_sck))
	    {
		len = 0;
	    }
	    else
	    {
		rv = 1;
		break;
	    }
	}
#endif

	else if (len == 0)
	{
	    /* wait for error message from pipe */
	    if (mod->pipefd)
	    {
		g_delete_wait_obj_from_socket(mod->x11_client_sck_obj);
		mod->x11_client_sck_obj = 0;
	    }
	    else
	    {
		rv = 1;
		break;
	    }
	}

	buf_avail -= len;
	
	if (mod->deflate_level)
	{
	    char out_buf[RDPX11_CHANNEL_RBUF];
	    int  out_len;
	    int  status;

	    if (buf_avail == 0)
	    {
		char *data;

#ifndef _WIN32
		if (buf != stack_buf)
		{
		    data = realloc(buf, size * 2);
		}
		else
#endif

		{
		    data = g_malloc(size * 2, 0);
		    if (data && buf == stack_buf)
			g_memcpy(data, buf, size);
		}

		if (data)
		{
		    buf_offset += len;
		    buf = data;
		    size *= 2;
		    continue;
		}
	    }

	    mod->outgoing_stream.next_in  = buf;
	    mod->outgoing_stream.avail_in = size - buf_avail;

	    do {
		mod->outgoing_stream.next_out  = out_buf;
		mod->outgoing_stream.avail_out = sizeof(out_buf);

		status = deflate(&mod->outgoing_stream, Z_SYNC_FLUSH);
		switch (status) {
		case Z_OK:
		    out_len = sizeof(out_buf) - mod->outgoing_stream.avail_out;
		    if (out_len)
			mod->server_send_to_channel(mod,
						    mod->x11_chanid,
						    out_buf,
						    out_len);
		    break;
		default:
		    g_writeln("[dmx] deflate returned %d", status);
		}
	    } while (mod->outgoing_stream.avail_out == 0);
	}
	else if (len)
	{
	    mod->server_send_to_channel(mod, mod->x11_chanid, buf, len);
	}	    
    } while (buf_avail == 0);

    if (buf != stack_buf)
	g_free (buf);

    return rv;
}

static int APP_CC
lib_mod_force_write(int socket, char *buf, int size)
{
    int total = 0;
    int sent;

    while (total < size)
    {

#ifndef _WIN32
	sent = write(socket, buf + total, size - total);
	if (sent == -1)
	{
	    if (errno == EINTR || errno == EAGAIN ||
		errno == EWOULDBLOCK)
	    {
		fd_set         rfds;
		struct timeval time;

		time.tv_sec = 0;
		time.tv_usec = 10000;

		FD_ZERO(&rfds);
		FD_SET(socket, &rfds);

		select(socket + 1, &rfds, 0, 0, &time);
	    }
	    else
	    {
		return -1;
	    }
	}
#else	
	sent = g_tcp_send(socket, buf + total, size - total, 0);
	if (sent == -1)
	{
	    if (g_tcp_last_error_would_block(socket))
		g_tcp_can_send(socket, 10);
	    else
		return -1;
	}
#endif

	else if (sent == 0)
	{
	    return 0;
	}
	else
	{
	    total = total + sent;
	}
    }

    return total;
}

#ifndef _WIN32
/* return error */
static int DEFAULT_CC
lib_mod_process_pipe_data(struct mod* mod)
{
    char msg[257];
    int  len;
    int  n = 0;

    msg[256] = '\0';

    do
    {
	len = read (mod->pipefd, &msg[n++], 1);
	if (len == -1)
	{
	    return 1;
	}
	else if (len == 0)
	{
	    close(mod->pipefd);
	    mod->pipefd = 0;
	    mod->server_set_login_mode(mod, 10);
	    return 0;
	}
	msg[n - 1] = tolower (msg[n - 1]);
    } while (n < 256);

    switch (msg[0]) {
    case 0: /* connection error */
	mod->server_msg(mod, &msg[1], 0);
	close(mod->pipefd);
	mod->pipefd = 0;
	mod->server_msg(mod, "rdpx11 connection failed", 0);
	if (lib_mod_connect_rdp(mod) == 0)
	    mod->server_set_login_mode(mod, 10);
	else
	    mod->server_set_login_mode(mod, 11);
	break;
    case 1: /* connection established */
	mod->server_msg(mod, "rdpx11 connection established", 0);
	break;
    case 2: /* connection message */
	mod->server_msg(mod, &msg[1], 0);
	break;
    }

    return 0;
}
#endif

static void
send_error_response(void *addr)
{
    char data[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    int  sck;
    
#ifndef _WIN32
    sck = socket(AF_UNIX, SOCK_STREAM, 0);
    if (connect(sck, (struct sockaddr *) addr, sizeof(struct sockaddr_un)) == 0)
	write (sck, data, sizeof (data));
    close(sck);
#else
    const char *host = "127.0.0.1";

    sck = g_tcp_socket();
    if (g_tcp_connect(sck, host, (const char *) addr) == 0)
	g_tcp_send (sck, data, sizeof (data), 0);
    close (sck);
#endif
}

/* return error */
static int DEFAULT_CC
lib_process_channel_data(struct mod* mod, int chanid, int size, struct stream* s)
{
  if (chanid == mod->x11_chanid)
  {
      if (mod->x11_output)
      {
	  if (mod->x11_client_sck)
	  {
	      int rv = 0;

	      if (mod->inflate_level)
	      {
		  char buf[RDPX11_CHANNEL_RBUF];
		  int  status;
		  int  len;

		  mod->incoming_stream.next_in  = s->p;
		  mod->incoming_stream.avail_in = size;

		  do
		  {
		      mod->incoming_stream.next_out  = buf;
		      mod->incoming_stream.avail_out = sizeof(buf);

		      status = inflate(&mod->incoming_stream, Z_SYNC_FLUSH);
		      switch (status) {
		      case Z_OK:
			  len = sizeof(buf) - mod->incoming_stream.avail_out;
			  rv = lib_mod_force_write (mod->x11_client_sck, buf,
						    len);
			  break;
		      case Z_BUF_ERROR:
			  break;
		      default:
			  g_writeln("[dmx] inflate returned %d", status);
		      }
		  } while (rv && status == Z_OK);
	      }
	      else
	      {
		  rv = lib_mod_force_write (mod->x11_client_sck, s->p, size);
	      }

	      if (rv == 0)
	      {
		  /* wait for error message from pipe */
		  if (mod->pipefd)
		  {
		      g_delete_wait_obj_from_socket(mod->x11_client_sck_obj);
		      mod->x11_client_sck_obj = 0;
		  }
		  else
		  {
		      return 1;
		  }
	      }
	  }
      }
      else
      {
	  struct xrdp_wm*    wm = (struct xrdp_wm *) mod->wm;
	  char               name[512];
	  char               screen[256];
	  char               *proto;
	  char               *data;
	  int		     proto_len;
	  int		     data_len;
	  int                type;
	  int                pid;
	  int                sck;
	  int                error;
	  int                len;

#ifndef _WIN32
	  struct sockaddr_un local, remote;
	  int                flag;
	  int                gid;
	  int                uid;
	  int                pipefd[2];

	  g_sprintf(screen, ":%d.0", mod->display);
#else
	  char               con_port[256];
    
	  g_sprintf(screen, "localhost:%d.0", mod->display);
#endif
	  g_sprintf(name, "%s@%s", mod->username, mod->hostname);

	  in_uint32_le(s, type);

	  switch (type) {
	  case RDPX11_OPEN_CONFIRMATION:
	      in_uint32_le(s, mod->x11_output);
	      in_uint16_le(s, mod->deflate_level);
	      in_uint16_le(s, mod->inflate_level);
	      in_uint32_le(s, proto_len);
	      in_uint32_le(s, data_len);
	      in_uint8p(s, proto, proto_len);
	      in_uint8p(s, data, data_len);

	      if (mod->deflate_level)
		  deflateInit (&mod->outgoing_stream, mod->deflate_level);

	      if (mod->inflate_level)
		  inflateInit (&mod->incoming_stream);

#ifndef _WIN32
	      sck = socket(AF_UNIX, SOCK_STREAM, 0);

	      local.sun_family = AF_UNIX;
	      g_snprintf(local.sun_path, sizeof local.sun_path, _PATH_UNIX_X,
			 mod->display);
	      len = strlen(local.sun_path) + sizeof(local.sun_family);
	      unlink(local.sun_path);

	      error = bind(sck, (struct sockaddr *) &local, len);
	      if (error != 0)
	      {
		  close(sck);
		  g_writeln("[dmx] bind() error: %d", error);
		  return 1;
	      }

	      if (g_getuser_info (mod->username, &gid, &uid, 0, 0, 0) == 0)
		  chown (local.sun_path, uid, gid);

	      error = listen(sck, 1);
	      if (error != 0)
	      {
		  close(sck);
		  unlink(local.sun_path);
		  g_writeln("[dmx] listen() error: %d", error);
		  return 1;
	      }

	      if (pipe(pipefd) == -1)
	      {
		  close(sck);
		  unlink(local.sun_path);
		  g_writeln("[dmx] pipe() error: %d", error);
		  return 1;
	      }
#else
	      g_sprintf(con_port, "%d", 6000 + mod->display);
  
	      sck = g_tcp_socket();
	      error = g_tcp_bind(sck, con_port);
	      if (error != 0)
	      {
		  g_tcp_close(sck);
		  g_writeln("[dmx] bind() error: %d", error);
		  return 1;
	      }
	      error = g_tcp_listen(sck);
	      if (error != 0)
	      {
		  g_tcp_close(sck);
		  g_writeln("[dmx] listen() error: %d", error);
		  return 1;
	      }
#endif

	      pid = g_fork();
	      if (pid == -1)
	      {
	      }
	      else if (pid == 0)
	      {
		  DBusConnection *c;
		  DBusError      err;
		  char           msg[256];

		  g_memset (msg, 0, sizeof (msg));

#ifndef _WIN32
		  close(pipefd[0]);
#endif
    
		  dbus_error_init (&err);

		  c = dbus_bus_get_private (DBUS_BUS_SYSTEM, &err);
		  if (dbus_error_is_set (&err))
		  {
#ifndef _WIN32
		      msg[0] = 0; /* connection error */
		      g_snprintf (&msg[1], sizeof (msg) - 1, "error - %s",
				  err.message);
		      write (pipefd[1], msg, sizeof (msg));
		      close (pipefd[1]);
		      send_error_response(&local);
#else
		      send_error_response(con_port);
#endif
		      dbus_error_free (&err);
		      exit (1);
		  }

		  if (dmx_connect (c,
				   screen,
				   name,
				   proto,
				   proto_len,
				   data,
				   data_len,
				   atoi (mod->port) - 6000,
				   mod->x11_output,
				   &err))
		  {
#ifndef _WIN32
		      msg[0] = 0; /* connection error */
		      g_snprintf (&msg[1], sizeof (msg) - 1, "error - %s",
				  err.message);
		      write (pipefd[1], msg, sizeof (msg));
		      close (pipefd[1]);
		      send_error_response(&local);
#else
		      send_error_response(con_port);
#endif
		      dbus_error_free (&err);
		      dbus_connection_close (c);
		      exit (1);
		  }

#ifndef _WIN32
		  msg[0] = 1; /* connection established */
		  write (pipefd[1], msg, sizeof (msg));

		  close(pipefd[1]); /* connection ready */
#endif
		  dbus_connection_close (c);
		  exit (1);
	      }
	      else
	      {
		  int  x11_client_sck;
                  char buf[1024];

#ifndef _WIN32
		  close(pipefd[1]);
		  mod->pipefd = pipefd[0];

                  len = sizeof(remote);
		  x11_client_sck = accept(sck, (struct sockaddr *) &remote, &len);
		  len = read(x11_client_sck, buf, sizeof (buf));
		  close(sck);
		  unlink(local.sun_path);

		  if (len < 0 || buf[0] == 0)
                  {
		      close(x11_client_sck);
		      lib_mod_process_pipe_data(mod);
		      mod->server_set_login_mode(mod, 11);
                      return 0;
                  }

		  if ((flag = fcntl(x11_client_sck, F_GETFL)) != -1)
		      fcntl(x11_client_sck, F_SETFL, flag | O_NONBLOCK);
#else
		  x11_client_sck = g_tcp_accept(sck);
		  len = g_tcp_recv(x11_client_sck, buf, sizeof (buf), 0);
		  g_tcp_close(sck);

		  if (len < 0 || buf[0] == 0)
                  {
		      g_tcp_close(x11_client_sck);
		      mod->server_msg(mod, "error - rdpx11 connection failed", 0);
		      mod->server_set_login_mode(mod, 11);
                      return 0;
                  }

		  g_tcp_set_non_blocking(x11_client_sck);
		  g_tcp_set_no_delay(x11_client_sck);

		  mod->server_set_login_mode(mod, 10);
#endif

		  if (mod->deflate_level)
		  {
		      char out_buf[RDPX11_CHANNEL_RBUF];
		      int  out_len;
		      int  status;

		      mod->outgoing_stream.next_in  = buf;
		      mod->outgoing_stream.avail_in = len;

		      do {
			  mod->outgoing_stream.next_out  = out_buf;
			  mod->outgoing_stream.avail_out = sizeof(out_buf);

			  status = deflate(&mod->outgoing_stream,
					   Z_SYNC_FLUSH);
			  switch (status) {
			  case Z_OK:
			      out_len = sizeof(out_buf) -
				  mod->outgoing_stream.avail_out;
			      if (out_len)
				  mod->server_send_to_channel(mod,
							      mod->x11_chanid,
							      out_buf,
							      out_len);
			      break;
			  default:
			      g_writeln("[dmx] deflate returned %d", status);
			  }
		      } while (mod->outgoing_stream.avail_out == 0);
		  }
		  else
		  {
		      mod->server_send_to_channel(mod,
						  mod->x11_chanid,
						  buf,
						  len);
		  }	    

		  mod->server_msg(mod, "rdpx11 connection initiated", 0);

		  mod->x11_client_sck = x11_client_sck;
		  mod->x11_client_sck_obj =
		      g_create_wait_obj_from_socket(mod->x11_client_sck, 0);
	      }
	      break;
	  case RDPX11_OPEN_FAILURE:
	      in_uint8s(s, 16);
	      mod->server_msg(mod, "error - rdpx11 open request failed", 0);
	      mod->server_set_login_mode(mod, 11);
	      break;
	  }
      }
  }

  return 0;
}

/* return error */
int DEFAULT_CC
lib_mod_event(struct mod* mod, int msg, tbus param1, tbus param2,
              tbus param3, tbus param4)
{
  struct stream* s;
  int len;
  int rv;
  int size;
  int chanid;
  char* data;

  LIB_DEBUG(mod, "in lib_mod_event");
  make_stream(s);
  if (msg == 0x5555) /* channel data */
  {
    chanid = (int)param1;
    size = (int)param2;
    data = (char*)param3;
    if ((size >= 0) && (size <= (32 * 1024)) && (data != 0))
    {
      init_stream(s, size);
      out_uint8a(s, data, size);
      s_mark_end(s);
      s->p = s->data;
      rv = lib_process_channel_data(mod, chanid, size, s);
    }
    else
    {
      rv = 1;
    }
  }
  else
  {
    init_stream(s, 8192);
    s_push_layer(s, iso_hdr, 4);
    out_uint16_le(s, 103);
    out_uint32_le(s, msg);
    out_uint32_le(s, param1);
    out_uint32_le(s, param2);
    out_uint32_le(s, param3);
    out_uint32_le(s, param4);
    s_mark_end(s);
    len = (int)(s->end - s->data);
    s_pop_layer(s, iso_hdr);
    out_uint32_le(s, len);
    rv = lib_send(mod, s->data, len);
  }
  free_stream(s);
  LIB_DEBUG(mod, "out lib_mod_event");
  return rv;
}

/******************************************************************************/
/* return error */
int DEFAULT_CC
lib_mod_signal(struct mod* mod)
{
  struct stream* s;
  int num_orders;
  int index;
  int rv;
  int len;
  int type;
  int x;
  int y;
  int cx;
  int cy;
  int fgcolor;
  int opcode;
  int width;
  int height;
  int srcx;
  int srcy;
  int len_bmpdata;
  int style;
  int x1;
  int y1;
  int x2;
  int y2;
  char* bmpdata;
  char cur_data[32 * (32 * 3)];
  char cur_mask[32 * (32 / 8)];

  LIB_DEBUG(mod, "in lib_mod_signal");
  make_stream(s);
  init_stream(s, 8192);
  rv = lib_recv(mod, s->data, 8);
  if (rv == 0)
  {
    in_uint16_le(s, type);
    in_uint16_le(s, num_orders);
    in_uint32_le(s, len);
    if (type == 1)
    {
      init_stream(s, len);
      rv = lib_recv(mod, s->data, len);
      if (rv == 0)
      {
        for (index = 0; index < num_orders; index++)
        {
          in_uint16_le(s, type);
          switch (type)
          {
            case 1: /* server_begin_update */
              rv = mod->server_begin_update(mod);
              break;
            case 2: /* server_end_update */
              rv = mod->server_end_update(mod);
              break;
            case 3: /* server_fill_rect */
              in_sint16_le(s, x);
              in_sint16_le(s, y);
              in_uint16_le(s, cx);
              in_uint16_le(s, cy);
              rv = mod->server_fill_rect(mod, x, y, cx, cy);
              break;
            case 4: /* server_screen_blt */
              in_sint16_le(s, x);
              in_sint16_le(s, y);
              in_uint16_le(s, cx);
              in_uint16_le(s, cy);
              in_sint16_le(s, srcx);
              in_sint16_le(s, srcy);
              rv = mod->server_screen_blt(mod, x, y, cx, cy, srcx, srcy);
              break;
            case 5: /* server_paint_rect */
              in_sint16_le(s, x);
              in_sint16_le(s, y);
              in_uint16_le(s, cx);
              in_uint16_le(s, cy);
              in_uint32_le(s, len_bmpdata);
              in_uint8p(s, bmpdata, len_bmpdata);
              in_uint16_le(s, width);
              in_uint16_le(s, height);
              in_sint16_le(s, srcx);
              in_sint16_le(s, srcy);
              rv = mod->server_paint_rect(mod, x, y, cx, cy,
                                          bmpdata, width, height,
                                          srcx, srcy);
              break;
            case 10: /* server_set_clip */
              in_sint16_le(s, x);
              in_sint16_le(s, y);
              in_uint16_le(s, cx);
              in_uint16_le(s, cy);
              rv = mod->server_set_clip(mod, x, y, cx, cy);
              break;
            case 11: /* server_reset_clip */
              rv = mod->server_reset_clip(mod);
              break;
            case 12: /* server_set_fgcolor */
              in_uint32_le(s, fgcolor);
              rv = mod->server_set_fgcolor(mod, fgcolor);
              break;
            case 14:
              in_uint16_le(s, opcode);
              rv = mod->server_set_opcode(mod, opcode);
              break;
            case 17:
              in_uint16_le(s, style);
              in_uint16_le(s, width);
              rv = mod->server_set_pen(mod, style, width);
              break;
            case 18:
              in_sint16_le(s, x1);
              in_sint16_le(s, y1);
              in_sint16_le(s, x2);
              in_sint16_le(s, y2);
              rv = mod->server_draw_line(mod, x1, y1, x2, y2);
              break;
            case 19:
              in_sint16_le(s, x);
              in_sint16_le(s, y);
              in_uint8a(s, cur_data, 32 * (32 * 3));
              in_uint8a(s, cur_mask, 32 * (32 / 8));
              rv = mod->server_set_cursor(mod, x, y, cur_data, cur_mask);
              break;
            default:
              rv = 1;
              break;
          }
          if (rv != 0)
          {
            break;
          }
        }
      }
    }
  }
  free_stream(s);
  LIB_DEBUG(mod, "out lib_mod_signal");
  return rv;
}

/******************************************************************************/
/* return error */
int DEFAULT_CC
lib_mod_end(struct mod* mod)
{
  return 0;
}

/******************************************************************************/
/* return error */
int DEFAULT_CC
lib_mod_set_param(struct mod* mod, char* name, char* value)
{
  if (g_strcasecmp(name, "username") == 0)
  {
    g_strncpy(mod->username, value, 255);
  }
  else if (g_strcasecmp(name, "password") == 0)
  {
    g_strncpy(mod->password, value, 255);
  }
  else if (g_strcasecmp(name, "ip") == 0)
  {
    g_strncpy(mod->ip, value, 255);
  }
  else if (g_strcasecmp(name, "port") == 0)
  {
    g_strncpy(mod->port, value, 255);
  }
  else if (g_strcasecmp(name, "hostname") == 0)
  {
    g_strncpy(mod->hostname, value, 255);
  }
  return 0;
}

/******************************************************************************/
/* return error */
int DEFAULT_CC
lib_mod_get_wait_objs(struct mod* mod, tbus* read_objs, int* rcount,
                      tbus* write_objs, int* wcount, int* timeout)
{
  int i;

  i = *rcount;
  if (mod != 0)
  {
    if (mod->sck_obj != 0)
    {
      read_objs[i++] = mod->sck_obj;
    }
    if (mod->x11_client_sck_obj != 0)
    {
      read_objs[i++] = mod->x11_client_sck_obj;
    }
    if (mod->pipefd != 0)
    {
      read_objs[i++] = mod->pipefd;
    }
  }
  *rcount = i;
  return 0;
}

/******************************************************************************/
/* return error */
int DEFAULT_CC
lib_mod_check_wait_objs(struct mod* mod)
{
  int rv;

  rv = 0;
  if (mod != 0)
  {
    if (mod->sck_obj != 0)
    {
      if (g_is_wait_obj_set(mod->sck_obj))
      {
        rv = lib_mod_signal(mod);
      }
    }
    if (mod->x11_client_sck_obj != 0)
    {
      if (g_is_wait_obj_set(mod->x11_client_sck_obj))
      {
	rv = lib_mod_rdpx11_channel_send(mod);
      }
    }
#ifndef _WIN32
    if (mod->pipefd != 0)
    {
      fd_set         rfds;
      struct timeval time = { 0, 0 };

      FD_ZERO(&rfds);
      FD_SET(mod->pipefd, &rfds);

      rv = select(mod->pipefd + 1, &rfds, 0, 0, &time);
      if (rv < 0)
	  return 1;

      if (rv > 0)
	rv = lib_mod_process_pipe_data(mod);

      FD_ZERO(&rfds);
    }
#endif
  }
  return rv;
}

/******************************************************************************/
struct mod* EXPORT_CC
mod_init(void)
{
  struct mod* mod;

  mod = (struct mod*)g_malloc(sizeof(struct mod), 1);
  mod->size = sizeof(struct mod);
  mod->handle = (tbus)mod;
  mod->mod_connect = lib_mod_connect;
  mod->mod_start = lib_mod_start;
  mod->mod_event = lib_mod_event;
  mod->mod_signal = lib_mod_signal;
  mod->mod_end = lib_mod_end;
  mod->mod_set_param = lib_mod_set_param;
  mod->mod_get_wait_objs = lib_mod_get_wait_objs;
  mod->mod_check_wait_objs = lib_mod_check_wait_objs;
  mod->deflate_level = 0;
  mod->inflate_level = 0;

  return mod;
}

/******************************************************************************/
int EXPORT_CC
mod_exit(struct mod* mod)
{
  if (mod == 0)
  {
    return 0;
  }
#ifndef _WIN32
  if (mod->pipefd != 0)
      close (mod->pipefd);
#endif
  if (mod->deflate_level)
      deflateEnd (&mod->outgoing_stream);
  if (mod->inflate_level)
      inflateEnd (&mod->incoming_stream);
  if (mod->x11_client_sck_obj != 0)
      g_delete_wait_obj_from_socket(mod->x11_client_sck_obj);
  if (mod->x11_client_sck != 0)
#ifndef _WIN32
      close(mod->x11_client_sck);
#else
      g_tcp_close(mod->x11_client_sck);
#endif
  if (mod->sck_obj != 0)
      g_delete_wait_obj_from_socket(mod->sck_obj);
  if (mod->sck != 0)
      g_tcp_close(mod->sck);
  if (mod->xpid > 0)
    g_sigterm(mod->xpid);
  g_free(mod);
  return 0;
}
