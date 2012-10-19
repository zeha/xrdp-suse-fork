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
 * @file session.c
 * @brief Session management code
 * @author Jay Sorg, Simone Fedele
 *
 */

#include "sesman.h"
#include "libscp_types.h"

#include <errno.h>
#include <stdio.h>
#ifndef _WIN32
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <X11/Xauth.h>
#include <xcb/xcb.h>
#endif
#include <dbus/dbus.h>

extern unsigned char g_fixedkey[8];
extern struct config_sesman* g_cfg; /* config.h */
struct session_chain* g_sessions = NULL;
int g_session_count = 0;

static int xbeDisplayOffset = 256;
/* max to 256 sessions */
static int available_displays [256];

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

static void
init_available_display ()
{
  int i;
  for (i = 0; i < g_cfg->sess.max_sessions; i++)
  {
    if (!x_server_running (i + 10))
      available_displays [i] = 1;
    else
      available_displays [i] = 0;
  }
}

static void
set_available_display (int display, int available)
{
  available_displays [display - 10] = available;
}

static int
get_available_display ()
{
  int i;
  static int initialized = 0;
  if (!initialized)
  {
    init_available_display();
    initialized = 1;
  }
  for (i = 0; !available_displays [i]; i++) {
  }
  return 10 + i;
}

/******************************************************************************/
struct session_item* DEFAULT_CC
session_get_bydata(char* name, int width, int height, int bpp)
{
  struct session_chain* tmp;

  /*THREAD-FIX require chain lock */
  lock_chain_acquire();

  tmp = g_sessions;

  while (tmp != 0)
  {
    if (g_strncmp(name, tmp->item->name, 255) == 0)
    {
      if (tmp->item->type == SESMAN_SESSION_TYPE_XDMX)
      {
	/*THREAD-FIX release chain lock */
        lock_chain_release();
        return tmp->item;
      }

      if (tmp->item->bpp == bpp &&
	  tmp->item->width == width &&
	  tmp->item->height == height)
      {
        /*THREAD-FIX release chain lock */
        lock_chain_release();
        return tmp->item;
      }
    }
    tmp = tmp->next;
  }

  /*THREAD-FIX release chain lock */
  lock_chain_release();
  return 0;
}

/******************************************************************************/
static void DEFAULT_CC
session_start_sessvc(int xpid, int wmpid, long data)
{
  struct list* sessvc_params;
  char wmpid_str[25];
  char xpid_str[25];
  char exe_path[262];
  int i;

  /* new style waiting for clients */
  g_sprintf(wmpid_str, "%d", wmpid);
  g_sprintf(xpid_str, "%d",  xpid);
  log_message(&(g_cfg->log), LOG_LEVEL_INFO,
              "starting xrdp-sessvc - xpid=%s - wmpid=%s",
              xpid_str, wmpid_str);

  sessvc_params = list_create();
  sessvc_params->auto_free = 1;

  /* building parameters */
  g_snprintf(exe_path, 261, "%s/xrdp-sessvc", XRDP_SBIN_PATH);

  list_add_item(sessvc_params, (long)g_strdup(exe_path));
  list_add_item(sessvc_params, (long)g_strdup(xpid_str));
  list_add_item(sessvc_params, (long)g_strdup(wmpid_str));
  list_add_item(sessvc_params, 0); /* mandatory */

  /* executing sessvc */
  g_execvp(exe_path, ((char**)sessvc_params->items));

  /* should not get here */
  log_message(&(g_cfg->log), LOG_LEVEL_ALWAYS,
              "error starting xrdp-sessvc - pid %d - xpid=%s - wmpid=%s",
              g_getpid(), xpid_str, wmpid_str);

  /* logging parameters */
  /* no problem calling strerror for thread safety: other threads
     are blocked */
  log_message(&(g_cfg->log), LOG_LEVEL_DEBUG, "errno: %d, description: %s",
              errno, g_get_strerror());
  log_message(&(g_cfg->log), LOG_LEVEL_DEBUG, "execve parameter list:");
  for (i = 0; i < (sessvc_params->count); i++)
  {
    log_message(&(g_cfg->log), LOG_LEVEL_DEBUG, "        argv[%d] = %s", i,
                (char*)list_get_item(sessvc_params, i));
  }
  list_delete(sessvc_params);

  /* keep the old waitpid if some error occurs during execlp */
  g_waitpid(wmpid);
  g_sigterm(xpid);
  g_sigterm(wmpid);
  g_sleep(1000);
  auth_end(data);
  g_exit(0);
}

/******************************************************************************/
static dbus_bool_t
add_param_basic (DBusMessageIter *iter_array,
                 const char      *name,
                 int              type,
                 const void      *value)
{
    DBusMessageIter iter_struct;
    DBusMessageIter iter_variant;
    const char     *container_type;

    switch (type) {
    case DBUS_TYPE_STRING:
	container_type = DBUS_TYPE_STRING_AS_STRING;
	break;
    case DBUS_TYPE_BOOLEAN:
	container_type = DBUS_TYPE_BOOLEAN_AS_STRING;
	break;
    case DBUS_TYPE_INT32:
	container_type = DBUS_TYPE_INT32_AS_STRING;
	break;
    default:
	goto oom;
	break;
    }

    if (! dbus_message_iter_open_container (iter_array,
					    DBUS_TYPE_STRUCT,
					    NULL,
					    &iter_struct)) {
	goto oom;
    }

    if (! dbus_message_iter_append_basic (&iter_struct,
					  DBUS_TYPE_STRING,
					  &name)) {
	goto oom;
    }

    if (! dbus_message_iter_open_container (&iter_struct,
					    DBUS_TYPE_VARIANT,
					    container_type,
					    &iter_variant)) {
	goto oom;
    }

    if (! dbus_message_iter_append_basic (&iter_variant,
					  type,
					  value)) {
	goto oom;
    }

    if (! dbus_message_iter_close_container (&iter_struct,
					     &iter_variant)) {
	goto oom;
    }

    if (! dbus_message_iter_close_container (iter_array,
					     &iter_struct)) {
	goto oom;
    }

    return TRUE;
oom:
    return FALSE;
}

static char *
session_ck_open_session (DBusConnection *connection,
			 const char     *username,
			 int            display)
{
    DBusError       error;
    DBusMessage     *message;
    DBusMessage     *reply;
    DBusMessageIter iter;
    DBusMessageIter iter_array;
    dbus_bool_t     res;
    char            *ret;
    char            *cookie;
    dbus_bool_t     is_local = FALSE;
    dbus_bool_t     active = TRUE;
    int             uid;
    char            display_str[256];
    const char      *x11_display = display_str;
    const char      *session_type = "rdp";

    reply = NULL;
    message = NULL;
    ret = NULL;

    g_sprintf(display_str, ":%d", display);

    if (g_getuser_info(username, 0, &uid, 0, 0, 0))
	goto out;

    message =
	dbus_message_new_method_call ("org.freedesktop.ConsoleKit",
				      "/org/freedesktop/ConsoleKit/Manager",
				      "org.freedesktop.ConsoleKit.Manager",
				      "OpenSessionWithParameters");
    if (message == NULL) {
	goto out;
    }

    dbus_message_iter_init_append (message, &iter);
    if (! dbus_message_iter_open_container (&iter,
					    DBUS_TYPE_ARRAY,
					    "(sv)",
					    &iter_array)) {
	goto out;
    }

    if (!add_param_basic (&iter_array,
			  "unix-user",
			  DBUS_TYPE_INT32,
			  &uid) ||
	!add_param_basic (&iter_array,
			  "x11-display",
			  DBUS_TYPE_STRING,
			  &x11_display) ||
	!add_param_basic (&iter_array,
			  "is-local",
			  DBUS_TYPE_BOOLEAN,
			  &is_local) ||
	!add_param_basic (&iter_array,
			  "active",
			  DBUS_TYPE_BOOLEAN,
			  &active) ||
	!add_param_basic (&iter_array,
			  "session-type",
			  DBUS_TYPE_STRING,
			  &session_type)) {
	log_message(&(g_cfg->log), LOG_LEVEL_ALWAYS,
		    "Error adding ck session parameter");
	goto out;
    }

    if (! dbus_message_iter_close_container (&iter, &iter_array)) {
	goto out;
    }

    dbus_error_init (&error);
    reply = dbus_connection_send_with_reply_and_block (connection,
						       message,
						       -1,
						       &error);
    if (reply == NULL) {
	if (dbus_error_is_set (&error)) {
	    log_message(&(g_cfg->log), LOG_LEVEL_ALWAYS,
			"Unable to open session: %s",
			error.message);
	    dbus_error_free (&error);
	    goto out;
	}
    }

    dbus_error_init (&error);
    if (! dbus_message_get_args (reply,
				 &error,
				 DBUS_TYPE_STRING, &cookie,
				 DBUS_TYPE_INVALID)) {
	if (dbus_error_is_set (&error)) {
	    log_message(&(g_cfg->log), LOG_LEVEL_ALWAYS,
			"Unable to open session: %s",
			error.message);
	    dbus_error_free (&error);
	    goto out;
	}
    }

    ret = g_strdup (cookie);

out:
    if (reply != NULL) {
	dbus_message_unref (reply);
    }

    if (message != NULL) {
	dbus_message_unref (message);
    }

    return ret;
}

static void
session_ck_close_session (DBusConnection *connection,
			  char           *cookie)
{
    DBusError   error;
    DBusMessage *message;
    DBusMessage *reply;

    reply = NULL;
    message = NULL;

    if (cookie == NULL) {
	goto out;
    }

    message =
	dbus_message_new_method_call ("org.freedesktop.ConsoleKit",
				      "/org/freedesktop/ConsoleKit/Manager",
				      "org.freedesktop.ConsoleKit.Manager",
				      "CloseSession");
    if (message == NULL) {
	goto out;
    }

    if (! dbus_message_append_args (message,
				    DBUS_TYPE_STRING, &cookie,
				    DBUS_TYPE_INVALID)) {
	goto out;
    }

    dbus_error_init (&error);
    reply = dbus_connection_send_with_reply_and_block (connection,
						       message,
						       -1,
						       &error);
    if (reply == NULL) {
	if (dbus_error_is_set (&error)) {
	    g_printf("\n[sessvc] Unable to close session: %s",
		     error.message);
	    dbus_error_free (&error);
	    goto out;
	}
    }

out:
    if (reply != NULL) {
	dbus_message_unref (reply);
    }

    if (message != NULL) {
	dbus_message_unref (message);
    }
}

/******************************************************************************/
#ifndef _WIN32
static int     received_usr1;
static jmp_buf jumpbuf;

static void
sig_usr1_waiting (int sig)
{
    signal (sig, sig_usr1_waiting);
    received_usr1++;
}

static void
sig_usr1_jump (int sig)
{
    sigset_t set;

    signal (sig, sig_usr1_waiting);

    sigemptyset (&set);
    sigaddset (&set, SIGUSR1);
    sigprocmask (SIG_UNBLOCK, &set, NULL);

    longjmp (jumpbuf, 1);
}

#define AUTH_DATA_LEN 16 /* bytes of authorization data */

static int
session_setup_auth (char* display,
		    char* auth_data,
		    int   auth_fd)
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
	return 1;

    bytes = 0;
    do {
	size = read (random_fd, auth_data + bytes, AUTH_DATA_LEN - bytes);
	if (size <= 0)
	    break;

	bytes += size;
    } while (bytes != AUTH_DATA_LEN);

    close (random_fd);

    if (bytes != AUTH_DATA_LEN)
	return 1;

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

/******************************************************************************/
int DEFAULT_CC
session_start(int width, int height, int bpp, int layout,
	      char* username, char* password,
              char* wm, long data, unsigned char type)
{
  int display;
  int pid;
  int xkbpid;
  int wmpid;
  int xpid;
  int i;
  char geometry[32];
  char depth[32];
  char screen[32];
  char text[256];
  char passwd_file[256];
  char** pp1;
  struct session_chain* temp;
  struct list* xserver_params=0;
  time_t ltime;
  struct tm stime;
  char *ck_cookie;
  DBusConnection *connection;
  DBusError error;
  int pipefd[2];

  /*THREAD-FIX lock to control g_session_count*/
  lock_chain_acquire();
  /* check to limit concurrent sessions */
  if (g_session_count >= g_cfg->sess.max_sessions)
  {
    /*THREAD-FIX unlock chain*/
    lock_chain_release();
    log_message(&(g_cfg->log), LOG_LEVEL_INFO, "max concurrent session limit exceeded. login \
for user %s denied", username);
    return 0;
  }

  display = get_available_display ();
  g_sprintf(geometry, "%dx%d", width, height);
  g_sprintf(depth, "%d", bpp);
  g_sprintf(screen, ":%d", display);

  /*THREAD-FIX unlock chain*/
  lock_chain_release();

  temp = (struct session_chain*)g_malloc(sizeof(struct session_chain), 0);
  if (temp == 0)
  {
    log_message(&(g_cfg->log), LOG_LEVEL_ERROR, "cannot create new chain element - user %s",
                username);
    return 0;
  }
  temp->item = (struct session_item*)g_malloc(sizeof(struct session_item), 0);
  if (temp->item == 0)
  {
    g_free(temp);
    log_message(&(g_cfg->log), LOG_LEVEL_ERROR, "cannot create new session item - user %s",
                username);
    return 0;
  }

  dbus_error_init (&error);
  connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
  if (connection == NULL) {
      if (dbus_error_is_set (&error)) {
	  log_message(&(g_cfg->log), LOG_LEVEL_INFO, "dbus_bus_get: %s",
		      error.message);
	  dbus_error_free (&error);
      }
      g_free(temp->item);
      g_free(temp);
      return 0;
  }

  dbus_connection_set_exit_on_disconnect (connection, FALSE);

#ifndef _WIN32
  if (pipe(pipefd) == -1)
  {
      log_message(&(g_cfg->log), LOG_LEVEL_INFO, "pipe failed");
      g_free(temp->item);
      g_free(temp);
      return 0;
  }
#endif

  /* block all the threads running to enable forking */
  scp_lock_fork_request();

  ck_cookie = session_ck_open_session (connection, username, display);

#ifndef _WIN32
  char       auth_file[256];
  const char *auth_templ = "/tmp/.xrdp-auth-XXXXXX";
  char       auth_data[AUTH_DATA_LEN];
  int        auth_fd;
  int        mask;

  strcpy (auth_file, auth_templ);
  mask = umask (0077);
  auth_fd = mkstemp (auth_file);
  umask (mask);

  if (auth_fd == -1)
  {
    log_message(&(g_cfg->log), LOG_LEVEL_ALWAYS,
          "error - generating unique authorization file");
    g_exit(1);
  }

  if (session_setup_auth (screen + 1, auth_data, auth_fd))
  {
      g_exit(1);
  }
#endif

  pid = g_fork();
  if (pid == -1)
  {
  }
  else if (pid == 0) /* child sesman */
  {
#ifndef _WIN32
    close(pipefd[0]);
#endif

    g_unset_signals();
    auth_start_session(data, display);

    if (env_set_user(username, passwd_file, display, auth_file) != 0)
    {
      log_message(&(g_cfg->log), LOG_LEVEL_ALWAYS, "error - set user failed");
      g_exit(1);
    }

    env_check_password_file(passwd_file, password);

#ifndef _WIN32
    g_signal (SIGUSR1, sig_usr1_waiting);
#endif

    xpid = g_fork();
    if (xpid == -1)
    {
    }
    else if (xpid == 0) /* child (child sesman) xserver */
    {

#ifndef _WIN32
      close(pipefd[1]);
      g_signal (SIGUSR1, SIG_IGN);
#endif

      if (type == SESMAN_SESSION_TYPE_XVNC)
      {
        xserver_params = list_create();
	xserver_params->auto_free = 1;
	/* these are the must have parameters */
	list_add_item(xserver_params, (long)g_strdup("Xvnc"));
	list_add_item(xserver_params, (long)g_strdup(screen));
	list_add_item(xserver_params, (long)g_strdup("-geometry"));
	list_add_item(xserver_params, (long)g_strdup(geometry));
	list_add_item(xserver_params, (long)g_strdup("-depth"));
	list_add_item(xserver_params, (long)g_strdup(depth));
	list_add_item(xserver_params, (long)g_strdup("-rfbauth"));
	list_add_item(xserver_params, (long)g_strdup(passwd_file));

#ifndef _WIN32
	list_add_item(xserver_params, (long)g_strdup("-auth"));
	list_add_item(xserver_params, (long)g_strdup(auth_file));
#endif


	/* additional parameters from sesman.ini file */
	//config_read_xserver_params(SESMAN_SESSION_TYPE_XVNC,
	//                           xserver_params);
	list_append_list_strdup(g_cfg->vnc_params, xserver_params, 0);

	/* make sure it ends with a zero */
	list_add_item(xserver_params, 0);
	pp1 = (char**)xserver_params->items;
	g_execvp("Xvnc", pp1);
      }
      else if (type == SESMAN_SESSION_TYPE_XRDP)
      {
	  xserver_params = list_create();
          xserver_params->auto_free = 1;
          /* these are the must have parameters */
          list_add_item(xserver_params, (long)g_strdup("X11rdp"));
          list_add_item(xserver_params, (long)g_strdup(screen));
          list_add_item(xserver_params, (long)g_strdup("-geometry"));
          list_add_item(xserver_params, (long)g_strdup(geometry));
          list_add_item(xserver_params, (long)g_strdup("-depth"));
          list_add_item(xserver_params, (long)g_strdup(depth));

#ifndef _WIN32
	  list_add_item(xserver_params, (long)g_strdup("-auth"));
	  list_add_item(xserver_params, (long)g_strdup(auth_file));
#endif

          /* additional parameters from sesman.ini file */
          //config_read_xserver_params(SESMAN_SESSION_TYPE_XRDP,
          //                           xserver_params);
	  list_append_list_strdup(g_cfg->rdp_params, xserver_params, 0);

          /* make sure it ends with a zero */
          list_add_item(xserver_params, 0);
          pp1 = (char**)xserver_params->items;
	  g_execvp("X11rdp", pp1);
      }
      else if (type == SESMAN_SESSION_TYPE_XDMX)
      {
	  xserver_params = list_create();
          xserver_params->auto_free = 1;
          /* these are the must have parameters */
          list_add_item(xserver_params, (long)g_strdup("Xdmx"));
          list_add_item(xserver_params, (long)g_strdup(screen));
	  list_add_item(xserver_params, (long)g_strdup("-depth"));
	  list_add_item(xserver_params, (long)g_strdup(depth));

#ifndef _WIN32
	  list_add_item(xserver_params, (long)g_strdup("-auth"));
	  list_add_item(xserver_params, (long)g_strdup(auth_file));
#endif

          /* additional parameters from sesman.ini file */
          list_append_list_strdup(g_cfg->dmx_params, xserver_params, 0);

          list_add_item(xserver_params, (long)g_strdup("--"));
          list_add_item(xserver_params, (long)g_strdup(g_cfg->dmx_backend));

          /* additional parameters from sesman.ini file */
          list_append_list_strdup(g_cfg->dmx_backend_params, xserver_params, 0);
          if (strstr (g_cfg->dmx_backend, "Xfake")) /* if the backend was Xfake, use the '-screen' param */
          {
            char geometry_depth [32];
            char xfake_display[32];
            int  xbe_display;

            xbe_display = display + xbeDisplayOffset;
            while (xbe_display <= xbeDisplayOffset * 2)
            {
              if (!x_server_running (xbe_display))
                break;
              xbe_display++;
            }

            if (xbe_display > xbeDisplayOffset * 2)
            {
              log_message(&(g_cfg->log), LOG_LEVEL_ALWAYS, "error - no available display offset");
              g_exit(1);
            }

            g_sprintf(xfake_display, ":%d", xbe_display);
            g_sprintf(geometry_depth, "%dx%dx%d", width, height, bpp);
            list_add_item(xserver_params, (long)g_strdup(xfake_display));
            list_add_item(xserver_params, (long)g_strdup("-screen"));
            list_add_item(xserver_params, (long)g_strdup(geometry_depth));  
          }

	  /* make sure it ends with a zero */
	  list_add_item(xserver_params, 0);
          pp1 = (char**)xserver_params->items;
          g_execvp("Xdmx", pp1);
      }
      else
      {
	log_message(&(g_cfg->log), LOG_LEVEL_ALWAYS, "bad session type - user %s - pid %d",
		    username, g_getpid());
	g_exit(1);
      }

      /* should not get here */
      log_message(&(g_cfg->log), LOG_LEVEL_ALWAYS, "error starting X server - user %s - pid %d",
		  username, g_getpid());

      /* logging parameters */
      /* no problem calling strerror for thread safety: other threads are blocked */
      log_message(&(g_cfg->log), LOG_LEVEL_DEBUG, "errno: %d, description: %s", errno, g_get_strerror());
      log_message(&(g_cfg->log), LOG_LEVEL_DEBUG, "execve parameter list: %d", (xserver_params)->count);

      for (i=0; i<(xserver_params->count); i++)
      {
	log_message(&(g_cfg->log), LOG_LEVEL_DEBUG, "        argv[%d] = %s", i, (char*)list_get_item(xserver_params, i));
      }
      list_delete(xserver_params);
      g_exit(1);
    }
    else /* parent (child sesman) */
    {

#ifdef _WIN32
      g_sleep (5000);
#else
      xcb_connection_t *c;

      received_usr1 = 0;

      for (;;)
      {
	g_signal (SIGUSR1, sig_usr1_waiting);
	if (setjmp (jumpbuf))
	  break;

	g_signal (SIGUSR1, sig_usr1_jump);
	if (received_usr1)
	  break;

	if (g_waitpid (xpid) != -1)
	{
	  log_message(&(g_cfg->log), LOG_LEVEL_ALWAYS,
		      "error X server died - user %s - pid %d",
		      username, xpid);
	  g_exit(1);
	}
      }

      c = xcb_connect (screen, NULL);
      if (!c || xcb_connection_has_error (c))
      {
          log_message(&(g_cfg->log), LOG_LEVEL_ALWAYS,
                      "error X server connection failed - user %s - pid %d",
                      username, xpid);
          g_exit(1);
      }
#endif

      log_message(&(g_cfg->log), LOG_LEVEL_ALWAYS,
		  "X server running - user %s - pid %d",
		  username, xpid);

      g_unset_signals();

      wmpid = g_fork();
      if (wmpid == -1)
      {
      }
      else if (wmpid == 0) /* child */
      {

#ifndef _WIN32
	close(pipefd[1]);
#endif

	if (ck_cookie)
	  g_setenv("XDG_SESSION_COOKIE", ck_cookie, 1);

	auth_set_env(data);

	/* for XDMX sessions, we adjust screen size using xrandr once
	   the X server is up */
	if (type == SESMAN_SESSION_TYPE_XDMX)
	{
	    if (g_fork() == 0)
	    {
		struct list* xrandr_params=0;

		xrandr_params = list_create();
		xrandr_params->auto_free = 1;
		list_add_item(xrandr_params, (long)g_strdup("xrandr"));
		list_add_item(xrandr_params, (long)g_strdup("--fb"));
		list_add_item(xrandr_params, (long)g_strdup(geometry));

		/* make sure it ends with a zero */
		list_add_item(xrandr_params, 0);
		pp1 = (char**)xrandr_params->items;
		g_execvp("xrandr", pp1);

		/* should not get here */
		log_message(&(g_cfg->log), LOG_LEVEL_ALWAYS,
			    "error running xrandr - user %s",
			    username);

		/* logging parameters */
		log_message(&(g_cfg->log), LOG_LEVEL_DEBUG,
			    "errno: %d, description: %s",
			    errno, g_get_strerror());
		log_message(&(g_cfg->log), LOG_LEVEL_DEBUG,
			    "execve parameter list: %d",
			    (xrandr_params)->count);

		for (i=0; i<(xrandr_params->count); i++)
		{
		    log_message(&(g_cfg->log), LOG_LEVEL_DEBUG,
				"        argv[%d] = %s", i,
				(char*)list_get_item(xrandr_params, i));
		}
		list_delete(xrandr_params);
		g_exit(1);
	    }
	}

	/* set XKB map */
        xkbpid = g_fork();
	if (xkbpid == 0)
	{
	    struct list* setxkbmap_params=0;

	    setxkbmap_params = list_create();
	    setxkbmap_params->auto_free = 1;
	    list_add_item(setxkbmap_params, (long)g_strdup("setxkbmap"));
	    switch (layout)
	    {
	    case 0x40c: /* france */
		list_add_item(setxkbmap_params, (long)g_strdup("fr"));
		break;
	    case 0x809: /* en-uk or en-gb */
		list_add_item(setxkbmap_params, (long)g_strdup("gb"));
		break;
	    case 0x407: /* german */
		list_add_item(setxkbmap_params, (long)g_strdup("de"));
		break;
	    case 0x416: /* Portuguese (Brazil) */
		list_add_item(setxkbmap_params, (long)g_strdup("pt"));
		break;
	    case 0x410: /* italy */
		list_add_item(setxkbmap_params, (long)g_strdup("it"));
		break;
	    case 0x41d: /* swedish */
		list_add_item(setxkbmap_params, (long)g_strdup("se"));
		break;
	    case 0x405: /* czech */
		list_add_item(setxkbmap_params, (long)g_strdup("cz"));
		break;
	    case 0x419: /* russian */
		list_add_item(setxkbmap_params, (long)g_strdup("ru"));
		break;
	    default: /* default 0x409 us en */
		list_add_item(setxkbmap_params, (long)g_strdup("us"));
		break;
	    }

            log_message(&(g_cfg->log), LOG_LEVEL_ALWAYS,
                        "using keyboard layout: 0x%x (%s)",
                        layout,
                        list_get_item(setxkbmap_params, 1));

	    /* make sure it ends with a zero */
	    list_add_item(setxkbmap_params, 0);
	    pp1 = (char**)setxkbmap_params->items;
	    g_execvp("setxkbmap", pp1);

	    /* should not get here */
	    log_message(&(g_cfg->log), LOG_LEVEL_ALWAYS,
			"error running setxkbmap - user %s",
			username);

	    /* logging parameters */
	    log_message(&(g_cfg->log), LOG_LEVEL_DEBUG,
			"errno: %d, description: %s",
			errno, g_get_strerror());
	    log_message(&(g_cfg->log), LOG_LEVEL_DEBUG,
			"execve parameter list: %d",
			(setxkbmap_params)->count);

	    for (i=0; i<(setxkbmap_params->count); i++)
	    {
		log_message(&(g_cfg->log), LOG_LEVEL_DEBUG,
			    "        argv[%d] = %s", i,
			    (char*)list_get_item(setxkbmap_params, i));
	    }
	    list_delete(setxkbmap_params);
	    g_exit(1);
	}

        g_waitpid(xkbpid);

	/* try to execute session window manager */
	if (*wm != '\0')
	  g_execlp3("/etc/X11/xdm/Xsession", "Xsession", wm);

          /* try to execute user window manager if enabled */
	if (g_cfg->enable_user_wm)
	{
          g_sprintf(text,"%s/%s", g_getenv("HOME"), g_cfg->user_wm);
	  if (g_file_exist(text))
	  {
            g_execlp3(text, g_cfg->user_wm, 0);
	    log_message(&(g_cfg->log), LOG_LEVEL_ALWAYS,"error starting user wm for user %s - pid %d",
			username, g_getpid());
	    /* logging parameters */
	    /* no problem calling strerror for thread safety: other threads are blocked */
	    log_message(&(g_cfg->log), LOG_LEVEL_DEBUG, "errno: %d, description: %s", errno,
			g_get_strerror());
	    log_message(&(g_cfg->log), LOG_LEVEL_DEBUG,"execlp3 parameter list:");
	    log_message(&(g_cfg->log), LOG_LEVEL_DEBUG, "        argv[0] = %s", text);
	    log_message(&(g_cfg->log), LOG_LEVEL_DEBUG, "        argv[1] = %s", g_cfg->user_wm);
	  }
	}
        /* if we're here something happened to g_execlp3
	   so we try running the default window manager */
	g_sprintf(text, "%s/%s", XRDP_CFG_PATH, g_cfg->default_wm);
	g_execlp3(text, g_cfg->default_wm, 0);

	log_message(&(g_cfg->log), LOG_LEVEL_ALWAYS,"error starting default wm for user %s - pid %d",
                    username, g_getpid());
	/* logging parameters */
	/* no problem calling strerror for thread safety: other threads are blocked */
	log_message(&(g_cfg->log), LOG_LEVEL_DEBUG, "errno: %d, description: %s", errno,
		    g_get_strerror());
	log_message(&(g_cfg->log), LOG_LEVEL_DEBUG,"execlp3 parameter list:");
	log_message(&(g_cfg->log), LOG_LEVEL_DEBUG, "        argv[0] = %s", text);
	log_message(&(g_cfg->log), LOG_LEVEL_DEBUG, "        argv[1] = %s", g_cfg->default_wm);

	/* still a problem starting window manager just start xterm */
	g_execlp3("xterm", "xterm", 0);

	/* should not get here */
	log_message(&(g_cfg->log), LOG_LEVEL_ALWAYS,"error starting xterm for user %s - pid %d",
		    username, g_getpid());
	/* logging parameters */
	/* no problem calling strerror for thread safety: other threads are blocked */
	log_message(&(g_cfg->log), LOG_LEVEL_DEBUG, "errno: %d, description: %s", errno, g_get_strerror());
      }
      else /* parent (child sesman) */
      {

#ifndef _WIN32
	char status = 1;

	write(pipefd[1], &status, 1);
	close(pipefd[1]);

        fcntl (xcb_get_file_descriptor (c), F_SETFD, 0);
#endif
	/* new style waiting for clients */
	session_start_sessvc(xpid, wmpid, data);
      }
    }
  }
  else /* parent sesman process */
  {
    char status = 0;
    int  len;
    /* let the other threads go on */
    scp_lock_fork_release();

#ifdef _WIN32
    /* wait for X server to start */
    g_sleep (5000);
    status = 1;
#else
    close(pipefd[1]);

    do {
	len = read(pipefd[0], &status, 1);
    } while (len == -1);

    close(pipefd[0]);
  
#endif

    if (status == 0)
    {
        unlink(auth_file);
	g_free(temp->item);
	g_free(temp);
	return 0;
    }

    temp->item->pid = pid;
    temp->item->display = display;
    temp->item->width = width;
    temp->item->height = height;
    temp->item->bpp = bpp;
    temp->item->data = data;
    temp->item->ck_cookie = ck_cookie;
    g_strncpy(temp->item->name, username, 255);
    g_strncpy(temp->item->auth_file, auth_file, 255);

    ltime = g_time1();
    gmtime_r(&ltime, &stime);
    temp->item->connect_time.year = (tui16)stime.tm_year;
    temp->item->connect_time.month = (tui8)stime.tm_mon;
    temp->item->connect_time.day = (tui8)stime.tm_mday;
    temp->item->connect_time.hour = (tui8)stime.tm_hour;
    temp->item->connect_time.minute = (tui8)stime.tm_min;
    zero_time(&(temp->item->disconnect_time));
    zero_time(&(temp->item->idle_time));

    temp->item->type=type;
    temp->item->status=SESMAN_SESSION_STATUS_ACTIVE;

    /*THREAD-FIX lock the chain*/
    lock_chain_acquire();
    temp->next=g_sessions;
    g_sessions=temp;
    set_available_display (display, 0);
    g_session_count++;
    /*THERAD-FIX free the chain*/
    lock_chain_release();
  }
  return display;
}

/*
SESMAN_SESSION_TYPE_XRDP  1
SESMAN_SESSION_TYPE_XVNC  2

SESMAN_SESSION_STATUS_ACTIVE        1
SESMAN_SESSION_STATUS_IDLE          2
SESMAN_SESSION_STATUS_DISCONNECTED  3

struct session_item
{
  char name[256];
  int pid;
  int display;
  int width;
  int height;
  int bpp;
  long data;

  / *
  unsigned char status;
  unsigned char type;
  * /

  / *
  time_t connect_time;
  time_t disconnect_time;
  time_t idle_time;
  * /
};

struct session_chain
{
  struct session_chain* next;
  struct session_item* item;
};

*/

/******************************************************************************/
int DEFAULT_CC
session_kill(int pid)
{
  struct session_chain* tmp;
  struct session_chain* prev;

  /*THREAD-FIX require chain lock */
  lock_chain_acquire();

  tmp=g_sessions;
  prev=0;

  while (tmp != 0)
  {
    if (tmp->item == 0)
    {
      log_message(&(g_cfg->log), LOG_LEVEL_ERROR, "session descriptor for pid %d is null!",
                  pid);
      if (prev == 0)
      {
        /* prev does no exist, so it's the first element - so we set
           g_sessions */
        g_sessions = tmp->next;
      }
      else
      {
        prev->next = tmp->next;
      }
      /*THREAD-FIX release chain lock */
      lock_chain_release();
      return SESMAN_SESSION_KILL_NULLITEM;
    }

    if (tmp->item->pid == pid)
    {
      unlink(tmp->item->auth_file);
      /* deleting the session */
      log_message(&(g_cfg->log), LOG_LEVEL_INFO, "session %d - user %s - terminated",
                  tmp->item->pid, tmp->item->name);
      if (tmp->item->ck_cookie)
      {
	  session_ck_close_session (dbus_bus_get(DBUS_BUS_SYSTEM, 0),
				    tmp->item->ck_cookie);
	g_free(tmp->item->ck_cookie);
      }
      g_free(tmp->item);
      if (prev == 0)
      {
        /* prev does no exist, so it's the first element - so we set
           g_sessions */
        g_sessions = tmp->next;
      }
      else
      {
        prev->next = tmp->next;
      }
      g_free(tmp);
      set_available_display (tmp->item->display, 1);
      g_session_count--;
      /*THREAD-FIX release chain lock */
      lock_chain_release();
      return SESMAN_SESSION_KILL_OK;
    }

    /* go on */
    prev = tmp;
    tmp=tmp->next;
  }

  /*THREAD-FIX release chain lock */
  lock_chain_release();
  return SESMAN_SESSION_KILL_NOTFOUND;
}

/******************************************************************************/
void DEFAULT_CC
session_sigkill_all()
{
  struct session_chain* tmp;

  /*THREAD-FIX require chain lock */
  lock_chain_acquire();

  tmp=g_sessions;

  while (tmp != 0)
  {
    if (tmp->item == 0)
    {
      log_message(&(g_cfg->log), LOG_LEVEL_ERROR, "found null session descriptor!");
    }
    else
    {
      unlink(tmp->item->auth_file);
      g_sigterm(tmp->item->pid);
    }

    /* go on */
    tmp=tmp->next;
  }

  /*THREAD-FIX release chain lock */
  lock_chain_release();
}

/******************************************************************************/
struct session_item* DEFAULT_CC
session_get_bypid(int pid)
{
  struct session_chain* tmp;

  /*THREAD-FIX require chain lock */
  lock_chain_acquire();

  tmp = g_sessions;
  while (tmp != 0)
  {
    if (tmp->item == 0)
    {
      log_message(&(g_cfg->log), LOG_LEVEL_ERROR, "session descriptor for pid %d is null!",
                  pid);
      /*THREAD-FIX release chain lock */
      lock_chain_release();
      return 0;
    }

    if (tmp->item->pid == pid)
    {
      /*THREAD-FIX release chain lock */
      lock_chain_release();
      return tmp->item;
    }

    /* go on */
    tmp=tmp->next;
  }

  /*THREAD-FIX release chain lock */
  lock_chain_release();
  return 0;
}

/******************************************************************************/
struct SCP_DISCONNECTED_SESSION*
session_get_byuser(char* user, int* cnt)
{
  struct session_chain* tmp;
  struct SCP_DISCONNECTED_SESSION* sess;
  int count;
  int index;

  count=0;

  /*THREAD-FIX require chain lock */
  lock_chain_acquire();

  tmp = g_sessions;
  while (tmp != 0)
  {
#warning FIXME: we should get only disconnected sessions!
    if (!g_strncasecmp(user, tmp->item->name, 256))
    {
      count++;
    }

    /* go on */
    tmp=tmp->next;
  }

  if (count==0)
  {
    (*cnt)=0;
    /*THREAD-FIX release chain lock */
    lock_chain_release();
    return 0;
  }

  /* malloc() an array of disconnected sessions */
  sess=g_malloc(count * sizeof(struct SCP_DISCONNECTED_SESSION),1);
  if (sess==0)
  {
    (*cnt)=0;
    /*THREAD-FIX release chain lock */
    lock_chain_release();
    return 0;
  }

  tmp = g_sessions;
  index = 0;
  while (tmp != 0)
  {
#warning FIXME: we should get only disconnected sessions!
    if (!g_strncasecmp(user, tmp->item->name, 256))
    {
      (sess[index]).SID=tmp->item->pid;
      (sess[index]).type=tmp->item->type;
      (sess[index]).height=tmp->item->height;
      (sess[index]).width=tmp->item->width;
      (sess[index]).bpp=tmp->item->bpp;
#warning FIXME: setting idle times and such
      /*(sess[index]).connect_time.year = tmp->item->connect_time.year;
      (sess[index]).connect_time.month = tmp->item->connect_time.month;
      (sess[index]).connect_time.day = tmp->item->connect_time.day;
      (sess[index]).connect_time.hour = tmp->item->connect_time.hour;
      (sess[index]).connect_time.minute = tmp->item->connect_time.minute;
      (sess[index]).disconnect_time.year = tmp->item->disconnect_time.year;
      (sess[index]).disconnect_time.month = tmp->item->disconnect_time.month;
      (sess[index]).disconnect_time.day = tmp->item->disconnect_time.day;
      (sess[index]).disconnect_time.hour = tmp->item->disconnect_time.hour;
      (sess[index]).disconnect_time.minute = tmp->item->disconnect_time.minute;
      (sess[index]).idle_time.year = tmp->item->idle_time.year;
      (sess[index]).idle_time.month = tmp->item->idle_time.month;
      (sess[index]).idle_time.day = tmp->item->idle_time.day;
      (sess[index]).idle_time.hour = tmp->item->idle_time.hour;
      (sess[index]).idle_time.minute = tmp->item->idle_time.minute;*/
      (sess[index]).conn_year = tmp->item->connect_time.year;
      (sess[index]).conn_month = tmp->item->connect_time.month;
      (sess[index]).conn_day = tmp->item->connect_time.day;
      (sess[index]).conn_hour = tmp->item->connect_time.hour;
      (sess[index]).conn_minute = tmp->item->connect_time.minute;
      (sess[index]).idle_days = tmp->item->idle_time.day;
      (sess[index]).idle_hours = tmp->item->idle_time.hour;
      (sess[index]).idle_minutes = tmp->item->idle_time.minute;

      index++;
    }

    /* go on */
    tmp=tmp->next;
  }

  /*THREAD-FIX release chain lock */
  lock_chain_release();
  (*cnt)=count;
  return sess;
}

