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

   main program

*/

#if defined(_WIN32)
#include <windows.h>
#endif
#include "xrdp.h"

static struct xrdp_listen* g_listen = 0;
static long g_threadid = 0; /* main threadid */

#if defined(_WIN32)
static SERVICE_STATUS_HANDLE g_ssh = 0;
static SERVICE_STATUS g_service_status;
#endif
static long g_sync_mutex = 0;
static long g_sync1_mutex = 0;
static tbus g_term_event = 0;
static tbus g_sync_event = 0;
/* syncronize stuff */
static int g_sync_command = 0;
static long g_sync_result = 0;
static long g_sync_param1 = 0;
static long g_sync_param2 = 0;
static long (*g_sync_func)(long param1, long param2);

/*****************************************************************************/
long APP_CC
g_xrdp_sync(long (*sync_func)(long param1, long param2), long sync_param1,
            long sync_param2)
{
  long sync_result;
  int sync_command;

  if (tc_threadid_equal(tc_get_threadid(), g_threadid))
  {
    /* this is the main thread, call the function directly */
    sync_result = sync_func(sync_param1, sync_param2);
  }
  else
  {
    tc_mutex_lock(g_sync1_mutex);
    tc_mutex_lock(g_sync_mutex);
    g_sync_param1 = sync_param1;
    g_sync_param2 = sync_param2;
    g_sync_func = sync_func;
    g_sync_command = 100;
    tc_mutex_unlock(g_sync_mutex);
    g_set_wait_obj(g_sync_event);
    do
    {
      g_sleep(100);
      tc_mutex_lock(g_sync_mutex);
      sync_command = g_sync_command;
      sync_result = g_sync_result;
      tc_mutex_unlock(g_sync_mutex);
    }
    while (sync_command != 0);
    tc_mutex_unlock(g_sync1_mutex);
  }
  return sync_result;
}

/*****************************************************************************/
void DEFAULT_CC
xrdp_shutdown(int sig)
{
  tbus threadid;

  threadid = tc_get_threadid();
  g_writeln("shutting down");
  g_writeln("signal %d threadid %p", sig, threadid);
  if (!g_is_wait_obj_set(g_term_event))
  {
    g_set_wait_obj(g_term_event);
  }
}

/*****************************************************************************/
int APP_CC
g_is_term(void)
{
  return g_is_wait_obj_set(g_term_event);
}

/*****************************************************************************/
void APP_CC
g_set_term(int in_val)
{
  if (in_val)
  {
    g_set_wait_obj(g_term_event);
  }
  else
  {
    g_reset_wait_obj(g_term_event);
  }
}

/*****************************************************************************/
tbus APP_CC
g_get_term_event(void)
{
  return g_term_event;
}

/*****************************************************************************/
tbus APP_CC
g_get_sync_event(void)
{
  return g_sync_event;
}

/*****************************************************************************/
void DEFAULT_CC
pipe_sig(int sig_num)
{
  /* do nothing */
  g_writeln("got SIGPIPE(%d)", sig_num);
}

/*****************************************************************************/
void APP_CC
g_loop(void)
{
  tc_mutex_lock(g_sync_mutex);
  if (g_sync_command != 0)
  {
    if (g_sync_func != 0)
    {
      if (g_sync_command == 100)
      {
        g_sync_result = g_sync_func(g_sync_param1, g_sync_param2);
      }
    }
    g_sync_command = 0;
  }
  tc_mutex_unlock(g_sync_mutex);
}

/* win32 service control functions */
#if defined(_WIN32)

/*****************************************************************************/
VOID WINAPI
MyHandler(DWORD fdwControl)
{
  if (g_ssh == 0)
  {
    return;
  }
  if (fdwControl == SERVICE_CONTROL_STOP)
  {
    g_service_status.dwCurrentState = SERVICE_STOP_PENDING;
    g_set_term(1);
  }
  else if (fdwControl == SERVICE_CONTROL_PAUSE)
  {
    /* shouldn't happen */
  }
  else if (fdwControl == SERVICE_CONTROL_CONTINUE)
  {
    /* shouldn't happen */
  }
  else if (fdwControl == SERVICE_CONTROL_INTERROGATE)
  {
  }
  else if (fdwControl == SERVICE_CONTROL_SHUTDOWN)
  {
    g_service_status.dwCurrentState = SERVICE_STOP_PENDING;
    g_set_term(1);
  }
  SetServiceStatus(g_ssh, &g_service_status);
}

/*****************************************************************************/
static void DEFAULT_CC
log_event(HANDLE han, char* msg)
{
  ReportEvent(han, EVENTLOG_INFORMATION_TYPE, 0, 0, 0, 1, 0, &msg, 0);
}

/*****************************************************************************/
VOID WINAPI
MyServiceMain(DWORD dwArgc, LPTSTR* lpszArgv)
{
  WSADATA w;
  //HANDLE event_han;
//  int fd;
//  char text[256];

//  fd = g_file_open("c:\\temp\\xrdp\\log.txt");
//  g_file_write(fd, "hi\r\n", 4);
  //event_han = RegisterEventSource(0, "xrdp");
  //log_event(event_han, "hi xrdp log");
  g_threadid = tc_get_threadid();
  g_set_current_dir("c:\\temp\\xrdp");
  g_listen = 0;
  WSAStartup(2, &w);
  g_sync_mutex = tc_mutex_create();
  g_sync1_mutex = tc_mutex_create();
  g_term_event = g_create_wait_obj("xrdp_main_term");
  g_sync_event = g_create_wait_obj("xrdp_main_sync");
  g_memset(&g_service_status, 0, sizeof(SERVICE_STATUS));
  g_service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  g_service_status.dwCurrentState = SERVICE_RUNNING;
  g_service_status.dwControlsAccepted = SERVICE_CONTROL_INTERROGATE |
                                        SERVICE_ACCEPT_STOP |
                                        SERVICE_ACCEPT_SHUTDOWN;
  g_service_status.dwWin32ExitCode = NO_ERROR;
  g_service_status.dwServiceSpecificExitCode = 0;
  g_service_status.dwCheckPoint = 0;
  g_service_status.dwWaitHint = 0;
//  g_sprintf(text, "calling RegisterServiceCtrlHandler\r\n");
//  g_file_write(fd, text, g_strlen(text));
  g_ssh = RegisterServiceCtrlHandler("xrdp", MyHandler);
  if (g_ssh != 0)
  {
//    g_sprintf(text, "ok\r\n");
//    g_file_write(fd, text, g_strlen(text));
    SetServiceStatus(g_ssh, &g_service_status);
    g_listen = xrdp_listen_create();
    xrdp_listen_main_loop(g_listen);
    g_sleep(100);
    g_service_status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_ssh, &g_service_status);
  }
  else
  {
    //g_sprintf(text, "RegisterServiceCtrlHandler failed\r\n");
    //g_file_write(fd, text, g_strlen(text));
  }
  xrdp_listen_delete(g_listen);
  tc_mutex_delete(g_sync_mutex);
  tc_mutex_delete(g_sync1_mutex);
  g_destroy_wait_obj(g_term_event);
  g_destroy_wait_obj(g_sync_event);
  WSACleanup();
  //CloseHandle(event_han);
}

#endif
/*****************************************************************************/
int DEFAULT_CC
main(int argc, char** argv)
{
  int test;
  int host_be;
#if defined(_WIN32)
  WSADATA w;
  SC_HANDLE sc_man;
  SC_HANDLE sc_ser;
  int run_as_service;
  SERVICE_TABLE_ENTRY te[2];
#else
  int pid;
  int fd;
  int no_daemon;
  char text[32];
#endif

  g_init();
  /* check compiled endian with actual endian */
  test = 1;
  host_be = !((int)(*(unsigned char*)(&test)));
#if defined(B_ENDIAN)
  if (!host_be)
#endif
#if defined(L_ENDIAN)
  if (host_be)
#endif
  {
    g_writeln("endian wrong, edit arch.h");
    return 0;
  }
  /* check long, int and void* sizes */
  if (sizeof(int) != 4)
  {
    g_writeln("unusable int size, must be 4");
    return 0;
  }
  if (sizeof(long) != sizeof(void*))
  {
    g_writeln("long size must match void* size");
    return 0;
  }
  if (sizeof(long) != 4 && sizeof(long) != 8)
  {
    g_writeln("unusable long size, must be 4 or 8");
    return 0;
  }
#if defined(_WIN32)
  run_as_service = 1;
  if (argc == 2)
  {
    if (g_strncasecmp(argv[1], "-help", 255) == 0 ||
        g_strncasecmp(argv[1], "--help", 255) == 0 ||
        g_strncasecmp(argv[1], "-h", 255) == 0)
    {
      g_writeln("");
      g_writeln("xrdp: A Remote Desktop Protocol server.");
      g_writeln("Copyright (C) Jay Sorg 2004-2008");
      g_writeln("See http://xrdp.sourceforge.net for more information.");
      g_writeln("");
      g_writeln("Usage: xrdp [options]");
      g_writeln("   -h: show help");
      g_writeln("   -install: install service");
      g_writeln("   -remove: remove service");
      g_writeln("");
      g_exit(0);
    }
    else if (g_strncasecmp(argv[1], "-install", 255) == 0 ||
             g_strncasecmp(argv[1], "--install", 255) == 0 ||
             g_strncasecmp(argv[1], "-i", 255) == 0)
    {
      /* open service manager */
      sc_man = OpenSCManager(0, 0, GENERIC_WRITE);
      if (sc_man == 0)
      {
        g_writeln("error OpenSCManager, do you have rights?");
        g_exit(0);
      }
      /* check if service is allready installed */
      sc_ser = OpenService(sc_man, "xrdp", SERVICE_ALL_ACCESS);
      if (sc_ser == 0)
      {
        /* install service */
        CreateService(sc_man, "xrdp", "xrdp", SERVICE_ALL_ACCESS,
                      SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
                      SERVICE_ERROR_IGNORE, "c:\\temp\\xrdp\\xrdp.exe",
                      0, 0, 0, 0, 0);

      }
      else
      {
        g_writeln("error service is allready installed");
        CloseServiceHandle(sc_ser);
        CloseServiceHandle(sc_man);
        g_exit(0);
      }
      CloseServiceHandle(sc_man);
      g_exit(0);
    }
    else if (g_strncasecmp(argv[1], "-remove", 255) == 0 ||
             g_strncasecmp(argv[1], "--remove", 255) == 0 ||
             g_strncasecmp(argv[1], "-r", 255) == 0)
    {
      /* open service manager */
      sc_man = OpenSCManager(0, 0, GENERIC_WRITE);
      if (sc_man == 0)
      {
        g_writeln("error OpenSCManager, do you have rights?");
        g_exit(0);
      }
      /* check if service is allready installed */
      sc_ser = OpenService(sc_man, "xrdp", SERVICE_ALL_ACCESS);
      if (sc_ser == 0)
      {
        g_writeln("error service is not installed");
        CloseServiceHandle(sc_man);
        g_exit(0);
      }
      DeleteService(sc_ser);
      CloseServiceHandle(sc_man);
      g_exit(0);
    }
    else
    {
      g_writeln("Unknown Parameter");
      g_writeln("xrdp -h for help");
      g_writeln("");
      g_exit(0);
    }
  }
  else if (argc > 1)
  {
    g_writeln("Unknown Parameter");
    g_writeln("xrdp -h for help");
    g_writeln("");
    g_exit(0);
  }
  if (run_as_service)
  {
    g_memset(&te, 0, sizeof(te));
    te[0].lpServiceName = "xrdp";
    te[0].lpServiceProc = MyServiceMain;
    StartServiceCtrlDispatcher(&te);
    g_exit(0);
  }
  WSAStartup(2, &w);
#else /* _WIN32 */
  no_daemon = 0;
  if (argc == 2)
  {
    if ((g_strncasecmp(argv[1], "-kill", 255) == 0) ||
        (g_strncasecmp(argv[1], "--kill", 255) == 0) ||
        (g_strncasecmp(argv[1], "-k", 255) == 0))
    {
      g_writeln("stopping xrdp");
      /* read the xrdp.pid file */
      fd = -1;
      if (g_file_exist(XRDP_PID_FILE)) /* xrdp.pid */
      {
        fd = g_file_open(XRDP_PID_FILE); /* xrdp.pid */
      }
      if (fd == -1)
      {
        g_writeln("problem opening to xrdp.pid");
        g_writeln("maybe its not running");
      }
      else
      {
        g_memset(text, 0, 32);
        g_file_read(fd, text, 31);
        pid = g_atoi(text);
        g_writeln("stopping process id %d", pid);
        if (pid > 0)
        {
          g_sigterm(pid);
        }
        g_file_close(fd);
      }
      g_exit(0);
    }
    else if (g_strncasecmp(argv[1], "-nodaemon", 255) == 0 ||
             g_strncasecmp(argv[1], "--nodaemon", 255) == 0 ||
             g_strncasecmp(argv[1], "-nd", 255) == 0 ||
             g_strncasecmp(argv[1], "--nd", 255) == 0 ||
             g_strncasecmp(argv[1], "-ns", 255) == 0 ||
             g_strncasecmp(argv[1], "--ns", 255) == 0)
    {
      no_daemon = 1;
    }
    else if (g_strncasecmp(argv[1], "-help", 255) == 0 ||
             g_strncasecmp(argv[1], "--help", 255) == 0 ||
             g_strncasecmp(argv[1], "-h", 255) == 0)
    {
      g_writeln("");
      g_writeln("xrdp: A Remote Desktop Protocol server.");
      g_writeln("Copyright (C) Jay Sorg 2004-2008");
      g_writeln("See http://xrdp.sourceforge.net for more information.");
      g_writeln("");
      g_writeln("Usage: xrdp [options]");
      g_writeln("   -h: show help");
      g_writeln("   -nodaemon: don't fork into background");
      g_writeln("   -kill: shut down xrdp");
      g_writeln("");
      g_exit(0);
    }
    else if ((g_strncasecmp(argv[1], "-v", 255) == 0) ||
             (g_strncasecmp(argv[1], "--version", 255) == 0))
    {
      g_writeln("");
      g_writeln("xrdp: A Remote Desktop Protocol server.");
      g_writeln("Copyright (C) Jay Sorg 2004-2008");
      g_writeln("See http://xrdp.sourceforge.net for more information.");
      g_writeln("Version 0.5.0");
      g_writeln("");
      g_exit(0);
    }
    else
    {
      g_writeln("Unknown Parameter");
      g_writeln("xrdp -h for help");
      g_writeln("");
      g_exit(0);
    }
  }
  else if (argc > 1)
  {
    g_writeln("Unknown Parameter");
    g_writeln("xrdp -h for help");
    g_writeln("");
    g_exit(0);
  }
  if (g_file_exist(XRDP_PID_FILE)) /* xrdp.pid */
  {
    g_writeln("It looks like xrdp is allready running,");
    g_writeln("if not delete the xrdp.pid file and try again");
    g_exit(0);
  }
  if (!no_daemon)
  {
    /* make sure we can write to pid file */
    fd = g_file_open(XRDP_PID_FILE); /* xrdp.pid */
    if (fd == -1)
    {
      g_writeln("running in daemon mode with no access to pid files, quitting");
      g_exit(0);
    }
    if (g_file_write(fd, "0", 1) == -1)
    {
      g_writeln("running in daemon mode with no access to pid files, quitting");
      g_exit(0);
    }
    g_file_close(fd);
    g_file_delete(XRDP_PID_FILE);
  }
  if (!no_daemon)
  {
    /* start of daemonizing code */
    pid = g_fork();
    if (pid == -1)
    {
      g_writeln("problem forking");
      g_exit(1);
    }
    if (0 != pid)
    {
      g_writeln("process %d started ok", pid);
      /* exit, this is the main process */
      g_exit(0);
    }
    g_sleep(1000);
    g_file_close(0);
    g_file_close(1);
    g_file_close(2);
    g_file_open("/dev/null");
    g_file_open("/dev/null");
    g_file_open("/dev/null");
    /* end of daemonizing code */
  }
  if (!no_daemon)
  {
    /* write the pid to file */
    pid = g_getpid();
    fd = g_file_open(XRDP_PID_FILE); /* xrdp.pid */
    if (fd == -1)
    {
      g_writeln("trying to write process id to xrdp.pid");
      g_writeln("problem opening xrdp.pid");
      g_writeln("maybe no rights");
    }
    else
    {
      g_set_file_rights(XRDP_PID_FILE, 1, 1); /* xrdp.pid */
      g_sprintf(text, "%d", pid);
      g_file_write(fd, text, g_strlen(text));
      g_file_close(fd);
    }
  }
#endif
  g_threadid = tc_get_threadid();
  g_listen = xrdp_listen_create();
  g_signal(2, xrdp_shutdown); /* SIGINT */
  g_signal(9, xrdp_shutdown); /* SIGKILL */
  g_signal(13, pipe_sig); /* sig pipe */
  g_signal(15, xrdp_shutdown); /* SIGTERM */
  g_sync_mutex = tc_mutex_create();
  g_sync1_mutex = tc_mutex_create();
  g_term_event = g_create_wait_obj("xrdp_main_term");
  g_sync_event = g_create_wait_obj("xrdp_main_sync");
  if (g_term_event == 0)
  {
    g_writeln("error creating g_term_event");
  }
  xrdp_listen_main_loop(g_listen);
  xrdp_listen_delete(g_listen);
  tc_mutex_delete(g_sync_mutex);
  tc_mutex_delete(g_sync1_mutex);
  g_delete_wait_obj(g_term_event);
  g_delete_wait_obj(g_sync_event);
#if defined(_WIN32)
  /* I don't think it ever gets here */
  /* when running in win32 app mode, control c exits right away */
  WSACleanup();
#else
  /* delete the xrdp.pid file */
  g_file_delete(XRDP_PID_FILE);
#endif
  return 0;
}

