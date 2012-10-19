/*
   Copyright (c) 2004-2008 Jay Sorg

   Permission is hereby granted, free of charge, to any person obtaining a
   copy of this software and associated documentation files (the "Software"),
   to deal in the Software without restriction, including without limitation
   the rights to use, copy, modify, merge, publish, distribute, sublicense,
   and/or sell copies of the Software, and to permit persons to whom the
   Software is furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included
   in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
   OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
   DEALINGS IN THE SOFTWARE.

   generic operating system calls

   put all the os / arch define in here you want
*/

#if defined(HAVE_CONFIG_H)
#include "config_ac.h"
#endif
#if defined(_WIN32)
#include <windows.h>
#include <winsock.h>
#else
/* fix for solaris 10 with gcc 3.3.2 problem */
#if defined(sun) || defined(__sun)
#define ctid_t id_t
#endif
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <fcntl.h>
#include <pwd.h>
#include <time.h>
#include <grp.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <dirent.h>
#include <locale.h>

#include "os_calls.h"
#include "arch.h"

/* for clearenv() */
#if defined(_WIN32)
#else
extern char** environ;
#endif

/* for solaris */
#if !defined(PF_LOCAL)
#define PF_LOCAL AF_UNIX
#endif
#if !defined(INADDR_NONE)
#define INADDR_NONE ((unsigned long)-1)
#endif

/*****************************************************************************/
void APP_CC
g_init(void)
{
#if defined(_WIN32)
  WSADATA wsadata;

  WSAStartup(2, &wsadata);
#endif
  setlocale(LC_CTYPE, "");
}

/*****************************************************************************/
void APP_CC
g_deinit(void)
{
#if defined(_WIN32)
  WSACleanup();
#endif
}

/*****************************************************************************/
/* allocate memory, returns a pointer to it, size bytes are allocated,
   if zero is non zero, each byte will be set to zero */
void* APP_CC
g_malloc(int size, int zero)
{
  char* rv;

  rv = (char*)malloc(size);
  if (zero)
  {
    if (rv != 0)
    {
      memset(rv, 0, size);
    }
  }
  return rv;
}

/*****************************************************************************/
/* free the memory pointed to by ptr, ptr can be zero */
void APP_CC
g_free(void* ptr)
{
  if (ptr != 0)
  {
    free(ptr);
  }
}

/*****************************************************************************/
/* output text to stdout, try to use g_write / g_writeln instead to avoid
   linux / windows EOL problems */
void DEFAULT_CC
g_printf(const char* format, ...)
{
  va_list ap;

  va_start(ap, format);
  vfprintf(stdout, format, ap);
  va_end(ap);
}

/*****************************************************************************/
void DEFAULT_CC
g_sprintf(char* dest, const char* format, ...)
{
  va_list ap;

  va_start(ap, format);
  vsprintf(dest, format, ap);
  va_end(ap);
}

/*****************************************************************************/
void DEFAULT_CC
g_snprintf(char* dest, int len, const char* format, ...)
{
  va_list ap;

  va_start(ap, format);
  vsnprintf(dest, len, format, ap);
  va_end(ap);
}

/*****************************************************************************/
void DEFAULT_CC
g_writeln(const char* format, ...)
{
  va_list ap;

  va_start(ap, format);
  vfprintf(stdout, format, ap);
  va_end(ap);
#if defined(_WIN32)
  g_printf("\r\n");
#else
  g_printf("\n");
#endif
}

/*****************************************************************************/
void DEFAULT_CC
g_write(const char* format, ...)
{
  va_list ap;

  va_start(ap, format);
  vfprintf(stdout, format, ap);
  va_end(ap);
}

/*****************************************************************************/
/* produce a hex dump */
void APP_CC
g_hexdump(char* p, int len)
{
  unsigned char* line;
  int i;
  int thisline;
  int offset;

  line = (unsigned char*)p;
  offset = 0;
  while (offset < len)
  {
    g_printf("%04x ", offset);
    thisline = len - offset;
    if (thisline > 16)
    {
      thisline = 16;
    }
    for (i = 0; i < thisline; i++)
    {
      g_printf("%02x ", line[i]);
    }
    for (; i < 16; i++)
    {
      g_printf("   ");
    }
    for (i = 0; i < thisline; i++)
    {
      g_printf("%c", (line[i] >= 0x20 && line[i] < 0x7f) ? line[i] : '.');
    }
    g_writeln("");
    offset += thisline;
    line += thisline;
  }
}

/*****************************************************************************/
void APP_CC
g_memset(void* ptr, int val, int size)
{
  memset(ptr, val, size);
}

/*****************************************************************************/
void APP_CC
g_memcpy(void* d_ptr, const void* s_ptr, int size)
{
  memcpy(d_ptr, s_ptr, size);
}

/*****************************************************************************/
int APP_CC
g_getchar(void)
{
  return getchar();
}

/*****************************************************************************/
int APP_CC
g_tcp_set_no_delay(int sck)
{
#if defined(_WIN32)
  int option_value;
  int option_len;
#else
  int option_value;
  unsigned int option_len;
#endif

  option_len = sizeof(option_value);
  /* SOL_TCP IPPROTO_TCP */
  if (getsockopt(sck, IPPROTO_TCP, TCP_NODELAY, (char*)&option_value,
                 &option_len) == 0)
  {
    if (option_value == 0)
    {
      option_value = 1;
      option_len = sizeof(option_value);
      setsockopt(sck, IPPROTO_TCP, TCP_NODELAY, (char*)&option_value,
                 option_len);
    }
  }
  return 0;
}

/*****************************************************************************/
/* returns a newly created socket or -1 on error */
int APP_CC
g_tcp_socket(void)
{
#if defined(_WIN32)
  int rv;
  int option_value;
  int option_len;
#else
  int rv;
  int option_value;
  unsigned int option_len;
#endif

  /* in win32 a socket is an unsigned int, in linux, its an int */
  rv = (int)socket(PF_INET, SOCK_STREAM, 0);
  if (rv < 0)
  {
    return -1;
  }
  option_len = sizeof(option_value);
  if (getsockopt(rv, SOL_SOCKET, SO_REUSEADDR, (char*)&option_value,
                 &option_len) == 0)
  {
    if (option_value == 0)
    {
      option_value = 1;
      option_len = sizeof(option_value);
      setsockopt(rv, SOL_SOCKET, SO_REUSEADDR, (char*)&option_value,
                 option_len);
    }
  }
  option_len = sizeof(option_value);
  if (getsockopt(rv, SOL_SOCKET, SO_SNDBUF, (char*)&option_value,
                 &option_len) == 0)
  {
    if (option_value < (1024 * 32))
    {
      option_value = 1024 * 32;
      option_len = sizeof(option_value);
      setsockopt(rv, SOL_SOCKET, SO_SNDBUF, (char*)&option_value,
                 option_len);
    }
  }
  return rv;
}

/*****************************************************************************/
int APP_CC
g_tcp_local_socket(void)
{
#if defined(_WIN32)
  return 0;
#else
  return socket(PF_LOCAL, SOCK_STREAM, 0);
#endif
}

/*****************************************************************************/
void APP_CC
g_tcp_close(int sck)
{
  if (sck == 0)
  {
    return;
  }
  shutdown(sck, 2);
#if defined(_WIN32)
  closesocket(sck);
#else
  close(sck);
#endif
}

/*****************************************************************************/
/* returns error, zero is good */
int APP_CC
g_tcp_connect(int sck, const char* address, const char* port)
{
  struct sockaddr_in s;
  struct hostent* h;

  g_memset(&s, 0, sizeof(struct sockaddr_in));
  s.sin_family = AF_INET;
  s.sin_port = htons((tui16)atoi(port));
  s.sin_addr.s_addr = inet_addr(address);
  if (s.sin_addr.s_addr == INADDR_NONE)
  {
    h = gethostbyname(address);
    if (h != 0)
    {
      if (h->h_name != 0)
      {
        if (h->h_addr_list != 0)
        {
          if ((*(h->h_addr_list)) != 0)
          {
            s.sin_addr.s_addr = *((int*)(*(h->h_addr_list)));
          }
        }
      }
    }
  }
  return connect(sck, (struct sockaddr*)&s, sizeof(struct sockaddr_in));
}

/*****************************************************************************/
int APP_CC
g_tcp_set_non_blocking(int sck)
{
  unsigned long i;

#if defined(_WIN32)
  i = 1;
  ioctlsocket(sck, FIONBIO, &i);
#else
  i = fcntl(sck, F_GETFL);
  i = i | O_NONBLOCK;
  fcntl(sck, F_SETFL, i);
#endif
  return 0;
}

/*****************************************************************************/
/* returns error, zero is good */
int APP_CC
g_tcp_bind(int sck, char* port)
{
  struct sockaddr_in s;

  memset(&s, 0, sizeof(struct sockaddr_in));
  s.sin_family = AF_INET;
  s.sin_port = htons((tui16)atoi(port));
  s.sin_addr.s_addr = INADDR_ANY;
  return bind(sck, (struct sockaddr*)&s, sizeof(struct sockaddr_in));
}

/*****************************************************************************/
int APP_CC
g_tcp_local_bind(int sck, char* port)
{
#if defined(_WIN32)
  return -1;
#else
  struct sockaddr_un s;

  memset(&s, 0, sizeof(struct sockaddr_un));
  s.sun_family = AF_UNIX;
  strcpy(s.sun_path, port);
  return bind(sck, (struct sockaddr*)&s, sizeof(struct sockaddr_un));
#endif
}

/*****************************************************************************/
/* returns error, zero is good */
int APP_CC
g_tcp_listen(int sck)
{
  return listen(sck, 2);
}

/*****************************************************************************/
int APP_CC
g_tcp_accept(int sck)
{
  struct sockaddr_in s;
#if defined(_WIN32)
  signed int i;
#else
  unsigned int i;
#endif

  i = sizeof(struct sockaddr_in);
  memset(&s, 0, i);
  return accept(sck, (struct sockaddr*)&s, &i);
}

/*****************************************************************************/
void APP_CC
g_sleep(int msecs)
{
#if defined(_WIN32)
  Sleep(msecs);
#else
  usleep(msecs * 1000);
#endif
}

/*****************************************************************************/
int APP_CC
g_tcp_last_error_would_block(int sck)
{
#if defined(_WIN32)
  return WSAGetLastError() == WSAEWOULDBLOCK;
#else
  return (errno == EWOULDBLOCK) || (errno == EINPROGRESS);
#endif
}

/*****************************************************************************/
int APP_CC
g_tcp_recv(int sck, void* ptr, int len, int flags)
{
#if defined(_WIN32)
  return recv(sck, (char*)ptr, len, flags);
#else
  return recv(sck, ptr, len, flags);
#endif
}

/*****************************************************************************/
int APP_CC
g_tcp_send(int sck, const void* ptr, int len, int flags)
{
#if defined(_WIN32)
  return send(sck, (const char*)ptr, len, flags);
#else
  return send(sck, ptr, len, flags);
#endif
}

/*****************************************************************************/
/* returns boolean */
int APP_CC
g_tcp_socket_ok(int sck)
{
#if defined(_WIN32)
  int opt;
  int opt_len;
#else
  int opt;
  unsigned int opt_len;
#endif

  opt_len = sizeof(opt);
  if (getsockopt(sck, SOL_SOCKET, SO_ERROR, (char*)(&opt), &opt_len) == 0)
  {
    if (opt == 0)
    {
      return 1;
    }
  }
  return 0;
}

/*****************************************************************************/
/* wait 'millis' milliseconds for the socket to be able to write */
/* returns boolean */
int APP_CC
g_tcp_can_send(int sck, int millis)
{
  fd_set wfds;
  struct timeval time;
  int rv;

  time.tv_sec = millis / 1000;
  time.tv_usec = (millis * 1000) % 1000000;
  FD_ZERO(&wfds);
  if (sck > 0)
  {
    FD_SET(((unsigned int)sck), &wfds);
    rv = select(sck + 1, 0, &wfds, 0, &time);
    if (rv > 0)
    {
      return g_tcp_socket_ok(sck);
    }
  }
  return 0;
}

/*****************************************************************************/
/* wait 'millis' milliseconds for the socket to be able to receive */
/* returns boolean */
int APP_CC
g_tcp_can_recv(int sck, int millis)
{
  fd_set rfds;
  struct timeval time;
  int rv;

  time.tv_sec = millis / 1000;
  time.tv_usec = (millis * 1000) % 1000000;
  FD_ZERO(&rfds);
  if (sck > 0)
  {
    FD_SET(((unsigned int)sck), &rfds);
    rv = select(sck + 1, &rfds, 0, 0, &time);
    if (rv > 0)
    {
      return g_tcp_socket_ok(sck);
    }
  }
  return 0;
}

/*****************************************************************************/
int APP_CC
g_tcp_select(int sck1, int sck2)
{
  fd_set rfds;
  struct timeval time;
  int max;
  int rv;

  time.tv_sec = 0;
  time.tv_usec = 0;
  FD_ZERO(&rfds);
  if (sck1 > 0)
  {
    FD_SET(((unsigned int)sck1), &rfds);
  }
  if (sck2 > 0)
  {
    FD_SET(((unsigned int)sck2), &rfds);
  }
  max = sck1;
  if (sck2 > max)
  {
    max = sck2;
  }
  rv = select(max + 1, &rfds, 0, 0, &time);
  if (rv > 0)
  {
    rv = 0;
    if (FD_ISSET(((unsigned int)sck1), &rfds))
    {
      rv = rv | 1;
    }
    if (FD_ISSET(((unsigned int)sck2), &rfds))
    {
      rv = rv | 2;
    }
  }
  else
  {
    rv = 0;
  }
  return rv;
}

/*****************************************************************************/
/* returns 0 on error */
tbus APP_CC
g_create_wait_obj(char* name)
{
#ifdef _WIN32
  tbus obj;

  obj = (tbus)CreateEvent(0, 1, 0, name);
  return obj;
#else
  tbus obj;
  struct sockaddr_un sa;
  int len;
  int sck;
  int i;

  sck = socket(PF_UNIX, SOCK_DGRAM, 0);
  if (sck < 0)
  {
    return 0;
  }
  memset(&sa, 0, sizeof(sa));
  sa.sun_family = AF_UNIX;
  if ((name == 0) || (strlen(name) == 0))
  {
    g_random((char*)&i, sizeof(i));
    sprintf(sa.sun_path, "/tmp/auto%8.8x", i);
    while (g_file_exist(sa.sun_path))
    {
      g_random((char*)&i, sizeof(i));
      sprintf(sa.sun_path, "/tmp/auto%8.8x", i);
    }
  }
  else
  {
    sprintf(sa.sun_path, "/tmp/%s", name);
  }
  unlink(sa.sun_path);
  len = sizeof(sa);
  if (bind(sck, (struct sockaddr*)&sa, len) < 0)
  {
    close(sck);
    return 0;
  }
  obj = (tbus)sck;
  return obj;
#endif
}

/*****************************************************************************/
/* returns 0 on error */
tbus APP_CC
g_create_wait_obj_from_socket(tbus socket, int write)
{
#ifdef _WIN32
  /* Create and return corresponding event handle for WaitForMultipleObjets */
  WSAEVENT event;
  long lnetevent;

  event = WSACreateEvent();
  lnetevent = (write ? FD_WRITE : FD_READ) | FD_CLOSE;
  if (WSAEventSelect(socket, event, lnetevent) == 0)
  {
    return (tbus)event;
  }
  else
  {
    return 0;
  }
#else
  return socket;
#endif
}

/*****************************************************************************/
void APP_CC
g_delete_wait_obj_from_socket(tbus wait_obj)
{
#ifdef _WIN32
  if (wait_obj == 0)
  {
    return;
  }
  WSACloseEvent((HANDLE)wait_obj);
#else
#endif
}

/*****************************************************************************/
/* returns error */
int APP_CC
g_set_wait_obj(tbus obj)
{
#ifdef _WIN32
  if (obj == 0)
  {
    return 0;
  }
  SetEvent((HANDLE)obj);
  return 0;
#else
  socklen_t sa_size;
  int s;
  struct sockaddr_un sa;

  if (obj == 0)
  {
    return 0;
  }
  if (g_tcp_can_recv((int)obj, 0))
  {
    /* already signalled */
    return 0;
  }
  sa_size = sizeof(sa);
  if (getsockname((int)obj, (struct sockaddr*)&sa, &sa_size) < 0)
  {
    return 1;
  }
  s = socket(PF_UNIX, SOCK_DGRAM, 0);
  if (s < 0)
  {
    return 1;
  }
  sendto(s, "sig", 4, 0, (struct sockaddr*)&sa, sa_size);
  close(s);
  return 0;
#endif
}

/*****************************************************************************/
/* returns error */
int APP_CC
g_reset_wait_obj(tbus obj)
{
#ifdef _WIN32
  if (obj == 0)
  {
    return 0;
  }
  ResetEvent((HANDLE)obj);
  return 0;
#else
  char buf[64];

  if (obj == 0)
  {
    return 0;
  }
  while (g_tcp_can_recv((int)obj, 0))
  {
    recvfrom((int)obj, &buf, 64, 0, 0, 0);
  }
  return 0;
#endif
}

/*****************************************************************************/
/* returns boolean */
int APP_CC
g_is_wait_obj_set(tbus obj)
{
#ifdef _WIN32
  if (obj == 0)
  {
    return 0;
  }
  if (WaitForSingleObject((HANDLE)obj, 0) == WAIT_OBJECT_0)
  {
    return 1;
  }
  return 0;
#else
  if (obj == 0)
  {
    return 0;
  }
  return g_tcp_can_recv((int)obj, 0);
#endif
}

/*****************************************************************************/
/* returns error */
int APP_CC
g_delete_wait_obj(tbus obj)
{
#ifdef _WIN32
  if (obj == 0)
  {
    return 0;
  }
  /* Close event handle */
  CloseHandle((HANDLE)obj);
  return 0;
#else
  socklen_t sa_size;
  struct sockaddr_un sa;

  if (obj == 0)
  {
    return 0;
  }
  sa_size = sizeof(sa);
  if (getsockname((int)obj, (struct sockaddr*)&sa, &sa_size) < 0)
  {
    return 1;
  }
  close((int)obj);
  unlink(sa.sun_path);
  return 0;
#endif
}

/*****************************************************************************/
/* returns error */
int APP_CC
g_obj_wait(tbus* read_objs, int rcount, tbus* write_objs, int wcount,
           int mstimeout)
{
#ifdef _WIN32
  HANDLE handles[256];
  DWORD count;
  DWORD error;
  int j;
  int i;

  j = 0;
  count = rcount + wcount;
  for (i = 0; i < rcount; i++)
  {
    handles[j++] = (HANDLE)(read_objs[i]);
  }
  for (i = 0; i < wcount; i++)
  {
    handles[j++] = (HANDLE)(write_objs[i]);
  }
  if (mstimeout < 1)
  {
    mstimeout = INFINITE;
  }
  error = WaitForMultipleObjects(count, handles, FALSE, mstimeout);
  if (error == WAIT_FAILED)
  {
    return 1;
  }
  return 0;
#else
  fd_set rfds;
  fd_set wfds;
  struct timeval time;
  struct timeval* ptime;
  int i;
  int max;
  int sck;

  max = 0;
  if (mstimeout < 1)
  {
    ptime = 0;
  }
  else
  {
    time.tv_sec = mstimeout / 1000;
    time.tv_usec = (mstimeout % 1000) * 1000;
    ptime = &time;
  }
  FD_ZERO(&rfds);
  FD_ZERO(&wfds);
  for (i = 0; i < rcount; i++)
  {
    sck = (int)(read_objs[i]);
    FD_SET(sck, &rfds);
    if (sck > max)
    {
      max = sck;
    }
  }
  for (i = 0; i < wcount; i++)
  {
    sck = (int)(write_objs[i]);
    FD_SET(sck, &wfds);
    if (sck > max)
    {
      max = sck;
    }
  }
  i = select(max + 1, &rfds, &wfds, 0, ptime);
  if (i < 0)
  {
    return 1;
  }
  return 0;
#endif
}

/*****************************************************************************/
void APP_CC
g_random(char* data, int len)
{
#if defined(_WIN32)
  int index;

  srand(g_time1());
  for (index = 0; index < len; index++)
  {
    data[index] = (char)rand(); /* rand returns a number between 0 and
                                   RAND_MAX */
  }
#else
  int fd;

  memset(data, 0x44, len);
  fd = open("/dev/urandom", O_RDONLY);
  if (fd == -1)
  {
    fd = open("/dev/random", O_RDONLY);
  }
  if (fd != -1)
  {
    read(fd, data, len);
    close(fd);
  }
#endif
}

/*****************************************************************************/
int APP_CC
g_abs(int i)
{
  return abs(i);
}

/*****************************************************************************/
int APP_CC
g_memcmp(const void* s1, const void* s2, int len)
{
  return memcmp(s1, s2, len);
}

/*****************************************************************************/
/* returns -1 on error, else return handle or file descriptor */
int APP_CC
g_file_open(const char* file_name)
{
#if defined(_WIN32)
  return (int)CreateFileA(file_name, GENERIC_READ | GENERIC_WRITE,
                          FILE_SHARE_READ | FILE_SHARE_WRITE,
                          0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
#else
  int rv;

  rv =  open(file_name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
  if (rv == -1)
  {
    /* can't open read / write, try to open read only */
    rv =  open(file_name, O_RDONLY);
  }
  return rv;
#endif
}

/*****************************************************************************/
/* returns error, always 0 */
int APP_CC
g_file_close(int fd)
{
#if defined(_WIN32)
  CloseHandle((HANDLE)fd);
#else
  close(fd);
#endif
  return 0;
}

/*****************************************************************************/
/* read from file, returns the number of bytes read or -1 on error */
int APP_CC
g_file_read(int fd, char* ptr, int len)
{
#if defined(_WIN32)
  if (ReadFile((HANDLE)fd, (LPVOID)ptr, (DWORD)len, (LPDWORD)&len, 0))
  {
    return len;
  }
  else
  {
    return -1;
  }
#else
  return read(fd, ptr, len);
#endif
}

/*****************************************************************************/
/* write to file, returns the number of bytes writen or -1 on error */
int APP_CC
g_file_write(int fd, char* ptr, int len)
{
#if defined(_WIN32)
  if (WriteFile((HANDLE)fd, (LPVOID)ptr, (DWORD)len, (LPDWORD)&len, 0))
  {
    return len;
  }
  else
  {
    return -1;
  }
#else
  return write(fd, ptr, len);
#endif
}

/*****************************************************************************/
/* move file pointer, returns offset on success, -1 on failure */
int APP_CC
g_file_seek(int fd, int offset)
{
#if defined(_WIN32)
  int rv;

  rv = (int)SetFilePointer((HANDLE)fd, offset, 0, FILE_BEGIN);
  if (rv == (int)INVALID_SET_FILE_POINTER)
  {
    return -1;
  }
  else
  {
    return rv;
  }
#else
  return (int)lseek(fd, offset, SEEK_SET);
#endif
}

/*****************************************************************************/
/* do a write lock on a file */
/* return boolean */
int APP_CC
g_file_lock(int fd, int start, int len)
{
#if defined(_WIN32)
  return LockFile((HANDLE)fd, start, 0, len, 0);
#else
  struct flock lock;

  lock.l_type = F_WRLCK;
  lock.l_whence = SEEK_SET;
  lock.l_start = start;
  lock.l_len = len;
  if (fcntl(fd, F_SETLK, &lock) == -1)
  {
    return 0;
  }
  return 1;
#endif
}

/*****************************************************************************/
/* returns error, always zero */
int APP_CC
g_set_file_rights(const char* filename, int read, int write)
{
#if defined(_WIN32)
  return 0;
#else
  int flags;

  flags = read ? S_IRUSR : 0;
  flags |= write ? S_IWUSR : 0;
  chmod(filename, flags);
  return 0;
#endif
}

/*****************************************************************************/
/* returns error */
int APP_CC
g_chmod_hex(const char* filename, int flags)
{
#if defined(_WIN32)
  return 0;
#else
  int fl;

  fl = 0;
  fl |= (flags & 0x4000) ? S_ISUID : 0;
  fl |= (flags & 0x2000) ? S_ISGID : 0;
  fl |= (flags & 0x1000) ? S_ISVTX : 0;
  fl |= (flags & 0x0400) ? S_IRUSR : 0;
  fl |= (flags & 0x0200) ? S_IWUSR : 0;
  fl |= (flags & 0x0100) ? S_IXUSR : 0;
  fl |= (flags & 0x0040) ? S_IRGRP : 0;
  fl |= (flags & 0x0020) ? S_IWGRP : 0;
  fl |= (flags & 0x0010) ? S_IXGRP : 0;
  fl |= (flags & 0x0004) ? S_IROTH : 0;
  fl |= (flags & 0x0002) ? S_IWOTH : 0;
  fl |= (flags & 0x0001) ? S_IXOTH : 0;
  return chmod(filename, fl);
#endif
}

/*****************************************************************************/
/* returns error, always zero */
int APP_CC
g_mkdir(const char* dirname)
{
#if defined(_WIN32)
  return 0;
#else
  mkdir(dirname, S_IRWXU);
  return 0;
#endif
}

/*****************************************************************************/
/* gets the current working directory and puts up to maxlen chars in
   dirname 
   always returns 0 */
char* APP_CC
g_get_current_dir(char* dirname, int maxlen)
{
#if defined(_WIN32)
  GetCurrentDirectoryA(maxlen, dirname);
  return 0;
#else
  getcwd(dirname, maxlen);
  return 0;
#endif
}

/*****************************************************************************/
/* returns error, zero on success and -1 on failure */
int APP_CC
g_set_current_dir(char* dirname)
{
#if defined(_WIN32)
  if (SetCurrentDirectoryA(dirname))
  {
    return 0;
  }
  else
  {
    return -1;
  }
#else
  return chdir(dirname);
#endif
}

/*****************************************************************************/
/* returns boolean, non zero if the file exists */
int APP_CC
g_file_exist(const char* filename)
{
#if defined(_WIN32)
  return 0; // use FileAge(filename) <> -1
#else
  return access(filename, F_OK) == 0;
#endif
}

/*****************************************************************************/
/* returns boolean, non zero if the directory exists */
int APP_CC
g_directory_exist(const char* dirname)
{
#if defined(_WIN32)
  return 0; // use GetFileAttributes and check return value
            // is not -1 and FILE_ATTRIBUT_DIRECTORY bit is set
#else
  struct stat st;

  if (stat(dirname, &st) == 0)
  {
    return S_ISDIR(st.st_mode);
  }
  else
  {
    return 0;
  }
#endif
}

/*****************************************************************************/
/* returns boolean */
int APP_CC
g_create_dir(const char* dirname)
{
#if defined(_WIN32)
  return CreateDirectoryA(dirname, 0); // test this
#else
  return mkdir(dirname, (mode_t)-1) == 0;
#endif
}

/*****************************************************************************/
/* returns boolean */
int APP_CC
g_remove_dir(const char* dirname)
{
#if defined(_WIN32)
  return RemoveDirectoryA(dirname); // test this
#else
  return rmdir(dirname) == 0;
#endif
}

/*****************************************************************************/
/* returns non zero if the file was deleted */
int APP_CC
g_file_delete(const char* filename)
{
#if defined(_WIN32)
  return DeleteFileA(filename);
#else
  return unlink(filename) != -1;
#endif
}

/*****************************************************************************/
/* returns file size, -1 on error */
int APP_CC
g_file_get_size(const char* filename)
{
#if defined(_WIN32)
  return -1;
#else
  struct stat st;

  if (stat(filename, &st) == 0)
  {
    return (int)(st.st_size);
  }
  else
  {
    return -1;
  }
#endif
}

/*****************************************************************************/
/* returns length of text */
int APP_CC
g_strlen(const char* text)
{
  if (text == 0)
  {
    return 0;
  }
  return strlen(text);
}

/*****************************************************************************/
/* returns dest */
char* APP_CC
g_strcpy(char* dest, const char* src)
{
  if (src == 0 && dest != 0)
  {
    dest[0] = 0;
    return dest;
  }
  if (dest == 0 || src == 0)
  {
    return 0;
  }
  return strcpy(dest, src);
}

/*****************************************************************************/
/* returns dest */
char* APP_CC
g_strncpy(char* dest, const char* src, int len)
{
  char* rv;

  if (src == 0 && dest != 0)
  {
    dest[0] = 0;
    return dest;
  }
  if (dest == 0 || src == 0)
  {
    return 0;
  }
  rv = strncpy(dest, src, len);
  dest[len] = 0;
  return rv;
}

/*****************************************************************************/
/* returns dest */
char* APP_CC
g_strcat(char* dest, const char* src)
{
  if (dest == 0 || src == 0)
  {
    return dest;
  }
  return strcat(dest, src);
}

/*****************************************************************************/
/* if in = 0, return 0 else return newly alloced copy of in */
char* APP_CC
g_strdup(const char* in)
{
  int len;
  char* p;

  if (in == 0)
  {
    return 0;
  }
  len = g_strlen(in);
  p = (char*)g_malloc(len + 1, 0);
  g_strcpy(p, in);
  return p;
}

/*****************************************************************************/
int APP_CC
g_strcmp(const char* c1, const char* c2)
{
  return strcmp(c1, c2);
}

/*****************************************************************************/
int APP_CC
g_strncmp(const char* c1, const char* c2, int len)
{
  return strncmp(c1, c2, len);
}

/*****************************************************************************/
int APP_CC
g_strcasecmp(const char* c1, const char* c2)
{
#if defined(_WIN32)
  return stricmp(c1, c2);
#else
  return strcasecmp(c1, c2);
#endif
}

/*****************************************************************************/
int APP_CC
g_strncasecmp(const char* c1, const char* c2, int len)
{
#if defined(_WIN32)
  return strnicmp(c1, c2, len);
#else
  return strncasecmp(c1, c2, len);
#endif
}

/*****************************************************************************/
int APP_CC
g_atoi(char* str)
{
  return atoi(str);
}

/*****************************************************************************/
int APP_CC
g_htoi(char* str)
{
  int len;
  int index;
  int rv;
  int val;
  int shift;

  rv = 0;
  len = strlen(str);
  index = len - 1;
  shift = 0;
  while (index >= 0)
  {
    val = 0;
    switch (str[index])
    {
      case '1':
        val = 1;
        break;
      case '2':
        val = 2;
        break;
      case '3':
        val = 3;
        break;
      case '4':
        val = 4;
        break;
      case '5':
        val = 5;
        break;
      case '6':
        val = 6;
        break;
      case '7':
        val = 7;
        break;
      case '8':
        val = 8;
        break;
      case '9':
        val = 9;
        break;
      case 'a':
      case 'A':
        val = 10;
        break;
      case 'b':
      case 'B':
        val = 11;
        break;
      case 'c':
      case 'C':
        val = 12;
        break;
      case 'd':
      case 'D':
        val = 13;
        break;
      case 'e':
      case 'E':
        val = 14;
        break;
      case 'f':
      case 'F':
        val = 15;
        break;
    }
    rv = rv | (val << shift);
    index--;
    shift += 4;
  }
  return rv;
}

/*****************************************************************************/
int APP_CC
g_pos(char* str, const char* to_find)
{
  char* pp;

  pp = strstr(str, to_find);
  if (pp == 0)
  {
    return -1;
  }
  return (pp - str);
}

/*****************************************************************************/
int APP_CC
g_mbstowcs(twchar* dest, const char* src, int n)
{
  wchar_t* ldest;
  int rv;

  ldest = (wchar_t*)dest;
  rv = mbstowcs(ldest, src, n);
  return rv;
}

/*****************************************************************************/
int APP_CC
g_wcstombs(char* dest, const twchar* src, int n)
{
  const wchar_t* lsrc;
  int rv;

  lsrc = (const wchar_t*)src;
  rv = wcstombs(dest, lsrc, n);
  return rv;
}

/*****************************************************************************/
/* returns error */
/* trim spaces and tabs, anything <= space */
/* trim_flags 1 trim left, 2 trim right, 3 trim both, 4 trim through */
/* this will always shorten the string or not change it */
int APP_CC
g_strtrim(char* str, int trim_flags)
{
  int index;
  int len;
  int text1_index;
  int got_char;
  wchar_t* text;
  wchar_t* text1;

  len = mbstowcs(0, str, 0);
  if (len < 1)
  {
    return 0;
  }
  if ((trim_flags < 1) || (trim_flags > 4))
  {
    return 1;
  }
  text = (wchar_t*)malloc(len * sizeof(wchar_t) + 8);
  text1 = (wchar_t*)malloc(len * sizeof(wchar_t) + 8);
  text1_index = 0;
  mbstowcs(text, str, len + 1);
  switch (trim_flags)
  {
    case 4: /* trim through */
      for (index = 0; index < len; index++)
      {
        if (text[index] > 32)
        {
          text1[text1_index] = text[index];
          text1_index++;
        }
      }
      text1[text1_index] = 0;
      break;
    case 3: /* trim both */
      got_char = 0;
      for (index = 0; index < len; index++)
      {
        if (got_char)
        {
          text1[text1_index] = text[index];
          text1_index++;
        }
        else
        {
          if (text[index] > 32)
          {
            text1[text1_index] = text[index];
            text1_index++;
            got_char = 1;
          }
        }
      }
      text1[text1_index] = 0;
      len = text1_index;
      /* trim right */
      for (index = len - 1; index >= 0; index--)
      {
        if (text1[index] > 32)
        {
          break;
        }
      }
      text1_index = index + 1;
      text1[text1_index] = 0;
      break;
    case 2: /* trim right */
      /* copy it */
      for (index = 0; index < len; index++)
      {
        text1[text1_index] = text[index];
        text1_index++;
      }
      /* trim right */
      for (index = len - 1; index >= 0; index--)
      {
        if (text1[index] > 32)
        {
          break;
        }
      }
      text1_index = index + 1;
      text1[text1_index] = 0;
      break;
    case 1: /* trim left */
      got_char = 0;
      for (index = 0; index < len; index++)
      {
        if (got_char)
        {
          text1[text1_index] = text[index];
          text1_index++;
        }
        else
        {
          if (text[index] > 32)
          {
            text1[text1_index] = text[index];
            text1_index++;
            got_char = 1;
          }
        }
      }
      text1[text1_index] = 0;
      break;
  }
  wcstombs(str, text1, text1_index + 1);
  free(text);
  free(text1);
  return 0;
}

/*****************************************************************************/
long APP_CC
g_load_library(char* in)
{
#if defined(_WIN32)
  return (long)LoadLibraryA(in);
#else
  char file[512];
  void *handle;
  g_snprintf(file, sizeof (file), XRDP_LIB_PATH "/%s", in);
  file[sizeof (file) - 1] = '\0';
  handle = dlopen(file, RTLD_LOCAL | RTLD_LAZY);
  if (handle)
    return (long) handle;
  return (long)dlopen(in, RTLD_LOCAL | RTLD_LAZY);
#endif
}

/*****************************************************************************/
int APP_CC
g_free_library(long lib)
{
  if (lib == 0)
  {
    return 0;
  }
#if defined(_WIN32)
  return FreeLibrary((HMODULE)lib);
#else
  return dlclose((void*)lib);
#endif
}

/*****************************************************************************/
/* returns NULL if not found */
void* APP_CC
g_get_proc_address(long lib, const char* name)
{
  if (lib == 0)
  {
    return 0;
  }
#if defined(_WIN32)
  return GetProcAddress((HMODULE)lib, name);
#else
  return dlsym((void*)lib, name);
#endif
}

/*****************************************************************************/
/* does not work in win32 */
int APP_CC
g_system(char* aexec)
{
#if defined(_WIN32)
  return 0;
#else
  return system(aexec);
#endif
}

/*****************************************************************************/
/* does not work in win32 */
char* APP_CC
g_get_strerror(void)
{
#if defined(_WIN32)
  return 0;
#else
  return strerror(errno);
#endif
}

/*****************************************************************************/
/* does not work in win32 */
int APP_CC
g_execvp(const char* p1, char* args[])
{
#if defined(_WIN32)
  return 0;
#else
  return execvp(p1, args);
#endif
}

/*****************************************************************************/
/* does not work in win32 */
int APP_CC
g_execlp3(const char* a1, const char* a2, const char* a3)
{
#if defined(_WIN32)
  return 0;
#else
  return execlp(a1, a2, a3, (void*)0);
#endif
}

/*****************************************************************************/
/* does not work in win32 */
void APP_CC
g_signal(int sig_num, void (*func)(int))
{
#if defined(_WIN32)
#else
  signal(sig_num, func);
#endif
}

/*****************************************************************************/
/* does not work in win32 */
void APP_CC
g_signal_child_stop(void (*func)(int))
{
#if defined(_WIN32)
#else
  signal(SIGCHLD, func);
#endif
}

/*****************************************************************************/
/* does not work in win32 */
void APP_CC
g_unset_signals(void)
{
#if defined(_WIN32)
#else
  sigset_t mask;

  sigemptyset(&mask);
  sigprocmask(SIG_SETMASK, &mask, NULL);
#endif
}

/*****************************************************************************/
/* does not work in win32 */
int APP_CC
g_fork(void)
{
#if defined(_WIN32)
  return 0;
#else
  return fork();
#endif
}

/*****************************************************************************/
/* does not work in win32 */
int APP_CC
g_setgid(int pid)
{
#if defined(_WIN32)
  return 0;
#else
  return setgid(pid);
#endif
}

/*****************************************************************************/
/* returns error, zero is success, non zero is error */
/* does not work in win32 */
int APP_CC
g_initgroups(const char* user, int gid)
{
#if defined(_WIN32)
  return 0;
#else
  return initgroups(user, gid);
#endif
}

/*****************************************************************************/
/* does not work in win32 */
/* returns user id */
int APP_CC
g_getuid(void)
{
#if defined(_WIN32)
  return 0;
#else
  return getuid();
#endif
}

/*****************************************************************************/
/* does not work in win32 */
/* On success, zero is returned. On error, -1 is returned */
int APP_CC
g_setuid(int pid)
{
#if defined(_WIN32)
  return 0;
#else
  return setuid(pid);
#endif
}

/*****************************************************************************/
/* does not work in win32 */
int APP_CC
g_waitchild(void)
{
#if defined(_WIN32)
  return 0;
#else
  int wstat;

  return waitpid(0, &wstat, WNOHANG);
#endif
}

/*****************************************************************************/
/* does not work in win32 */
int APP_CC
g_waitpid(int pid)
{
#if defined(_WIN32)
  return 0;
#else
  return waitpid(pid, 0, 0);
#endif
}

/*****************************************************************************/
/* does not work in win32 */
void APP_CC
g_clearenv(void)
{
#if defined(_WIN32)
#else
  environ = 0;
#endif
}

/*****************************************************************************/
/* does not work in win32 */
int APP_CC
g_setenv(const char* name, const char* value, int rewrite)
{
#if defined(_WIN32)
  return 0;
#else
  return setenv(name, value, rewrite);
#endif
}

/*****************************************************************************/
/* does not work in win32 */
char* APP_CC
g_getenv(const char* name)
{
#if defined(_WIN32)
  return 0;
#else
  return getenv(name);
#endif
}

/*****************************************************************************/
int APP_CC
g_exit(int exit_code)
{
  _exit(exit_code);
  return 0;
}

/*****************************************************************************/
/* does not work in win32 */
int APP_CC
g_getpid(void)
{
#if defined(_WIN32)
  return 0;
#else
  return getpid();
#endif
}

/*****************************************************************************/
/* does not work in win32 */
int APP_CC
g_sigterm(int pid)
{
#if defined(_WIN32)
  return 0;
#else
  return kill(pid, SIGTERM);
#endif
}

/*****************************************************************************/
/* returns 0 if ok */
/* does not work in win32 */
int APP_CC
g_getuser_info(const char* username, int* gid, int* uid, char* shell,
               char* dir, char* gecos)
{
#if defined(_WIN32)
  return 1;
#else
  struct passwd* pwd_1;

  pwd_1 = getpwnam(username);
  if (pwd_1 != 0)
  {
    if (gid != 0)
    {
      *gid = pwd_1->pw_gid;
    }
    if (uid != 0)
    {
      *uid = pwd_1->pw_uid;
    }
    if (dir != 0)
    {
      g_strcpy(dir, pwd_1->pw_dir);
    }
    if (shell != 0)
    {
      g_strcpy(shell, pwd_1->pw_shell);
    }
    if (gecos != 0)
    {
      g_strcpy(gecos, pwd_1->pw_gecos);
    }
    return 0;
  }
  return 1;
#endif
}

/*****************************************************************************/
/* returns 0 if ok */
/* does not work in win32 */
int APP_CC
g_getgroup_info(const char* groupname, int* gid)
{
#if defined(_WIN32)
  return 1;
#else
  struct group* g;

  g = getgrnam(groupname);
  if (g != 0)
  {
    if (gid != 0)
    {
      *gid = g->gr_gid;
    }
    return 0;
  }
  return 1;
#endif
}

/*****************************************************************************/
/* returns error */
/* if zero is returned, then ok is set */
/* does not work in win32 */
int APP_CC
g_check_user_in_group(const char* username, int gid, int* ok)
{
#if defined(_WIN32)
  return 1;
#else
  struct group* groups;
  int i;

  groups = getgrgid(gid);
  if (groups == 0)
  {
    return 1;
  }
  *ok = 0;
  i = 0;
  while (0 != groups->gr_mem[i])
  {
    if (0 == g_strcmp(groups->gr_mem[i], username))
    {
      *ok = 1;
      break;
    }
    i++;
  }
  return 0;
#endif
}

/*****************************************************************************/
/* returns the time since the Epoch (00:00:00 UTC, January 1, 1970),
   measured in seconds.
   for windows, returns the number of seconds since the machine was
   started. */
int APP_CC
g_time1(void)
{
#if defined(_WIN32)
  return GetTickCount() / 1000;
#else
  return time(0);
#endif
}

/*****************************************************************************/
/* returns the number of milliseconds since the machine was
   started. */
int APP_CC
g_time2(void)
{
#if defined(_WIN32)
  return (int)GetTickCount();
#else
  struct tms tm;
  clock_t num_ticks;

  num_ticks = times(&tm);
  return (int)(num_ticks * 10);
#endif
}

/*****************************************************************************/
/* returns 0 on error, else return handle */
unsigned int APP_CC
g_dir_open(const char * dir_name)
{
#if defined(_WIN32)
  return 0;
#else
  return (unsigned int) opendir (dir_name);
#endif
}

/*****************************************************************************/
void APP_CC
g_dir_close(unsigned int handle)
{
#if defined(_WIN32)
#else
  closedir ((DIR *) handle);
#endif
}

/*****************************************************************************/
const char* APP_CC
g_dir_read_name(unsigned int handle)
{
#if defined(_WIN32)
  return 0;
#else
  struct dirent *ent;

  ent = readdir ((DIR *) handle);
  if (!ent)
    return 0;

  return ent->d_name;
#endif
}

/*****************************************************************************/
/* returns -1 on error, else 0 is returned */
int APP_CC
g_gethostname(char *name, unsigned int len)
{
#if defined(_WIN32)
  return -1;
#else
  return gethostname (name, len);
#endif
}
