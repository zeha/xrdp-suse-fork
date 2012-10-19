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
 * @file config.h
 * @brief User authentication definitions
 * @author Simone Fedele @< simo [at] esseemme [dot] org @>
 *
 */

#ifndef CONFIG_H
#define CONFIG_H

#include "arch.h"
#include "list.h"
#include "log.h"

/**
 *
 * @def SESMAN_CFG_FILE
 * @brief Configuration file path
 *
 */
#ifndef SESMAN_CFG_FILE
#define SESMAN_CFG_FILE              "./sesman.ini"
#endif

#define SESMAN_CFG_GLOBALS           "Globals"
#define SESMAN_CFG_DEFWM             "DefaultWindowManager"
#define SESMAN_CFG_ADDRESS           "ListenAddress"
#define SESMAN_CFG_PORT              "ListenPort"
#define SESMAN_CFG_ENABLE_USERWM     "EnableUserWindowManager"
#define SESMAN_CFG_USERWM            "UserWindowManager"
#define SESMAN_CFG_MAX_SESSION       "MaxSessions"
#define SESMAN_CFG_AUTH_FILE_PATH    "AuthFilePath"

#define SESMAN_CFG_RDP_PARAMS        "X11rdp"
#define SESMAN_CFG_VNC_PARAMS        "Xvnc"
#define SESMAN_CFG_DMX_PARAMS        "Xdmx"
#define SESMAN_CFG_DMX_XKB_PARAMS    "XdmxXKB"
#define SESMAN_CFG_DMX_BACKEND_PARAMS "XdmxBackend"
#define SESMAN_CFG_DMX_BACKEND       "Backend"

#define SESMAN_CFG_LOGGING           "Logging"
#define SESMAN_CFG_LOG_FILE          "LogFile"
#define SESMAN_CFG_LOG_LEVEL         "LogLevel"
#define SESMAN_CFG_LOG_ENABLE_SYSLOG "EnableSyslog"
#define SESMAN_CFG_LOG_SYSLOG_LEVEL  "SyslogLevel"

#define SESMAN_CFG_SECURITY          "Security"
#define SESMAN_CFG_SEC_LOGIN_RETRY   "MaxLoginRetry"
#define SESMAN_CFG_SEC_ALLOW_ROOT    "AllowRootLogin"
#define SESMAN_CFG_SEC_USR_GROUP     "TerminalServerUsers"
#define SESMAN_CFG_SEC_ADM_GROUP     "TerminalServerAdmins"

#define SESMAN_CFG_SESSIONS          "Sessions"
#define SESMAN_CFG_SESS_MAX          "MaxSessions"
#define SESMAN_CFG_SESS_KILL_DISC    "KillDisconnected"
#define SESMAN_CFG_SESS_IDLE_LIMIT   "IdleTimeLimit"
#define SESMAN_CFG_SESS_DISC_LIMIT   "DisconnectedTimeLimit"

/**
 *
 * @struct config_security
 * @brief struct that contains sesman access control configuration
 *
 */
struct config_security
{
  /**
   * @var allow_root
   * @brief allow root login on TS
   */
  int allow_root;
  /**
   * @var login_retry
   * @brief maximum login attempts
   */
  int login_retry;
  /**
   * @var ts_users
   * @brief Terminal Server Users group
   */
  int ts_users_enable;
  int ts_users;
  /**
   * @var ts_admins
   * @brief Terminal Server Adminnistrators group
   */
  int ts_admins_enable;
  int ts_admins;
};

/**
 *
 * @struct config_sessions
 * @brief struct that contains sesman session handling configuration
 *
 */
struct config_sessions
{
  /**
   * @var max_sessions
   * @brief maximum number of allowed sessions. 0 for unlimited
   */
  int max_sessions;
  /**
   * @var max_idle_time
   * @brief maximum idle time for each session
   */
  int max_idle_time;
  /**
   * @var max_disc_time
   * @brief maximum disconnected time for each session
   */
  int max_disc_time;
  /**
   * @var kill_disconnected
   * @brief enables automatic killing of disconnected session
   */
  int kill_disconnected;
};

/**
 *
 * @struct config_sesman
 * @brief struct that contains sesman configuration
 *
 * This struct contains all of sesman configuration parameters\n
 * Every parameter in [globals] is a member of this struct, other
 * sections options are embedded in this struct as member structures
 *
 */
struct config_sesman
{
  /**
   * @var listen_address
   * @brief Listening address
   */
  char listen_address[32];
  /**
   * @var listen_port
   * @brief Listening port
   */
  char listen_port[16];
  /**
   * @var enable_user_wm
   * @brief Flag that enables user specific wm
   */
  int enable_user_wm;
  /**
   * @var default_wm
   * @brief Default window manager
   */
  char default_wm[32];
  /**
   * @var user_wm
   * @brief Default window manager
   */
  char user_wm[32];
  /**
   * @var auth_file_path
   * @brief Auth file path
   */
  char* auth_file_path;
  /**
   * @var vnc_params
   * @brief Xvnc additional parameter list
   */
  struct list* vnc_params;
  /**
   * @var rdp_params
   * @brief X11rdp additional parameter list
   */
  struct list* rdp_params;
  /**
   * @var dmx_params
   * @brief Xdmx additional parameter list
   */
  struct list* dmx_params;
  /**
   * @var dmx_backend;
   * @brief the backend which dmx choose
   */
  char *dmx_backend;
  /**
   * @var dmx_backend_params;
   * @brief Xdmx backend additional parameter list
   */
  struct list* dmx_backend_params;
  /**
   * @var dmx_xkb_params;
   * @brief setxkbmap additional parameter list
   */
  struct {
    struct list* lang;
    struct list* params;
  }dmx_xkb_params;
    
  /**
   * @var log
   * @brief Log configuration struct
   */
  struct log_config log;
  /**
   * @var sec
   * @brief Security configuration options struct
   */
  struct config_security sec;
  /**
   * @var sess
   * @brief Session configuration options struct
   */
  struct config_sessions sess;
};

/**
 *
 * @brief Reads sesman configuration
 * @param cfg pointer to configuration object to be replaced
 * @return 0 on success, 1 on failure
 *
 */
int DEFAULT_CC
config_read(struct config_sesman* cfg);

/**
 *
 * @brief Reads sesman [global] configuration section
 * @param file configuration file descriptor
 * @param cf pointer to a config struct
 * @param param_n parameter name list
 * @param param_v parameter value list
 * @return 0 on success, 1 on failure
 *
 */
int DEFAULT_CC
config_read_globals(int file, struct config_sesman* cf,
                    struct list* param_n, struct list* param_v);

/**
 *
 * @brief Reads sesman [logging] configuration section
 * @param file configuration file descriptor
 * @param lc pointer to a log_config struct
 * @param param_n parameter name list
 * @param param_v parameter value list
 * @return 0 on success, 1 on failure
 *
 */
int DEFAULT_CC
config_read_logging(int file, struct log_config* lc, struct list* param_n,
                    struct list* param_v);

/**
 *
 * @brief Reads sesman [Security] configuration section
 * @param file configuration file descriptor
 * @param sc pointer to a config_security struct
 * @param param_n parameter name list
 * @param param_v parameter value list
 * @return 0 on success, 1 on failure
 *
 */
int DEFAULT_CC
config_read_security(int file, struct config_security* sc,
                     struct list* param_n, struct list* param_v);

/**
 *
 * @brief Reads sesman [Sessions] configuration section
 * @param file configuration file descriptor
 * @param ss pointer to a config_sessions struct
 * @param param_n parameter name list
 * @param param_v parameter value list
 * @return 0 on success, 1 on failure
 *
 */
int DEFAULT_CC
config_read_sessions(int file, struct config_sessions* ss,
                     struct list* param_n, struct list* param_v);

/**
 *
 * @brief Reads sesman [X11rdp] configuration section
 * @param file configuration file descriptor
 * @param cs pointer to a config_sesman struct
 * @param param_n parameter name list
 * @param param_v parameter value list
 * @return 0 on success, 1 on failure
 *
 */
int DEFAULT_CC
config_read_rdp_params(int file, struct config_sesman* cs, struct list* param_n,
                       struct list* param_v);


/**
 *
 * @brief Reads sesman [Xvnc] configuration section
 * @param file configuration file descriptor
 * @param cs pointer to a config_sesman struct
 * @param param_n parameter name list
 * @param param_v parameter value list
 * @return 0 on success, 1 on failure
 *
 */
int DEFAULT_CC
config_read_vnc_params(int file, struct config_sesman* cs, struct list* param_n,
                       struct list* param_v);


/**
 *
 * @brief Reads sesman [Xdmx] configuration section
 * @param file configuration file descriptor
 * @param cs pointer to a config_sesman struct
 * @param param_n parameter name list
 * @param param_v parameter value list
 * @return 0 on success, 1 on failure
 *
 */
int DEFAULT_CC
config_read_dmx_params(int file, struct config_sesman* cs, struct list* param_n,
                       struct list* param_v);
/**
 *
 * @brief Reads sesman [XdmxXKB] configuration section
 * @param file configuration file descriptor
 * @param cs pointer to a config_sesman struct
 * @param param_n parameter name list
 * @param param_v parameter value list
 * @return 0 on success, 1 on failure
 *
 */
int DEFAULT_CC
config_read_dmx_xkb_params(int file, struct config_sesman* cs, struct list* param_n,
                       struct list* param_v);

/**
 *
 * @brief Reads sesman [XdmxBackend] configuration section
 * @param file configuration file descriptor
 * @param cs pointer to a config_sesman struct
 * @param param_n parameter name list
 * @param param_v parameter value list
 * @return 0 on success, 1 on failure
 *
 */
int DEFAULT_CC
config_read_dmx_backend_params(int file, struct config_sesman* cs, struct list* param_n,
                       struct list* param_v);
#endif

