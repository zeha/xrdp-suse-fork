#!/bin/sh
# xrdp control script
# Written : 1-13-2006 - Mark Balliet - posicat@pobox.com
# maintaned by Jay Sorg
# chkconfig: 2345 11 89
# description: starts xrdp
#
### BEGIN INIT INFO
# Provides:          xrdp
# Required-Start:    $remote_fs
# Should-Start:      ypbind $syslog firstboot resmgr winbind acpid
# Should-Stop:       $null
# Required-Stop:     $null
# Default-Start:     5
# Default-Stop:
# Description:       Start the xrdp daemon
### END INIT INFO    

SBINDIR=/usr/sbin
LOG=/dev/null
CFGDIR=/etc/xrdp

if ! test -x $SBINDIR/xrdp
then
  echo "xrdp is not executable"
  exit 0
fi
if ! test -x $SBINDIR/xrdp-sesman
then
  echo "xrdp-sesman is not executable"
  exit 0
fi
if ! test -x $CFGDIR/startwm.sh
then
  echo "startwm.sh is not executable"
  exit 0
fi

xrdp_start()
{
  echo "Starting sesman daemon"
  $SBINDIR/xrdp-sesman >> $LOG
  echo "Starting xrdp daemon"
  $SBINDIR/xrdp >> $LOG
  return 0;
}

xrdp_stop()
{
  echo "Stopping xrdp daemon"
  $SBINDIR/xrdp --kill >> $LOG
  echo "Stopping sesman daemon"
  $SBINDIR/xrdp-sesman --kill >> $LOG
  return 0;
}

is_xrdp_running()
{
  ps u --noheading -C xrdp | grep -q -i $SBINDIR/xrdp
  if test $? -eq 0
  then
    return 1;
  else
    return 0;
  fi
}

is_sesman_running()
{
  ps u --noheading -C xrdp-sesman | grep -q -i $SBINDIR/xrdp-sesman
  if test $? -eq 0
  then
    return 1;
  else
    return 0;
  fi
}

check_up()
{
  # Cleanup : If sesman isn't running, but the pid exists, erase it.
  is_sesman_running
  if test $? -eq 0
  then
    if test -e /var/run/xrdp-sesman.pid
    then
      rm /var/run/xrdp-sesman.pid
    fi
  fi
  # Cleanup : If xrdp isn't running, but the pid exists, erase it.
  is_xrdp_running
  if test $? -eq 0
  then
    if test -e /var/run/xrdp.pid
    then
      rm /var/run/xrdp.pid
    fi
  fi
  return 0;
}

case "$1" in
  start)
    check_up
    is_xrdp_running
    if ! test $? -eq 0
    then
      echo "xrdp is already loaded"
      exit 1
    fi
    is_sesman_running
    if ! test $? -eq 0
    then
      echo "sesman is already loaded"
      exit 1
    fi
    xrdp_start
    ;;
  stop)
    check_up
    is_xrdp_running
    if test $? -eq 0
    then
      echo "xrdp is not loaded."
    fi
    is_sesman_running
    if test $? -eq 0
    then
      echo "sesman is not loaded."
    fi
    xrdp_stop
    ;;
  force-reload|restart)
    check_up
    xrdp_stop
    is_xrdp_running
    while ! test $? -eq 0
    do
      check_up
      sleep 1
      is_xrdp_running
    done
    xrdp_start
    ;;
  *)
    echo "Usage: xrdp.sh {start|stop|restart|force-reload}"
    exit 1
esac

exit 0
