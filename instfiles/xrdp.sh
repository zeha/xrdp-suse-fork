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
XRDP_BIN=$SBINDIR/xrdp
XRDPSESMAN_BIN=$SBINDIR/xrdp-sesman
LOG=/dev/null
CFGDIR=/etc/xrdp

# Check for missing binaries (stale symlinks should not happen)
# Note: Special treatment of stop for LSB conformance
test -x $XRDP_BIN || { echo "$XRDP_BIN not installed";
	if [ "$1" = "stop" ]; then exit 0;
	else exit 5; fi; }
test -x $XRDPSESMAN_BIN || { echo "$XRDPSESMAN_BIN not installed";
	if [ "$1" = "stop" ]; then exit 0;
	else exit 5; fi; }

# Check for existence of needed config file and read it
XRDP_CONFIG=$CFGDIR/startwm.sh
test -r $XRDP_CONFIG || { echo "$XRDP_CONFIG not existing";
	if [ "$1" = "stop" ]; then exit 0;
	else exit 6; fi; }

# Source LSB init functions
# providing start_daemon, killproc, pidofproc,
# log_success_msg, log_failure_msg and log_warning_msg.
# This is currently not used by UnitedLinux based distributions and
# not needed for init scripts for UnitedLinux only. If it is used,
# the functions from rc.status should not be sourced or used.
#. /lib/lsb/init-functions

# Shell functions sourced from /etc/rc.status:
#      rc_check         check and set local and overall rc status
#      rc_status        check and set local and overall rc status
#      rc_status -v     be verbose in local rc status and clear it afterwards
#      rc_status -v -r  ditto and clear both the local and overall rc status
#      rc_status -s     display "skipped" and exit with status 3
#      rc_status -u     display "unused" and exit with status 3
#      rc_failed        set local and overall rc status to failed
#      rc_failed <num>  set local and overall rc status to <num>
#      rc_reset         clear both the local and overall rc status
#      rc_exit          exit appropriate to overall rc status
#      rc_active        checks whether a service is activated by symlinks
. /etc/rc.status

# Reset status of this service
rc_reset

# Return values acc. to LSB for all commands but status:
# 0	  - success
# 1       - generic or unspecified error
# 2       - invalid or excess argument(s)
# 3       - unimplemented feature (e.g. "reload")
# 4       - user had insufficient privileges
# 5       - program is not installed
# 6       - program is not configured
# 7       - program is not running
# 8--199  - reserved (8--99 LSB, 100--149 distrib, 150--199 appl)
#
# Note that starting an already running service, stopping
# or restarting a not-running service as well as the restart
# with force-reload (in case signaling is not supported) are
# considered a success.

case "$1" in
  start)
    echo -n "Starting xrdp"

    ## Start daemon with startproc(8). If this fails
    ## the return value is set appropriately by startproc.
    /sbin/startproc $XRDPSESMAN_BIN > /dev/null
    /sbin/startproc $XRDP_BIN > /dev/null

    # Remember status and be verbose
    rc_status -v
    ;;
  stop)
    echo -n "Shutting down xrdp "

    ## Stop daemon with killproc(8) and if this fails
    ## killproc sets the return value according to LSB.

    /sbin/killproc -TERM $XRDP_BIN
    /sbin/killproc -TERM $XRDPSESMAN_BIN

    # Remember status and be verbose
    rc_status -v
    ;;
  try-restart|condrestart)
    ## Do a restart only if the service was active before.
    ## Note: try-restart is now part of LSB (as of 1.9).
    ## RH has a similar command named condrestart.
    if test "$1" = "condrestart"; then
	echo "${attn} Use try-restart ${done}(LSB)${attn} rather than condrestart ${warn}(RH)${norm}"
    fi
    $0 status
    if test $? = 0; then
	$0 restart
    else
	rc_reset	# Not running is not a failure.
    fi
    # Remember status and be quiet
    rc_status
    ;;
  force-reload|reload|restart)
    ## Stop the service and regardless of whether it was
    ## running or not, start it again.
    $0 stop
    $0 start

    # Remember status and be quiet
    rc_status
    ;;
  status)
    echo -n "Checking for service xrdp "
    ## Check status with checkproc(8), if process is running
    ## checkproc will return with exit status 0.

    # Return value is slightly different for the status command:
    # 0 - service up and running
    # 1 - service dead, but /var/run/  pid  file exists
    # 2 - service dead, but /var/lock/ lock file exists
    # 3 - service not running (unused)
    # 4 - service status unknown :-(
    # 5--199 reserved (5--99 LSB, 100--149 distro, 150--199 appl.)

    # NOTE: checkproc returns LSB compliant status values.
    /sbin/checkproc $XRDP_BIN
    /sbin/checkproc $XRDPSESMAN_BIN
    # NOTE: rc_status knows that we called this init script with
    # "status" option and adapts its messages accordingly.
    rc_status -v
    ;;
  probe)
    ## Optional: Probe for the necessity of a reload, print out the
    ## argument to this init script which is required for a reload.
    ## Note: probe is not (yet) part of LSB (as of 1.9)
    ;;
  *)
    echo "Usage: $0 {start|stop|status|try-restart|restart|force-reload|reload|probe}"
    exit 1
esac
rc_exit
