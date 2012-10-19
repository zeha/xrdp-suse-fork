#!/bin/bash
#
# startwm.sh for SuSE Linux
#

. /etc/sysconfig/windowmanager

test -z "$DEFAULT_WM" && DEFAULT_WM=twm
WINDOWMANAGER="`type -p ${DEFAULT_WM##*/}`"
unset DEFAULT_WM

exec /etc/X11/xdm/Xsession $WINDOWMANAGER

exit 1
