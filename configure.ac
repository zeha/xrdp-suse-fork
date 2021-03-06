# Process this file with autoconf to produce a configure script

AC_PREREQ(2.59)
AC_INIT([xrdp], [0.5.0], [xrdp-devel@lists.sourceforge.net])
AC_CONFIG_HEADERS([config_ac.h:config_ac-h.in])
AM_INIT_AUTOMAKE([1.6 foreign])
AC_PROG_CC
AC_C_CONST
AC_PROG_LIBTOOL
PKG_CHECK_MODULES(AVAHI, avahi-client >= 0.6.4)
AC_ARG_ENABLE(nopam, AS_HELP_STRING([--enable-nopam],
              [Build no PAM support (default: no)]),
              [nopam=true], [nopam=false])
AM_CONDITIONAL(SESMAN_NOPAM, [test x$nopam = xtrue])
AC_ARG_ENABLE(kerberos, AS_HELP_STRING([--enable-kerberos],
              [Build kerberos support (default: no)]),
              [kerberos=true], [kerberos=false])
AM_CONDITIONAL(SESMAN_KERBEROS, [test x$kerberos = xtrue])
AC_ARG_ENABLE(pamuserpass, AS_HELP_STRING([--enable-pamuserpass],
              [Build pam userpass support (default: no)]),
              [pamuserpass=true], [pamuserpass=false])
AM_CONDITIONAL(SESMAN_PAMUSERPASS, [test x$pamuserpass = xtrue])
PKG_CHECK_MODULES(DBUS, dbus-1)
PKG_CHECK_MODULES(XAU, xau)
PKG_CHECK_MODULES(XCB, xcb)
libdir="${libdir}/xrdp";
AC_DEFINE_UNQUOTED([XRDP_LIB_PATH], ["${libdir}"], [xrdp lib dir])
if test "x${prefix}" = "xNONE" ; then
sysconfdir="/etc/";
else
AC_DEFINE_UNQUOTED([XRDP_CFG_PATH], ["${sysconfdir}/xrdp"], [xrdp config dir])
AC_DEFINE_UNQUOTED([XRDP_CFG_FILE], ["${sysconfdir}/xrdp/xrdp.ini"], [xrdp config file])
AC_DEFINE_UNQUOTED([XRDP_KEY_FILE], ["${sysconfdir}/xrdp/rsakeys.ini"], [xrdp key file])
AC_DEFINE_UNQUOTED([XRDP_KEYMAP_FILE], ["${sysconfdir}/xrdp/km-%4.4x.ini"], [xrdp keymap file])
AC_DEFINE_UNQUOTED([XRDP_PID_FILE], ["${localstatedir}/run/xrdp.pid"], [xrdp pid file])
AC_DEFINE_UNQUOTED([XRDP_SBIN_PATH], ["${prefix}/sbin"], [xrdp sbin dir])
AC_DEFINE_UNQUOTED([XRDP_SHARE_PATH], ["${prefix}/share/xrdp"], [xrdp share dir])
AC_DEFINE_UNQUOTED([SESMAN_PID_FILE], ["${localstatedir}/run/sesman.pid"], [sesman pid file])
AC_DEFINE_UNQUOTED([SESMAN_CFG_FILE], ["${sysconfdir}/xrdp/sesman.ini"], [sesman config file])
fi
AC_CONFIG_FILES([Makefile
                 common/Makefile
                 vnc/Makefile
                 rdp/Makefile
                 libxrdp/Makefile
                 xup/Makefile
                 mc/Makefile
                 xrdp/Makefile
                 sesman/Makefile
                 sesman/libscp/Makefile
                 sesman/tools/Makefile
                 keygen/Makefile
                 docs/Makefile
                 docs/man/Makefile
                 instfiles/Makefile
                 instfiles/pam.d/Makefile
                 dmx/Makefile
])
#                 fontdump/Makefile
#                 xrdp/cursors/Makefile
#                 Xserver/hw/rdp/Makefile
AC_OUTPUT

# example of how to check for a struct in a header
#AC_CHECK_MEMBER([struct in6_addr.s6_addr],
#                [],
#                [AC_DEFINE(NO_ARPA_INET_H_IP6, 1, [for IPv6])],
#                [#include <arpa/inet.h>])
