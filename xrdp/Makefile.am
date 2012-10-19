INCLUDES = \
  -I$(top_srcdir)/common \
  -I$(top_srcdir)/libxrdp \
  $(AVAHI_CFLAGS)

sbin_PROGRAMS = \
  xrdp

xrdp_SOURCES = \
  funcs.c \
  lang.c \
  xrdp_bitmap.c \
  xrdp.c \
  xrdp_cache.c \
  xrdp_font.c \
  xrdp_listen.c \
  xrdp_login_wnd.c \
  xrdp_mm.c \
  xrdp_painter.c \
  xrdp_process.c \
  xrdp_region.c \
  xrdp_wm.c \
  xrdp_avahi.c

xrdp_LDADD = \
  $(top_srcdir)/common/libcommon.la \
  $(top_srcdir)/libxrdp/libxrdp.la \
  $(AVAHI_LIBS)

xrdpsysconfdir=$(sysconfdir)/xrdp

xrdpsysconf_DATA = \
  xrdp.ini \
  rsakeys.ini

pkgdata_DATA = \
  ad256.bmp \
  xrdp256.bmp \
  tile256.bmp \
  opensuse256.bmp \
  rdc256.bmp \
  sans-10.fv1 \
  tahoma-10.fv1 \
  cursor0.cur \
  cursor1.cur

# must be tab below
install-data-hook:
	chmod 600 $(DESTDIR)$(sysconfdir)/xrdp/rsakeys.ini
