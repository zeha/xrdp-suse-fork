INCLUDES = \
  -I$(top_srcdir)/common \
  -I$(top_srcdir)/xrdp \
  -I$(top_srcdir)/libxrdp \
  $(DBUS_CFLAGS) \
  $(XAU_CFLAGS)


lib_LTLIBRARIES = \
  libdmx.la

libdmx_la_SOURCES = dmx.c

libdmx_la_LIBADD = \
  $(top_srcdir)/common/libcommon.la \
  $(DBUS_LIBS) \
  $(XAU_LIBS)
