
SUBDIRS = \
  pam.d

startscriptdir=$(sysconfdir)/xrdp

startscript_DATA = \
  xrdp.sh

# must be tab below
install-data-hook:
	chmod 755 $(DESTDIR)$(sysconfdir)/xrdp/xrdp.sh
	mkdir -p $(DESTDIR)/etc/init.d
	$(LN_S) $(sysconfdir)/xrdp/xrdp.sh $(DESTDIR)/etc/init.d/xrdp
#	$(DESTDIR)$(bindir)/xrdp-keygen xrdp $(DESTDIR)$(sysconfdir)/xrdp/rsakeys.ini
