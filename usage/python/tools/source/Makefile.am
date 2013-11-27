AUTOMAKE_OPTIONS = foreign

pylibdir = $(libdir)/python/usage
usagevardir = $(localstatedir)/usage

sbin_SCRIPTS = $(usage_scripts)
pylib_DATA = $(usage_modules)
pkgdata_DATA = usage-tables.sql index.html
sysconf_DATA = globus-usage-tools.conf
usagevar_DATA = 
man_MANS = globus-usage-collector.8 globus-usage-uploader.8

usage_scripts = globus-usage-collector globus-usage-uploader
usage_modules = \
    cusagepacket.py \
    cwscorev1packet.py \
    cwscorev2packet.py \
    dnscache.py \
    drspacket.py \
    gram4packet.py \
    gram5packet.py \
    gridftppacket.py \
    iptimemonitorpacket.py \
    javawscorev1packet.py \
    javawscorev2packet.py \
    javawscorev3packet.py \
    mdsaggregatorpacket.py \
    mpigpacket.py \
    ogsadaipacket.py \
    packetfile.py \
    packetparser.py \
    rftpacket.py \
    rlspacket.py \
    myproxypacket.py \
    usageconfig.py \
    usagepacket.py

EXTRA_DIST = $(usage_scripts) $(usage_modules) $(man_MANS) $(pkgdata_DATA) \
        admin.xml \
        configuration.xml \
        globus-usage-collector.xml \
        globus-usage-uploader.xml \
        manual.xml \
        globus-usage-tools.conf.in \
        xinclude.mod \
        $(doc_data)

AT=@
globus-usage-tools.conf: globus-usage-tools.conf.in
	sed -e "s|$(AT)localstatedir$(AT)|${localstatedir}|" < $< > $@

if BUILD_MANPAGES
SUFFIXES = .xml .8

.xml.8:
	$(XMLLINT) --nonet --dtdvalid $(DOCBOOK_DTD) $< > /dev/null
	$(XSLTPROC) --nonet $(MAN_XSL) $<
CLEANFILES = $(man_MANS)
endif

