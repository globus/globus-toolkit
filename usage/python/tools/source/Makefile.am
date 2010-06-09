include $(top_srcdir)/globus_automake_pre

SUBDIRS = pkgdata

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
usage_manual = globus-usage-collector.8 globus-usage-uploader.8

sbin_SCRIPTS = $(usage_scripts)
pylibdir = $(libdir)/python/usage
pylib_DATA = $(usage_modules)
pkgdata_DATA = usage-tables.sql index.html
sysconf_DATA = globus-usage-tools.conf
usagevardir = $(localstatedir)/usage
usagevar_DATA = 

## maneight = [ DATA ]
maneightdir = $(mandir)/man8
maneight_DATA = $(usage_manual)

EXTRA_DIST = $(usage_scripts) $(usage_modules) $(usage_manual) $(pkgdata_DATA) \
        manual.xml \
        globus-usage-tools.conf.in \
        $(doc_data)

AT=@
globus-usage-tools.conf: globus-usage-tools.conf.in
	sed -e "s|$(AT)localstatedir$(AT)|${localstatedir}|" < $< > $@

include $(top_srcdir)/globus_automake_post
