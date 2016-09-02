sbin_SCRIPTS = \
	grid-mapfile-add-entry \
	grid-mapfile-check-consistency \
	grid-mapfile-delete-entry

man_MANS =  grid-mapfile-add-entry.8 \
            grid-mapfile-check-consistency.8 \
            grid-mapfile-delete-entry.8

EXTRA_DIST = $(man_MANS) \
        grid-mapfile-add-entry.txt \
        grid-mapfile-check-consistency.txt \
        grid-mapfile-delete-entry.txt \
        grid-mapfile-merge.txt

if BUILD_MANPAGES
SUFFIXES = .txt .8

.txt.8:
	$(A2X) -d manpage -f manpage $<

MAINTAINERCLEANFILES = $(man_MANS)
endif
