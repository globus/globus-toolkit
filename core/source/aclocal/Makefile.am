include $(top_srcdir)/aclocal/automake_targets

PRE_FILES = automake_targets \
	automake_config

POST_FILES = 
PRE_TOP_FILES =
POST_TOP_FILES = automake_top_rules

AUTOMAKE_MACROS = \
	globus_package.m4 \
	acnetworking.m4 \
	acdoxygen.m4

DOXYGEN_FILES = \
	doxygen_Makefile.am \
	Doxyfile.in \
	Doxyfile-internal.in
	
aclocal_DATA = \
	$(AUTOMAKE_MACROS) \
	$(DOXYGEN_FILES) \
	globus_automake_pre \
	globus_automake_post \
	globus_automake_pre_top \
	globus_automake_post_top

EXTRA_DIST = $(PRE_FILES) \
	$(POST_FILES) \
	$(PRE_TOP_FILES) \
	$(POST_TOP_FILES) \
	$(AUTOMAKE_MACROS) \
	$(DOXYGEN_FILES)

globus_automake_pre: $(PRE_FILES)
	file="globus_automake_pre"; \
	list="$(PRE_FILES)"; \
	if test -f $$file; then \
		rm $$file; \
	fi; \
	touch $$file; \
	for p in $$list; do \
	    if test -f $$p; then \
		cat $$p >> $$file; \
	    elif test -f $(srcdir)/$$p ; then \
		cat $(srcdir)/$$p >> $$file; \
	    fi ; \
	done

globus_automake_post: $(POST_FILES)
	file="globus_automake_post"; \
	list="$(POST_FILES)" ; \
	if test -f $$file; then \
		rm $$file; \
	fi; \
	touch $$file; \
	for p in $$list; do \
	    if test -f $$p; then \
		cat $$p >> $$file; \
	    elif test -f $(srcdir)/$$p ; then \
		cat $(srcdir)/$$p >> $$file; \
	    fi ; \
	done

globus_automake_pre_top: $(PRE_TOP_FILES)
	file="globus_automake_pre_top"; \
	list="$(PRE_TOP_FILES)"; \
	if test -f $$file; then \
		rm $$file; \
	fi; \
	touch $$file; \
	for p in $$list; do \
	    if test -f $$p; then \
		cat $$p >> $$file; \
	    elif test -f $(srcdir)/$$p ; then \
		cat $(srcdir)/$$p >> $$file; \
	    fi ; \
	done

globus_automake_post_top: $(POST_TOP_FILES)
	file="globus_automake_post_top"; \
	list="$(POST_TOP_FILES)"; \
	if test -f $$file; then \
		rm $$file; \
	fi; \
	touch $$file; \
	for p in $$list; do \
	    if test -f $$p; then \
		cat $$p >> $$file; \
	    elif test -f $(srcdir)/$$p ; then \
		cat $(srcdir)/$$p >> $$file; \
	    fi ; \
	done
