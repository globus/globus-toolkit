include $(top_srcdir)/aclocal/automake_targets

PRE_FILES = automake_targets \
	automake_config

POST_FILES = 
PRE_TOP_FILES =
POST_TOP_FILES = automake_top_rules

aclocal_DATA = globus_package.m4 \
	globus_automake_pre \
	globus_automake_post \
	globus_automake_pre_top \
	globus_automake_post_top \
	acnetworking.m4 \
	acdoxygen.m4 \
	doxygen_Makefile.am \
	Doxyfile.in \
	Doxyfile-internal.in

EXTRA_DIST = $(PRE_FILES) \
	$(POST_FILES) \
	$(PRE_TOP_FILES) \
	$(POST_TOP_FILES)

globus_automake_pre: $(PRE_FILES)
	file="globus_automake_pre"; \
	list="$(PRE_FILES)"
	if test -f $$file; then \
		rm $$file; \
	fi; \
	touch $$file; \
	for p in $$list; do \
		cat $$p >> $$file; \
	done

globus_automake_post: $(POST_FILES)
	file="globus_automake_post"; \
	list="$(POST_FILES)"
	if test -f $$file; then \
		rm $$file; \
	fi; \
	touch $$file; \
	for p in $$list; do \
		cat $$p >> $$file; \
	done

globus_automake_pre_top: $(PRE_TOP_FILES)
	file="globus_automake_pre_top"; \
	list="$(PRE__TOP_FILES)"
	if test -f $$file; then \
		rm $$file; \
	fi; \
	touch $$file; \
	for p in $$list; do \
		cat $$p >> $$file; \
	done

globus_automake_post_top: $(POST_TOP_FILES)
	file="globus_automake_post_top"; \
	list="$(POST_TOP_FILES)"
	if test -f $$file; then \
		rm $$file; \
	fi; \
	touch $$file; \
	for p in $$list; do \
		cat $$p >> $$file; \
	done
