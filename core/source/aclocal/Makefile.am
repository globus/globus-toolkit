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
	@file="globus_automake_pre"; \
	if test -f $$file; then \
		rm $$file; \
	fi; \
	touch $$file; \
	for p in $(PRE_FILES); do \
		cat $$p >> $$file; \
	done

globus_automake_post: $(POST_FILES)
	@file="globus_automake_post"; \
	if test -f $$file; then \
		rm $$file; \
	fi; \
	touch $$file; \
	for p in $(POST_FILES); do \
		cat $$p >> $$file; \
	done

globus_automake_pre_top: $(PRE_TOP_FILES)
	@file="globus_automake_pre_top"; \
	if test -f $$file; then \
		rm $$file; \
	fi; \
	touch $$file; \
	for p in $(PRE__TOP_FILES); do \
		cat $$p >> $$file; \
	done

globus_automake_post_top: $(POST_TOP_FILES)
	@file="globus_automake_post_top"; \
	if test -f $$file; then \
		rm $$file; \
	fi; \
	touch $$file; \
	for p in $(POST_TOP_FILES); do \
		cat $$p >> $$file; \
	done
