include $(top_srcdir)/globus_automake_pre
include $(top_srcdir)/globus_automake_pre_top

SUBDIRS= \
	pkgdata \
	doxygen

globusperldir = $(GLOBUS_LOCATION)/lib/perl/Globus
globusperl_DATA = URL.pm

Scripts= \
	TESTS.pl \
	FtpTestLib.pm \
    globus-ftp-client-dir-test.pl \
    globus-ftp-client-run-backend-tests.pl  \
	globus-ftp-client-bad-buffer-test.pl \
	globus-ftp-client-create-destroy-test.pl \
	globus-ftp-client-exist-test.pl \
	globus-ftp-client-extended-get-test.pl \
	globus-ftp-client-extended-put-test.pl \
	globus-ftp-client-extended-transfer-test.pl \
	globus-ftp-client-lingering-get-test.pl \
	globus-ftp-client-multiple-block-get-test.pl \
	globus-ftp-client-partial-get-test.pl \
	globus-ftp-client-partial-put-test.pl \
	globus-ftp-client-partial-transfer-test.pl \
	globus-ftp-client-plugin-test.pl \
	globus-ftp-client-run-tests.pl \
	globus-ftp-client-get-test.pl \
	globus-ftp-client-caching-get-test.pl \
	globus-ftp-client-put-test.pl \
	globus-ftp-client-size-test.pl \
	globus-ftp-client-transfer-test.pl \
	globus-ftp-client-caching-transfer-test.pl \
	globus-ftp-client-user-auth-test.pl

test_SCRIPTS = $(Scripts)

Data = \
	dc31a685.0 \
	dc31a685.signing_policy \
	testcred.pem

test_DATA = $(Data) 

EXTRA_DIST = $(Scripts) $(Data) $(globusperl_DATA)

LibHeaders = \
	globus_ftp_client_test_abort_plugin.h \
	globus_ftp_client_test_pause_plugin.h \
	globus_ftp_client_test_restart_plugin.h \
	globus_ftp_client_test_perf_plugin.h \
	globus_ftp_client_test_throughput_plugin.h \
	globus_ftp_client_test_common.h
LibSources = \
	globus_ftp_client_test_abort_plugin.c \
	globus_ftp_client_test_pause_plugin.c \
	globus_ftp_client_test_restart_plugin.c \
	globus_ftp_client_test_perf_plugin.c \
	globus_ftp_client_test_throughput_plugin.c \
	globus_ftp_client_test_common.c

noinst_LTLIBRARIES = libglobus_ftp_client_test_$(GLOBUS_FLAVOR_NAME).la
libglobus_ftp_client_test___GLOBUS_FLAVOR_NAME__la_SOURCES = \
	$(LibHeaders) \
	$(LibSources)

test_PROGRAMS= \
	globus-ftp-client-ascii-list-test \
	globus-ftp-client-ascii-verbose-list-test \
	globus-ftp-client-ascii-machine-list-test \
	globus-ftp-client-bad-buffer-test \
	globus-ftp-client-cache-all-test \
	globus-ftp-client-create-destroy-test \
	globus-ftp-client-cksm-test \
	globus-ftp-client-chmod-test \
	globus-ftp-client-delete-test \
	globus-ftp-client-exist-test \
	globus-ftp-client-extended-get-test \
	globus-ftp-client-extended-get-caching-test \
	globus-ftp-client-extended-put-test \
	globus-ftp-client-extended-transfer-test \
	globus-ftp-client-feat-test \
	globus-ftp-client-lingering-get-test \
	globus-ftp-client-mlst-test \
	globus-ftp-client-mkdir-test \
	globus-ftp-client-modification-time-test \
	globus-ftp-client-move-test \
	globus-ftp-client-multiget-test \
	globus-ftp-client-multiple-bad-buffer-test \
	globus-ftp-client-multiple-block-get-test \
	globus-ftp-client-multiple-block-put-test \
	globus-ftp-client-partial-get-test \
	globus-ftp-client-partial-put-test \
	globus-ftp-client-partial-read-all-test \
	globus-ftp-client-partial-transfer-test \
	globus-ftp-client-plugin-test \
	globus-ftp-client-read-all-test \
	globus-ftp-client-rmdir-test \
	globus-ftp-client-size-test \
	globus-ftp-client-get-test \
	globus-ftp-client-caching-get-test \
	globus-ftp-client-put-test \
	globus-ftp-client-transfer-test \
	globus-ftp-client-caching-transfer-test \
	globus-ftp-client-pipelined-transfer-test \
	globus-ftp-client-user-auth-test \
    globus-ftp-client-restart-marker-test
    

INCLUDES = $(GPT_INCLUDES)
LDADD = libglobus_ftp_client_test_$(GLOBUS_FLAVOR_NAME).la $(GPT_PGM_LINKS)

globus_ftp_client_create_destroy_test_SOURCES = globus_ftp_client_create_destroy_test.c $(LibHeaders)
globus_ftp_client_create_destroy_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_get_test_SOURCES = globus_ftp_client_get_test.c $(LibHeaders)
globus_ftp_client_get_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_put_test_SOURCES = globus_ftp_client_put_test.c $(LibHeaders)
globus_ftp_client_put_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_caching_get_test_SOURCES = globus_ftp_client_caching_get_test.c $(LibHeaders)
globus_ftp_client_caching_get_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_multiple_block_get_test_SOURCES = globus_ftp_client_multiple_block_get_test.c $(LibHeaders)
globus_ftp_client_multiple_block_get_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_ascii_list_test_SOURCES = globus_ftp_client_ascii_list_test.c $(LibHeaders)
globus_ftp_client_ascii_list_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_bad_buffer_test_SOURCES = globus_ftp_client_bad_buffer_test.c $(LibHeaders)
globus_ftp_client_bad_buffer_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_multiple_bad_buffer_test_SOURCES = globus_ftp_client_multiple_bad_buffer_test.c $(LibHeaders)
globus_ftp_client_multiple_bad_buffer_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_transfer_test_SOURCES = globus_ftp_client_transfer_test.c $(LibHeaders)
globus_ftp_client_transfer_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_lingering_get_test_SOURCES = globus_ftp_client_lingering_get_test.c $(LibHeaders)
globus_ftp_client_lingering_get_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_multiple_block_put_test_SOURCES = globus_ftp_client_multiple_block_put_test.c $(LibHeaders)
globus_ftp_client_multiple_block_put_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_caching_transfer_test_SOURCES = globus_ftp_client_caching_transfer_test.c $(LibHeaders)
globus_ftp_client_caching_transfer_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_pipelined_transfer_test_SOURCES = globus_ftp_client_pipelined_transfer_test.c $(LibHeaders)
globus_ftp_client_pipelined_transfer_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_partial_get_test_SOURCES = globus_ftp_client_partial_get_test.c $(LibHeaders)
globus_ftp_client_partial_get_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_partial_put_test_SOURCES = globus_ftp_client_partial_put_test.c $(LibHeaders)
globus_ftp_client_partial_put_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_extended_get_test_SOURCES = globus_ftp_client_extended_get_test.c $(LibHeaders)
globus_ftp_client_extended_get_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_user_auth_test_SOURCES = globus_ftp_client_user_auth_test.c $(LibHeaders)
globus_ftp_client_user_auth_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_extended_put_test_SOURCES = globus_ftp_client_extended_put_test.c $(LibHeaders)
globus_ftp_client_extended_put_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_partial_transfer_test_SOURCES = globus_ftp_client_partial_transfer_test.c $(LibHeaders)
globus_ftp_client_partial_transfer_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_multiget_test_SOURCES = globus_ftp_client_multiget_test.c $(LibHeaders)
globus_ftp_client_multiget_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_extended_transfer_test_SOURCES = globus_ftp_client_extended_transfer_test.c $(LibHeaders)
globus_ftp_client_extended_transfer_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_extended_get_caching_test_SOURCES = globus_ftp_client_extended_get_caching_test.c $(LibHeaders)
globus_ftp_client_extended_get_caching_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_read_all_test_SOURCES = globus_ftp_client_read_all_test.c $(LibHeaders)
globus_ftp_client_read_all_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_restart_marker_test_SOURCES = globus_ftp_client_restart_marker_test.c $(LibHeaders)
globus_ftp_client_restart_marker_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_chmod_test_SOURCES = globus_ftp_client_chmod_test.c $(LibHeaders)
globus_ftp_client_chmod_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_cksm_test_SOURCES = globus_ftp_client_cksm_test.c $(LibHeaders)
globus_ftp_client_cksm_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_delete_test_SOURCES = globus_ftp_client_delete_test.c $(LibHeaders)
globus_ftp_client_delete_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_mkdir_test_SOURCES = globus_ftp_client_mkdir_test.c $(LibHeaders)
globus_ftp_client_mkdir_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_rmdir_test_SOURCES = globus_ftp_client_rmdir_test.c $(LibHeaders)
globus_ftp_client_rmdir_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_move_test_SOURCES = globus_ftp_client_move_test.c $(LibHeaders)
globus_ftp_client_move_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_mlst_test_SOURCES = globus_ftp_client_mlst_test.c $(LibHeaders)
globus_ftp_client_mlst_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_ascii_verbose_list_test_SOURCES = globus_ftp_client_ascii_verbose_list_test.c $(LibHeaders)
globus_ftp_client_ascii_verbose_list_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_ascii_machine_list_test_SOURCES = globus_ftp_client_ascii_machine_list_test.c $(LibHeaders)
globus_ftp_client_ascii_machine_list_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_cache_all_test_SOURCES = globus_ftp_client_cache_all_test.c $(LibHeaders)
globus_ftp_client_cache_all_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_exist_test_SOURCES = globus_ftp_client_exist_test.c $(LibHeaders)
globus_ftp_client_exist_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_feat_test_SOURCES = globus_ftp_client_feat_test.c $(LibHeaders)
globus_ftp_client_feat_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_modification_time_test_SOURCES = globus_ftp_client_modification_time_test.c $(LibHeaders)
globus_ftp_client_modification_time_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_size_test_SOURCES = globus_ftp_client_size_test.c $(LibHeaders)
globus_ftp_client_size_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_plugin_test_SOURCES = globus_ftp_client_plugin_test.c $(LibHeaders)
globus_ftp_client_plugin_test_LDFLAGS = $(GPT_LDFLAGS)

globus_ftp_client_partial_read_all_test_SOURCES = globus_ftp_client_partial_read_all_test.c $(LibHeaders)
globus_ftp_client_partial_read_all_test_LDFLAGS = $(GPT_LDFLAGS)

include $(top_srcdir)/globus_automake_post
include $(top_srcdir)/globus_automake_post_top
