include $(top_srcdir)/globus_automake_targets

Sources= \
	globus_args.c \
	globus_args.h \
	globus_callback.c \
	globus_callback.h \
	globus_cfifo.c \
	globus_cfifo.h \
	globus_common.c \
	globus_common_paths.c \
	globus_debug.c \
	globus_debug.h \
	globus_error.c \
	globus_error.h \
	globus_error_hierarchy.c \
	globus_error_hierarchy.h \
	globus_fifo.c \
	globus_fifo.h \
	globus_handle_table.c \
	globus_handle_table.h \
	globus_hashtable.c \
	globus_hashtable.h \
	globus_i_thread.h \
	globus_libc.c \
	globus_libc.h \
	globus_libc_setenv.c \
	globus_list.c \
	globus_list.h \
	globus_memory.c \
	globus_memory.h \
	globus_module.c \
	globus_module.h \
	globus_object.c \
	globus_object.h \
	globus_object_cache.c \
	globus_object_cache.h \
	globus_object_hierarchy.c \
	globus_object_hierarchy.h \
	globus_print.c \
	globus_print.h \
	globus_priority_q.c \
	globus_priority_q.h \
	globus_release.h \
	globus_strptime.c \
	globus_strptime.h \
	globus_symboltable.c \
	globus_symboltable.h \
	globus_thread_common.c \
	globus_thread_common.h \
	globus_thread_$(GLOBUS_THREADS).c \
	globus_thread_$(GLOBUS_THREADS).h \
	globus_thread_external.c \
	globus_thread_external.h \
	globus_thread_pool.c \
	globus_thread_pool.h \
	globus_tilde_expand.c \
	globus_time.c \
	globus_tilde_expand.h \
	globus_time.h \
	globus_timeq.c \
	globus_timeq.h \
	globus_url.c \
	globus_url.h \
	globus_error_string.c \
	globus_error_string.h

include_HEADERS = \
	globus_release.h \
	globus_module.h \
	globus_url.h \
	globus_list.h \
	globus_hashtable.h \
	globus_fifo.h \
	globus_cfifo.h \
	globus_symboltable.h \
	globus_object.h \
	globus_object_hierarchy.h \
	globus_error.h \
	globus_error_hierarchy.h \
	globus_time.h \
	globus_thread_pool.h \
	globus_handle_table.h \
	globus_callback.h \
	globus_timeq.h \
	globus_memory.h \
	globus_print.h \
	globus_tilde_expand.h \
	globus_libc.h \
	globus_debug.h \
	globus_args.h \
	globus_strptime.h \
	globus_thread_common.h

if WITHOUT_FLAVORS
lib_LTLIBRARIES = libglobus_common_$(GLOBUS_FLAVOR_NAME).la
else
lib_LTLIBRARIES = libglobus_uncommon_$(GLOBUS_FLAVOR_NAME).la
endif
INCLUDES = -I $(GLOBUS_INSTALL_PATH)/include/$(GLOBUS_FLAVOR_NAME) @GPT_
libglobus_common___GLOBUS_FLAVOR_NAME__la_LIBADD = @GPT_LIBS@

libglobus_common___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)

flavorinclude_HEADERS = \
	globus_common.h \
	globus_thread_$(GLOBUS_THREADS).h

EXTRA_DIST = \
	globus_thread_none.c \
	globus_thread_none.h \
	globus_thread_pthreads.c \
	globus_thread_pthreads.h \
	globus_thread_solaristhreads.c \
	globus_thread_solaristhreads.h \
	globus_thread_sproc.c \
	globus_thread_sproc.h


include $(top_srcdir)/globus_automake_rules