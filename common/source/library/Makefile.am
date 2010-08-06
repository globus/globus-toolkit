include $(top_srcdir)/globus_automake_pre

Sources= \
	globus_args.c \
	globus_args.h \
	globus_callback.c \
	globus_callback_nothreads.c \
	globus_callback_threads.c \
	globus_callback.h \
	globus_options.c \
	globus_options.h \
	globus_i_callback.h \
	globus_common_paths.c \
	globus_common.c \
	globus_debug.c \
	globus_debug.h \
	globus_error.c \
	globus_error.h \
	globus_error_hierarchy.c \
	globus_error_hierarchy.h \
	globus_error_generic.c \
	globus_i_error_generic.c \
	globus_error_generic.h \
	globus_i_error_generic.h \
	globus_error_errno.c \
	globus_i_error_errno.c \
	globus_error_errno.h \
	globus_i_error_errno.h \
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
	globus_logging.c \
	globus_logging.h \
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
	globus_range_list.c \
	globus_range_list.h \
	globus_release.h \
	globus_strptime.c \
	globus_strptime.h \
	globus_symboltable.c \
	globus_symboltable.h \
	globus_thread_common.c \
	globus_thread_common.h \
	globus_thread.c \
	globus_thread.h \
	globus_thread_pool.c \
	globus_thread_pool.h \
	globus_thread_rw_mutex.c \
	globus_thread_rw_mutex.h \
	globus_thread_rmutex.c \
	globus_thread_rmutex.h \
	globus_tilde_expand.c \
	globus_time.c \
	globus_tilde_expand.h \
	globus_time.h \
	globus_url.c \
	globus_url.h \
    globus_states.h \
    globus_states.c \
	globus_error_string.c \
	globus_error_string.h \
	globus_extension.c \
	globus_extension.h \
	globus_common_include.h \
	globus_uuid.c \
	globus_uuid.h \
    freeaddrinfo.c \
    gai_strerror.c \
    getaddrinfo.c \
    getnameinfo.c \
    inet_addr.c \
    inet_pton.c \
    globus_thread_none.c \
    globus_netos_libc.h

flavorinclude_HEADERS = \
        $(OS_HEADERS) \
	globus_release.h \
	globus_module.h \
	globus_url.h \
    globus_states.h \
	globus_list.h \
	globus_hashtable.h \
	globus_fifo.h \
	globus_symboltable.h \
	globus_logging.h    \
	globus_object.h \
	globus_object_hierarchy.h \
	globus_error.h \
	globus_error_hierarchy.h \
	globus_error_string.h \
	globus_error_generic.h \
	globus_error_errno.h \
	globus_time.h \
	globus_thread_pool.h \
	globus_handle_table.h \
	globus_callback.h \
	globus_options.h \
	globus_memory.h \
	globus_print.h \
	globus_priority_q.h \
	globus_range_list.h \
	globus_tilde_expand.h \
	globus_libc.h \
	globus_debug.h \
	globus_args.h \
	globus_strptime.h \
	globus_thread_common.h \
	globus_thread_rw_mutex.h \
	globus_thread_rmutex.h \
	globus_extension.h \
	globus_common.h \
	globus_common_include.h \
        globus_thread.h \
	globus_uuid.h


CFLAGS += -DGLOBUS_PREFIX=\"${prefix}\" -DGLOBUS_LIBDIR=\"${libdir}\"
pthreads_sources = globus_thread_pthreads.h globus_thread_pthreads.c
windowsthreads_sources = globus_thread_windows.h globus_thread_windows.c

thread_libs = 
if BUILD_PTHREADS
thread_libs += libglobus_thread_pthread.la
endif
if BUILD_WINDOWS_THREADS
thread_libs += libglobus_thread_windows.la
endif

lib_LTLIBRARIES = libglobus_common_$(GLOBUS_FLAVOR_NAME).la $(thread_libs)

INCLUDES = @GPT_INCLUDES@

libglobus_common___GLOBUS_FLAVOR_NAME__la_LIBADD = @GPT_LIB_LINKS@
libglobus_common___GLOBUS_FLAVOR_NAME__la_SOURCES = $(Sources)
libglobus_common___GLOBUS_FLAVOR_NAME__la_LDFLAGS = @GPT_LDFLAGS@

if BUILD_PTHREADS
libglobus_thread_pthread_la_LIBADD = libglobus_common_$(GLOBUS_FLAVOR_NAME).la @GPT_LIB_LINKS@ @PTHREAD_LIBS@
libglobus_thread_pthread_la_SOURCES = globus_thread_pthreads.c globus_thread_pthreads.h
libglobus_thread_pthread_la_LDFLAGS = @GPT_LDFLAGS@ -module
endif

if BUILD_WINDOWS_THREADS
libglobus_thread_windows_la_LIBADD = libglobus_common_$(GLOBUS_FLAVOR_NAME).la @GPT_LIB_LINKS@
libglobus_thread_windows_la_SOURCES = globus_thread_windows.c globus_thread_windows.h
libglobus_thread_windows_la_LDFLAGS = @GPT_LDFLAGS@ -module
endif

EXTRA_DIST = \
	globus_callback_nothreads.c \
	globus_callback_threads.c \
        $(pthreads_sources) \
        $(windowsthreads_sources)

EXTRA_HEADERS = \
        globus_netos_dir.h

include $(top_srcdir)/globus_automake_post
