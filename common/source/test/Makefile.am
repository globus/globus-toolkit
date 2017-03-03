AM_CPPFLAGS = -I$(top_srcdir)/library $(PACKAGE_DEP_CFLAGS) 
LDADD = ../library/libglobus_common.la

thread_model_tests = 
if BUILD_WINDOWS_THREADS
thread_model_tests += thread_test_windows
thread_test_windows_SOURCES = thread_test.c
thread_test_windows_CPPFLAGS = -DTHREAD_MODEL="\"windows\"" $(AM_CPPFLAGS)
thread_test_windows_LDFLAGS = -dlopen ../library/libglobus_thread_windows.la
endif

if BUILD_PTHREADS
thread_model_tests += thread_test_pthread
thread_test_pthread_SOURCES = thread_test.c
thread_test_pthread_CPPFLAGS = -DTHREAD_MODEL="\"pthread\"" $(AM_CPPFLAGS)
thread_test_pthread_LDFLAGS = -dlopen ../library/libglobus_thread_pthread.la
endif

check_PROGRAMS = \
    error_test \
    fifo_test \
    globus_args_scan_test \
    globus_error_construct_string_test \
    globus_eval_path_test \
    globus_error_errno_test \
    globus_libc_setenv_test \
    globus_location_test \
    globus_url_test \
    handle_table_test \
    hash_test \
    list_test \
    memory_test \
    module_test \
    off_t_test \
    poll_test \
    strptime_test \
    $(thread_model_tests) \
    timedwait_test \
    uuid_test

TESTS = $(check_PROGRAMS)
LOG_COMPILER = $(LIBTOOL)
AM_LOG_FLAGS = --mode=execute \
		$(thread_test_windows_LDFLAGS) \
		$(thread_test_pthread_LDFLAGS)

globus_location_test_CPPFLAGS = $(AM_CPPFLAGS) -DGLOBUS_LOCATION=\"$(prefix)\"
globus_eval_path_test_CPPFLAGS = $(AM_CPPFLAGS) \
	-Dprefix=\"$(prefix)\" \
        -Dexec_prefix=\"$(exec_prefix)\" \
        -Dsbindir=\"$(sbindir)\" \
        -Dbindir=\"$(bindir)\" \
        -Dlibdir=\"$(libdir)\" \
        -Dlibexecdir=\"$(libexecdir)\" \
        -Dincludedir=\"$(includedir)\" \
        -Ddatarootdir=\"$(datarootdir)\" \
        -Ddatadir=\"$(datadir)\" \
        -Dmandir=\"$(mandir)\" \
        -Dsysconfdir=\"$(sysconfdir)\" \
        -Dsharedstatedir=\"$(sharedstatedir)\" \
        -Dlocalstatedir=\"$(localstatedir)\" \
        -Dperlmoduledir=\"$(perlmoduledir)\"

EXTRA_DIST = globus_test_tap.h thread_test.c
