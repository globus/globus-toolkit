AM_CPPFLAGS = -I$(top_srcdir)/library $(PACKAGE_DEP_CFLAGS) 
LDADD = ../library/libglobus_common.la

if BUILD_WINDOWS_THREADS
thread_model_opt = -DTHREAD_MODEL="\"windows\""
thread_shobj = -dlopen ../library/libglobus_thread_windows.la
else
thread_model_opt = -DTHREAD_MODEL="\"pthread\""
thread_shobj = -dlopen ../library/libglobus_thread_pthread.la
endif

check_PROGRAMS = \
    error_test \
    fifo_test \
    globus_args_scan_test \
    globus_error_construct_string_test \
    globus_libc_setenv_test \
    globus_url_test \
    handle_table_test \
    hash_test \
    list_test \
    memory_test \
    module_test \
    off_t_test \
    poll_test \
    strptime_test \
    thread_test \
    timedwait_test \
    uuid_test
if !CROSS_COMPILING
TESTS = $(check_PROGRAMS)
endif

LOG_COMPILER = $(top_builddir)/libtool --mode=execute $(thread_shobj)

thread_test_CPPFLAGS = $(thread_model_opt) $(AM_CPPFLAGS)
thread_test_LDADD = $(thread_shobj) $(LDADD)
thread_test_LDFLAGS = -R $(abs_top_builddir)/library

if WINDOWS_TEST_SCRIPT
CHECK_CMD_SCRIPT=check.cmd
check.cmd: Makefile
	@printf "@echo off > check.log\r\n" > check.cmd
	@printf "echo ----------------------- >> check.log\r\n" >> check.cmd
	@printf "echo Testing Without Threads >> check.log\r\n" >> check.cmd
	@printf "echo ----------------------- >> check.log\r\n" >> check.cmd
	@for tests in $(TESTS); do \
		echo "$$tests >> $$tests.log" >> check.cmd; \
		echo "echo $$tests %errorlevel% >> check.log" >> check.cmd; \
	done
	@printf "\r\n" >> check.cmd
	@printf "echo ----------------------- >> check.log\r\n" >> check.cmd
	@printf "echo Testing With Threads >> check.log\r\n" >> check.cmd
	@printf "echo ----------------------- >> check.log\r\n" >> check.cmd
	@printf "\r\n" >> check.cmd
	@printf "set GLOBUS_THREAD_MODEL=windows\r\n" >> check.cmd
	@for tests in $(TESTS); do \
		echo "$$tests >> $$tests.log" >> check.cmd; \
		echo "echo $$tests %errorlevel% >> check.log" >> check.cmd; \
	done
else
CHECK_CMD_SCRIPT=
endif

EXTRA_DIST = globus_test_tap.h
