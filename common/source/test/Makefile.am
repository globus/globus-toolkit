AM_CPPFLAGS = -I$(top_srcdir)/library $(PACKAGE_DEP_CFLAGS) 
LDADD = ../library/libglobus_common.la -lltdl

if WINDOWS_TEST_SCRIPT
thread_model_opt = -DTHREAD_MODEL="\"windows\""
else
thread_model_opt = -DTHREAD_MODEL="\"pthread\""
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
TESTS = $(check_PROGRAMS)
if CROSS_COMPILING
XFAIL_TESTS = $(TESTS)
endif


thread_test_CPPFLAGS = $(thread_model_opt) $(AM_CPPFLAGS)

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
