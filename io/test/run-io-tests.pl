#!/usr/bin/env perl

use strict;
use Test::Harness;
require 5.005;
use vars qw(@tests);

@tests = qw( globus_io_file_test.pl
	     globus_io_tcp_test.pl
	     globus_io_tcp_client_test.pl
	     globus_io_tcp_server_test.pl
	     globus_io_udp_test.pl
	     globus_io_udp_client_test.pl
	     globus_io_udp_server_test.pl
	     );

runtests(@tests);
