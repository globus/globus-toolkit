#!/usr/bin/perl

# 
# Copyright 1999-2006 University of Chicago
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 

require 5.005;

use warnings;
use strict;
use Test::Harness;
use vars qw(@tests);

@tests = qw( globus-io-file-test.pl
             globus-io-authorization-test.pl
             globus-io-tcp-test.pl
             );

runtests(@tests);

