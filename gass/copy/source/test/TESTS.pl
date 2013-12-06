#!/usr/bin/env perl

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


# -----------------------------------------------------------------------
# TESTS.pl - This script calls all the other tests in the current
# directory only. 
#
# In each directory behind the Globus CVS test module, there will be a
# TESTS.pl file for that directory which will call all the scripts in
# that directory.  The 'test-toolkit' script in side_tools/ will
# recursively search the test/ directory and run the TESTS.pl script in 
# each directory.
#
# You should only modify the @tests array below.  That's it.
#
# -----------------------------------------------------------------------


use strict;
use Cwd;

my @tests = qw(
                guc-simple.pl
                guc-stack.pl
                guc-cc.pl
                guc-fw.pl
               );

foreach (@tests)
{
    system("./$_");
}
