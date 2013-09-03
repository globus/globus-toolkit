#! /usr/bin/perl
#
# Copyright 1999-2013 University of Chicago
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

# This test runs gcmu setup twice on the same config file. It should end
# with the same config after the second run as after the first one

use strict;
package TempUser;

my @chars = ("a".."z");
my @nums = ("0".."9");
my @pwchars = ("A".."Z", "a".."z", "0".."9", "^","&","*","(",")",",",".");
my @users;

sub create_user(;$$)
{
    my $class = shift;
    my $random_user="";
    my $random_pass="";
    my $salt = "";
    my $crypted;
    my $rc;

    if (scalar(@_) > 0)
    {
        $random_user = shift;
    }
    else
    {
        $random_user .= $chars[rand @chars] for 1..8;
        $random_user .= $nums[rand @nums] for 1..3;
    }
    if (scalar(@_) > 0)
    {
        $random_pass = shift;
    }
    else
    {
        $random_pass .= $pwchars[rand @pwchars] for 1..12;
    }
    $salt .= $chars[rand @chars] for 1..2;
    $crypted = crypt($random_pass, $salt);
    $rc = system("useradd", $random_user, "-m", "-p", $crypted);

    if ($rc != 0)
    {
        return undef;
    }
    push(@users, $random_user);

    return ($random_user, $random_pass);
}

sub delete_user($)
{
    my $deletable = shift;
    for (my $i = 0; $i < scalar(@users); $i++)
    {
        if ($users[$i] eq $deletable)
        {
            delete $users[$i];
        }
    }
}

END
{
    for (my $i = 0; $i < scalar(@users); $i++)
    {
        if ($users[$i])
        {
            system("userdel", "-r", $users[$i]);
            delete $users[$i];
        }
    }
}

1;
# vim: filetype=perl :
