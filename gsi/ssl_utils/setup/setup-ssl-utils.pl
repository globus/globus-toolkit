

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

use Getopt::Long;
use English;

my $gpath = $ENV{GPT_LOCATION};
if (!defined($gpath))
{
  $gpath = $ENV{GLOBUS_LOCATION};

}
if (!defined($gpath))
{
   die "GPT_LOCATION or GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");


$setup_gsi_options = join(" ", @ARGV);

if( ! &GetOptions("nonroot|d:s","help!") ) 
{
   pod2usage(1);
}

if(defined($opt_help))
{
   pod2usage(0);
}

my $globusdir = $ENV{GLOBUS_LOCATION};
my $setupdir = "$globusdir/setup/globus";

my $target_dir = "/etc/grid-security";
my $trusted_certs_dir = $target_dir . "/certificates";

my $myname = "setup-ssl-utils";

print "$myname: Configuring ssl-utils package\n";

#
# Run setup-ssl-utils-sh-scripts. This will:
#   -Create grid-security-config from grid-security-config.in
#   -Create grid-cert-request-config from grid-cert-request-config.in
#

print "Running setup-ssl-utils-sh-scripts...\n";

my $result = `$setupdir/setup-ssl-utils-sh-scripts`;

$result = system("chmod 755 $setupdir/grid-security-config");

if ($result != 0) {
  die "Failed to set permissions on $setupdir/grid-security-config";
}

$result = system("chmod 755 $setupdir/grid-cert-request-config");

if ($result != 0) {
  die "Failed to set permissions on $setupdir/grid-cert-request-config";
}

if(defined($opt_nonroot))
{

    print "

Running: $setupdir/setup-gsi $setup_gsi_options

";

    system("$setupdir/setup-gsi $setup_gsi_options");

    print "
done with setup-ssl-utils.
";

} 
else 
{

   print "
***************************************************************************

Note: To complete setup of the GSI software you need to run the
following script as root to configure your /etc/grid-security/
directory:

$setupdir/setup-gsi

***************************************************************************

$myname: Complete

Press return to continue.
";

   $foo=<STDIN>;
   
}

sub pod2usage 
{
  my $ex = shift;

  print "setup-ssl-utils [
              -help
              -nonroot[=path] 
                 sets the directory that the security configuration
	         files will be placed in.  If no argument is given,
	         the config files will be placed in \$GLOBUS_LOCATION/etc/
                 and the CA files will be placed in  
                 \$GLOBUS_LOCATION/share/certificates.
                ]\n";

  exit $ex;
}


# End
