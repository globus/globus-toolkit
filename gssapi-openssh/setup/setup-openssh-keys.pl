#
# setup-openssh-keys.pl:
#   Generates the host keys for the openssh install.
#
# Send comments/fixes/suggestions to:
# Chase Phillips <cphillip@ncsa.uiuc.edu>
#

$gpath = $ENV{GLOBUS_LOCATION};
if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

#
# i'm including this because other perl scripts in the gpt setup directories
# do so
#

@INC = (@INC, "$gpath/lib/perl");

require Grid::GPT::Setup;

my $globusdir = $gpath;
my $setupdir = "$globusdir/setup/globus";
my $myname = "setup-openssh-keys.pl";

print "$myname: Configuring keys for package 'gsi_openssh'...\n";

#
# Set up path prefixes for use in the path translations
#

$prefix = ${globusdir};
$exec_prefix = "${prefix}";
$bindir = "${exec_prefix}/bin";
$sysconfdir = "/etc";

sub runkeygen
{
    print "Generating ssh keys (if necessary)...\n";
    if ( -e "${sysconfdir}/ssh_host_key" )
    {
        print "${sysconfdir}/ssh_host_key already exists, skipping.\n";
    }
    else
    {
        # if $sysconfdir/ssh_host_key doesn't exist..
        system("$bindir/ssh-keygen -t rsa1 -f $sysconfdir/ssh_host_key -N \"\"");
    }

    if ( -e "${sysconfdir}/ssh_host_dsa_key" )
    {
        print "${sysconfdir}/ssh_host_dsa_key already exists, skipping.\n";
    }
    else
    {
        # if $sysconfdir/ssh_host_dsa_key doesn't exist..
        system("$bindir/ssh-keygen -t dsa -f $sysconfdir/ssh_host_dsa_key -N \"\"");
    }

    if ( -e "${sysconfdir}/ssh_host_rsa_key" )
    {
        print "${sysconfdir}/ssh_host_rsa_key already exists, skipping.\n";
    }
    else
    {
        # if $sysconfdir/ssh_host_rsa_key doesn't exist..
        system("$bindir/ssh-keygen -t rsa -f $sysconfdir/ssh_host_rsa_key -N \"\"");
    }

    return 0;
}

runkeygen();
