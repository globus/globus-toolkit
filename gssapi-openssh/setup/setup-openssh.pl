#!/usr/bin/perl -w
#
# setup-openssh.pl - substitutes variables into text files and runs
#                     ssh key gen programs
#
# adapted from 'fixpath', located in the openssh-3.0.2p1 package
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
my $myname = "setup-openssh.pl";

print "$myname: Configuring gsi-openssh package";

#
# Set up path prefixes for use in the path translations
#

$prefix = ${globusdir};
$exec_prefix = "${prefix}";
$bindir = "${exec_prefix}/bin";
$mandir = "${prefix}/man";
$mansubdir = "man";
$libexecdir = "${exec_prefix}/libexec";
$sysconfdir = "${prefix}/etc";
$piddir = "/var/run";
$xauth_path = "/usr/bin/X11/xauth";

sub fixpaths
{
    #
    # Set up path translations for the installation files
    #

    %def = (
        "/etc/ssh_config" => "${sysconfdir}/ssh_config",
        "/etc/ssh_known_hosts" => "${sysconfdir}/ssh_known_hosts",
        "/etc/sshd_config" => "${sysconfdir}/sshd_config",
        "/usr/libexec" => "${libexecdir}",
        "/etc/shosts.equiv" => "${sysconfdir}/shosts.equiv",
        "/etc/ssh_host_key" => "${sysconfdir}/ssh_host_key",
        "/etc/ssh_host_dsa_key" => "${sysconfdir}/ssh_host_dsa_key",
        "/etc/ssh_host_rsa_key" => "${sysconfdir}/ssh_host_rsa_key",
        "/var/run/sshd.pid" => "${piddir}/sshd.pid",
        "/etc/moduli" => "${sysconfdir}/moduli",
        "/etc/sshrc" => "${sysconfdir}/sshrc",
        "/usr/X11R6/bin/xauth" => "${xauth_path}",
        "/usr/bin:/bin:/usr/sbin:/sbin" => "/usr/bin:/bin:/usr/sbin:/sbin:${bindir}",
        "/path/to/scp.real" => "${bindir}/scp.real",
        "/path/to/ssh" => "${bindir}/ssh",
        );

    #
    # Files on which to perform path translations
    #

    @files = (
        "${bindir}/scp",
        "${sysconfdir}/ssh_config",
        "${sysconfdir}/sshd_config",
        "${sysconfdir}/moduli",
        "${mandir}/${mansubdir}1/scp.1",
        "${mandir}/${mansubdir}1/ssh-add.1",
        "${mandir}/${mansubdir}1/ssh-agent.1",
        "${mandir}/${mansubdir}1/ssh-keygen.1",
        "${mandir}/${mansubdir}1/ssh-keyscan.1",
        "${mandir}/${mansubdir}1/ssh.1",
        "${mandir}/${mansubdir}8/sshd.8",
        "${mandir}/${mansubdir}8/sftp-server.8",
        "${mandir}/${mansubdir}1/sftp.1",
        );

    print "Translating strings in config/man files...\n";
    for $f (@files)
    {
        $f =~ /(.*\/)*(.*)$/;
        $g = "$f.tmp";

        $result = system("mv $f $g");
        if ($result != 0)
        {
            die "Failed to copy $f to $g!\n";
        }

        open(IN, "<$g") || die ("$0: input file $g missing!\n");
        open(OUT, ">$f") || die ("$0: unable to open output file $f!\n");

        while (<IN>)
        {
            for $s (keys(%def))
            {
                s#$s#$def{$s}#;
            } # for $s
            print OUT "$_";
        } # while <IN>

        close(OUT);
        close(IN);

        $result = system("rm $g");
        if ($result != 0)
        {
            die "Failed to remove $g\n";
        }
    } # for $f

    return 0;
}

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

fixpaths();
runkeygen();

my $metadata = new Grid::GPT::Setup(package_name => "gsi-openssh-setup");

$metadata->finish();
