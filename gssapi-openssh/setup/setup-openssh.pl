#
# setup-openssh.pl:
#   Adapts the installed gsi-ssh environment to the current machine,
#   performing actions that originally occurred during the package's
#   'make install' phase.
#
# Large parts adapted from 'fixpath', a tool found in openssh-3.0.2p1.
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
my $myname = "setup-openssh.pl";

print "$myname: Configuring package 'gsi_openssh'...\n";
print "Run this as root for the intended effect...\n";

#
# Set up path prefixes for use in the path translations
#

$prefix = ${globusdir};
$exec_prefix = "${prefix}";
$bindir = "${exec_prefix}/bin";
$sbindir = "${exec_prefix}/sbin";
$mandir = "${prefix}/man";
$mansubdir = "man";
$libexecdir = "${exec_prefix}/libexec";
$sysconfdir = "/etc/ssh";
$piddir = "/var/run";
$xauth_path = "/usr/bin/X11/xauth";

#
# We need to make sure it's okay to copy our setup files (if some files are already
# present).  If we do copy any files, we backup the old files so the user can (possibly)
# reverse any damage.
#

sub copy_setup_files
{
    my $response, $curr_time;

    $curr_time = time();

    $response = "y";
    if ( -e "${sysconfdir}/ssh_config" )
    {
        $response = query_boolean("${sysconfdir}/ssh_config already exists.  Overwrite? ", "n");
    }

    if ($response eq "y")
    {
        action("cp ${sysconfdir}/ssh_config ${sysconfdir}/ssh_config.bak_${curr_time}");
        action("cp ${globusdir}/setup/globus/ssh_config ${sysconfdir}/ssh_config");
    }

    #
    # Reset response for our new query
    #

    $response = "y";
    if ( -e "${sysconfdir}/sshd_config" )
    {
        $response = query_boolean("${sysconfdir}/sshd_config already exists.  Overwrite? ", "n");
    }

    if ($response eq "y")
    {
        action("cp ${sysconfdir}/sshd_config ${sysconfdir}/sshd_config.bak_${curr_time}");
        action("cp ${globusdir}/setup/globus/sshd_config ${sysconfdir}/sshd_config");
    }

    #
    # Reset response for our new query
    #

    $response = "y";
    if ( -e "${sysconfdir}/moduli" )
    {
        $response = query_boolean("${sysconfdir}/moduli already exists.  Overwrite? ", "n");
    }

    if ($response eq "y")
    {
        action("cp ${sysconfdir}/moduli ${sysconfdir}/moduli.bak_${curr_time}");
        action("cp ${globusdir}/setup/globus/moduli ${sysconfdir}/moduli");
    }
}

sub runkeygen
{
    if ( ! -d "${sysconfdir}" )
    {
        print "Could not find ${sysconfdir} directory... creating\n";
        mkdir($sysconfdir, 16877);
        # 16877 should be 755, or drwxr-xr-x
    }

    print "Generating ssh keys (if necessary)...\n";
    if ( -e "${sysconfdir}/ssh_host_key" )
    {
        print "${sysconfdir}/ssh_host_key already exists, skipping.\n";
    }
    else
    {
        # if $sysconfdir/ssh_host_key doesn't exist..
        action("$bindir/ssh-keygen -t rsa1 -f $sysconfdir/ssh_host_key -N \"\"");
    }

    if ( -e "${sysconfdir}/ssh_host_dsa_key" )
    {
        print "${sysconfdir}/ssh_host_dsa_key already exists, skipping.\n";
    }
    else
    {
        # if $sysconfdir/ssh_host_dsa_key doesn't exist..
        action("$bindir/ssh-keygen -t dsa -f $sysconfdir/ssh_host_dsa_key -N \"\"");
    }

    if ( -e "${sysconfdir}/ssh_host_rsa_key" )
    {
        print "${sysconfdir}/ssh_host_rsa_key already exists, skipping.\n";
    }
    else
    {
        # if $sysconfdir/ssh_host_rsa_key doesn't exist..
        action("$bindir/ssh-keygen -t rsa -f $sysconfdir/ssh_host_rsa_key -N \"\"");
    }

    return 0;
}

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
        "(/path/to/scp.real)" => "${bindir}/scp.real",
        "(/path/to/ssh)" => "${bindir}/ssh",
        "(/path/to/sftp.real)" => "${bindir}/sftp.real",
        "(/path/to/sshd.real)" => "${sbindir}/sshd.real",
        "(/path/to/ssh_config)" => "${sysconfdir}/ssh_config",
        "(/path/to/sshd_config)" => "${sysconfdir}/sshd_config",
        );

    #
    # Files on which to perform path translations
    #

    %files = (
        "${bindir}/scp" => 0,
        "${bindir}/sftp" => 0,
        "${sbindir}/sshd" => 0,
        "${sysconfdir}/ssh_config" => 1,
        "${sysconfdir}/sshd_config" => 1,
        "${sysconfdir}/moduli" => 1,
        "${mandir}/${mansubdir}1/scp.1" => 0,
        "${mandir}/${mansubdir}1/ssh-add.1" => 0,
        "${mandir}/${mansubdir}1/ssh-agent.1" => 0,
        "${mandir}/${mansubdir}1/ssh-keygen.1" => 0,
        "${mandir}/${mansubdir}1/ssh-keyscan.1" => 0,
        "${mandir}/${mansubdir}1/ssh.1" => 0,
        "${mandir}/${mansubdir}8/sshd.8" => 0,
        "${mandir}/${mansubdir}8/sftp-server.8" => 0,
        "${mandir}/${mansubdir}1/sftp.1" => 0,
        );

    print "Translating strings in config/man files...\n";
    for my $f (keys %files)
    {
        $f =~ /(.*\/)*(.*)$/;

        #
        # we really should create a random filename and make sure that it
        # doesn't already exist (based off current time_t or something)
        #

        $g = "$f.tmp";

        #
        # Grab the current mode/uid/gid for use later
        #

        $mode = (stat($f))[2];
        $uid = (stat($f))[4];
        $gid = (stat($f))[5];

        action("mv $f $g");

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

        if ($file{$f} eq 0)
        {
            action("rm $g");
        }
        else
        {
            print "Left backup config file '$g'\n";
        }

        #
        # An attempt to revert the new file back to the original file's
        # mode/uid/gid
        #

        chmod($mode, $f);
        chown($uid, $gid, $f);
    } # for $f

    return 0;
}

copy_setup_files();
runkeygen();
fixpaths();

my $metadata = new Grid::GPT::Setup(package_name => "gsi_openssh_setup");

$metadata->finish();

print "$myname: Finished configuring package 'gsi_openssh'.\n";

#
# Just need a minimal action() subroutine for now..
#

sub action
{
    my ($command) = @_;

    printf "$command\n";

    my $result = system("$command 2>&1");

    if (($result or $?) and $command !~ m!patch!)
    {
        die "ERROR: Unable to execute command: $!\n";
    }
}

sub query_boolean
{
    my ($query_text, $default) = @_;
    my $nondefault, $foo, $bar;

    #
    # Set $nondefault to the boolean opposite of $default.
    #

    if ($default eq "n")
    {
        $nondefault = "y";
    }
    else
    {
        $nondefault = "n";
    }

    print "${query_text} ";
    print "[$default] ";

    $foo = getc(STDIN);
    $bar = <STDIN>;

    if ($foo ne $nondefault)
    {
        $foo = $default;
    }

    return $foo;
}

