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
# Backup-related variables
#

$curr_time = time();
$backupdir = "/etc/ssh/globus_backup_${curr_time}";

#
# Check that we are running as root
#

$uid = $>;

if ($uid != 0)
{
    print "--> NOTE: You must be root to run this script! <--\n";
    exit 0;
}

#
# We need to make sure it's okay to copy our setup files (if some files are already
# present).  If we do copy any files, we backup the old files so the user can (possibly)
# reverse any damage.
#

sub test_dirs
{
    print "\nPreparatory: Checking for existence of critical directories..\n";

    #
    # Remember to put in check for /etc
    #

    #
    # Test for /etc/ssh
    #

    if ( ! -d "$sysconfdir" )
    {
        print "Could not find directory: '${sysconfdir}'.. creating.\n";
        mkdir($sysconfdir, 16877);
        # 16877 should be 755, or drwxr-xr-x
    }

    #
    # Test for /etc/ssh/globus_backup_<curr>
    #

    if ( ! -d "${backupdir}" )
    {
        print "Could not find directory: '${backupdir}'.. creating.\n";
        mkdir($backupdir, 16877);
    }

    return 0;
}

sub backup_files
{
    print "\nStage 1: Backing up configuration files to '${backupdir}/'..\n";

    if ( -e "${sysconfdir}/ssh_config" )
    {
        action("cp ${sysconfdir}/ssh_config ${backupdir}/ssh_config");
    }
    else
    {
        print "${sysconfdir}/ssh_config does not exist.\n";
    }

    if ( -e "${sysconfdir}/sshd_config" )
    {
        action("cp ${sysconfdir}/sshd_config ${backupdir}/sshd_config");
    }
    else
    {
        print "${sysconfdir}/sshd_config does not exist.\n";
    }

    if ( -e "${sysconfdir}/moduli" )
    {
        action("cp ${sysconfdir}/moduli ${backupdir}/moduli");
    }
    else
    {
        print "${sysconfdir}/moduli does not exist.\n";
    }
}

sub copy_setup_files
{
    my $response;

    print "\nStage 2: Copying configuration files into '${sysconfdir}'..\n";

    action("cp ${globusdir}/setup/globus/ssh_config ${sysconfdir}/ssh_config");
    action("cp ${globusdir}/setup/globus/sshd_config ${sysconfdir}/sshd_config");
    action("cp ${globusdir}/setup/globus/moduli ${sysconfdir}/moduli");
}

sub runkeygen
{
    print "\nStage 3: Generating ssh host keys..\n";

    if ( ! -d "${sysconfdir}" )
    {
        print "Could not find ${sysconfdir} directory... creating\n";
        mkdir($sysconfdir, 16877);
        # 16877 should be 755, or drwxr-xr-x
    }

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
    my $g;

    print "\nStage 4: Translating strings in config and man files..\n";

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
        );

    #
    # Files on which to perform path translations
    #

    @files = (
        "${sysconfdir}/ssh_config" => 0,
        "${sysconfdir}/sshd_config" => 0,
        "${sysconfdir}/moduli" => 0,
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

    for my $f (@files)
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

        #
        # Move $f into a .tmp file for the translation step
        #

        $result = system("mv $f $g 2>&1");
        if ($result or $?)
        {
            die "ERROR: Unable to execute command: $!\n";
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

        #
        # Remove the old .tmp file
        #

        $result = system("rm $g 2>&1");

        if ($result or $?)
        {
            die "ERROR: Unable to execute command: $!\n";
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

print "---------------------------------------------------------------\n";
print "$myname: Configuring package gsi_openssh..\n";
print "\n";
print "Hi, I'm the setup script for the gsi_openssh package!  There\n";
print "are some last minute details that I've got to set straight\n";
print "in the config and man files, along with generating the ssh keys\n";
print "for this machine (if it doesn't already have them).\n";
print "\n";
print "I like to install my config-related files in:
print "  ${sysconfdir}\n";
print "and, if you choose to continue, you will find a backup of the\n";
print "original files in:\n";
print "  ${backupdir}/\n";
print "\n";
print "Your host keys will remain untouched if they are already present.\n";
print "If they aren't present, this script will generate them for you.\n";
print "\n";

$response = query_boolean("Do you wish to continue with the setup package?","y");

if ($response eq "n")
{
    print "\n";
    print "Okay.. exiting gsi_openssh setup.\n";

    exit 0;
}

test_dirs();
backup_files();
copy_setup_files();
runkeygen();
fixpaths();

my $metadata = new Grid::GPT::Setup(package_name => "gsi_openssh_setup");

$metadata->finish();

print "\n";
print "$myname: Finished configuring package 'gsi_openssh'.\n";
print "---------------------------------------------------------------\n";

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

    $foo = <STDIN>;
    ($bar) = split //, $foo;

    if ($bar ne $nondefault)
    {
        $bar = $default;
    }

    return $bar;
}

