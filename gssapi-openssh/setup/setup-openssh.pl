#! perl
#
# setup-openssh.pl
#
# Adapts the installed gsi-openssh environment to the current machine,
# performing actions that originally occurred during the package's
# 'make install' phase.
#
# Send comments/fixes/suggestions to:
# Chase Phillips <cphillip@ncsa.uiuc.edu>
#

#
# Get user's GPT_LOCATION since we may be installing this using a new(er)
# version of GPT.
#

$gptpath = $ENV{GPT_LOCATION};

#
# And the old standby..
#

$gpath = $ENV{GLOBUS_LOCATION};
if (!defined($gpath))
{
    die "GLOBUS_LOCATION needs to be set before running this script"
}

#
# modify the ld library path for when we call ssh executables
#

$oldldpath = $ENV{LD_LIBRARY_PATH};
$newldpath = "$gpath/lib";
if (length($oldldpath) > 0)
{
    $newldpath .= ":$oldldpath";
}
$ENV{LD_LIBRARY_PATH} = "$newldpath";

#
# i'm including this because other perl scripts in the gpt setup directories
# do so
#

if (defined($gptpath))
{
    @INC = (@INC, "$gptpath/lib/perl", "$gpath/lib/perl");
}
else
{
    @INC = (@INC, "$gpath/lib/perl");
}

require Grid::GPT::Setup;

my $globusdir = $gpath;
my $myname = "setup-openssh.pl";

#
# Set up path prefixes for use in the path translations
#

$prefix = ${globusdir};
$exec_prefix = "${prefix}";
$bindir = "${exec_prefix}/bin";
$sbindir = "${exec_prefix}/sbin";
$sysconfdir = "$prefix/etc/ssh";
$localsshdir = "/etc/ssh";
$setupdir = "$prefix/setup/gsi_openssh_setup";

my $keyfiles = {
                 "dsa" => "ssh_host_dsa_key",
                 "rsa" => "ssh_host_rsa_key",
                 "rsa1" => "ssh_host_key",
               };

print "$myname: Configuring package 'gsi_openssh'...\n";
print "---------------------------------------------------------------------\n";
print "Hi, I'm the setup script for the gsi_openssh package!  There\n";
print "are some last minute details that I've got to set straight\n";
print "in the sshd config file, along with generating the ssh keys\n";
print "for this machine (if it doesn't already have them).\n";
print "\n";
print "If I find a pair of host keys in /etc/ssh, I will copy them into\n";
print "\$GLOBUS_LOCATION/etc/ssh.  If they aren't present, I will generate\n";
print "them for you.\n";
print "\n";

$response = query_boolean("Do you wish to continue with the setup package?","y");
if ($response eq "n")
{
    print "\n";
    print "Exiting gsi_openssh setup.\n";

    exit 0;
}

print "\n";

makeConfDir();
$keyhash = determineKeys();
runKeyGen($keyhash->{gen});
copyKeyFiles($keyhash->{copy});
fixpaths();
copyConfigFiles();
alterFiles();

my $metadata = new Grid::GPT::Setup(package_name => "gsi_openssh_setup");

$metadata->finish();

print "\n";
print "Additional Notes:\n";
print "\n";
print "  o I see that you have your GLOBUS_LOCATION environmental variable\n";
print "    set to:\n";
print "\n";
print "    \t\"$gpath\"\n";
print "\n";
print "    Remember to keep this variable set (correctly) when you want to\n";
print "    use the executables that came with this package.\n";
print "\n";
print "    After that you may run, e.g.:\n";
print "\n";
print "    \t\$ . \$GLOBUS_LOCATION/etc/globus-user-env.sh\n";
print "\n";
print "    to prepare your environment for running the gsi_openssh\n";
print "    executables.\n";
print "---------------------------------------------------------------------\n";
print "$myname: Finished configuring package 'gsi_openssh'.\n";

exit;

#
# subroutines
#

### copyKeyFiles( $copylist )
#
# given an array of keys to copy, copy both the key and its public variant into
# the gsi-openssh configuration directory.
#

sub copyKeyFiles
{
    my($copylist) = @_;
    my($regex, $basename);

    if (@$copylist)
    {
        print "Copying ssh host keys...\n";

        for my $f (@$copylist)
        {
            $f =~ s:/+:/:g;

            if (length($f) > 0)
            {
                $keyfile = "$f";
                $pubkeyfile = "$f.pub";

                action("cp $localsshdir/$keyfile $sysconfdir/$keyfile");
                action("cp $localsshdir/$pubkeyfile $sysconfdir/$pubkeyfile");
            }
        }
    }
}

### isReadable( $file )
#
# given a file, return true if that file both exists and is readable by the
# effective user id.  return false otherwise.
#

sub isReadable
{
    my($file) = @_;

    if ( ( -e $file ) && ( -r $file ) )
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

### isPresent( $file )
#
# given a file, return true if that file exists.  return false otherwise.
#

sub isPresent
{
    my($file) = @_;

    if ( -e $file )
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

### makeConfDir( )
#
# make the gsi-openssh configuration directory if it doesn't already exist.
#

sub makeConfDir
{
    if ( isPresent($sysconfdir) )
    {
        if ( -d $sysconfdir )
        {
            return;
        }

        die("${sysconfdir} already exists and is not a directory!\n");
    }

    print "Could not find ${sysconfdir} directory... creating.\n";
    action("mkdir -p $sysconfdir");

    return;
}

### determineKeys( )
#
# based on a set of key types, triage them to determine if for each key type, that
# key type should be copied from the main ssh configuration directory, or if it
# should be generated using ssh-keygen.
#

sub determineKeys
{
    my($keyhash, $keylist);
    my($count);

    #
    # initialize our variables
    #

    $count = 0;

    $keyhash = {};
    $keyhash->{gen} = [];   # a list of keytypes to generate
    $keyhash->{copy} = [];  # a list of files to copy from the 

    $genlist = $keyhash->{gen};
    $copylist = $keyhash->{copy};

    #
    # loop over our keytypes and determine what we need to do for each of them
    #

    for my $keytype (keys %$keyfiles)
    {
        $basekeyfile = $keyfiles->{$keytype};

        #
        # if the key's are already present, we don't need to bother with this rigamarole
        #

        $gkeyfile = "$sysconfdir/$basekeyfile";
        $gpubkeyfile = "$sysconfdir/$basekeyfile.pub";

        if ( isPresent($gkeyfile) && isPresent($gpubkeyfile) )
        {
            next;
        }

        #
        # if we can find a copy of the keys in /etc/ssh, we'll copy them to the user's
        # globus location
        #

        $mainkeyfile = "$localsshdir/$basekeyfile";
        $mainpubkeyfile = "$localsshdir/$basekeyfile.pub";

        if ( isReadable($mainkeyfile) && isReadable($mainpubkeyfile) )
        {
            push(@$copylist, $basekeyfile);
            $count++;
            next;
        }

        #
        # otherwise, we need to generate the key
        #

        push(@$genlist, $keytype);
        $count++;
    }

    if ($count > 0)
    {
        if ( ! -d $sysconfdir )
        {
            print "Could not find ${sysconfdir} directory... creating\n";
            action("mkdir -p $sysconfdir");
        }
    }

    return $keyhash;
}

### runKeyGen( $gen_keys )
#
# given a set of key types, generate private and public keys for that key type and
# place them in the gsi-openssh configuration directory.
#

sub runKeyGen
{
    my($gen_keys) = @_;
    my $keygen = "$bindir/ssh-keygen";

    if (@$gen_keys && -x $keygen)
    {
        print "Generating ssh host keys...\n";

        for my $k (@$gen_keys)
        {
            $keyfile = $keyfiles->{$k};

            # if $sysconfdir/$keyfile doesn't exist..
            action("$bindir/ssh-keygen -t $k -f $sysconfdir/$keyfile -N \"\"");
        }
    }

    return 0;
}

### fixpaths( )
#
# this subroutine 'edits' the paths in sshd_config to suit them to the current environment
# in which the setup script is being run.
#

sub fixpaths
{
    my($fileInput, $fileOutput);
    my($mode, $uid, $gid);
    my($line, $newline);

    print "Fixing paths in sshd_config...\n";

    $fileInput = "$setupdir/sshd_config.in";
    $fileOutput = "$sysconfdir/sshd_config";

    if ( ! -f "$fileInput" )
    {
        printf("Cannot find $fileInput!\n");
        die();
    }

    if ( -e "$fileOutput" )
    {
        printf("$fileOutput already exists!\n");
        die();
    }

    #
    # Grab the current mode/uid/gid for use later
    #

    $mode = (stat($fileInput))[2];
    $uid = (stat($fileInput))[4];
    $gid = (stat($fileInput))[5];

    #
    # Open the files for reading and writing, and loop over the input's contents
    #

    open(IN, "<$fileInput") || die ("$0: input file $fileInput missing!\n");
    open(OUT, ">$fileOutput") || die ("$0: unable to open output file $fileOutput!\n");

    while (<IN>)
    {
        #
        # sorry for the whacky regex, but i need to verify a whole line
        #

        $line = $_;
        if ( $line =~ /^\s*Subsystem\s+sftp\s+\S+\s*$/ )
        {
            $newline = "Subsystem\tsftp\t$gpath/libexec/sftp-server\n";
            $newline =~ s:/+:/:g;
        }
        elsif ( $line =~ /^\s*PidFile.*$/ )
        {
            $newline = "PidFile\t$gpath/var/sshd.pid\n";
            $newline =~ s:/+:/:g;
        }
        else
        {
            $newline = $line;
        }

        print OUT "$newline";
    } # while <IN>

    close(OUT);
    close(IN);

    #
    # An attempt to revert the new file back to the original file's
    # mode/uid/gid
    #

    chmod($mode, $fileOutput);
    chown($uid, $gid, $fileOutput);

    return 0;
}

### copyConfigFiles( )
#
# subroutine that copies some extra config files to their proper location in
# $GLOBUS_LOCATION/etc/ssh.
#

sub copyConfigFiles
{
    print "Copying ssh_config and moduli to their proper location...\n";

    action("cp $setupdir/ssh_config $sysconfdir/ssh_config");
    action("cp $setupdir/moduli $sysconfdir/moduli");
}

### alterFileGlobusLocation( $in, $out )
#
# parse the input file, substituting in place the value of GLOBUS_LOCATION, and
# write the result to the output file.
#

sub alterFileGlobusLocation
{
    my ($in, $out) = @_;

    if ( -r $in )
    {
        if ( ( -w $out ) || ( ! -e $out ) )
        {
            $data = readFile($in);
            $data =~ s|\@GLOBUS_LOCATION\@|$gpath|g;
            writeFile($out, $data);
            action("chmod 755 $out");
        }
    }
}

### alterFiles( )
#
# the main alteration function, which doesn't do much (other than have GLOBUS_LOCATION
# replaced in the sshd startup/shutdown script).
#

sub alterFiles
{
    alterFileGlobusLocation("$setupdir/SXXsshd.in", "$sbindir/SXXsshd");
}

### readFile( $filename )
#
# reads and returns $filename's contents
#

sub readFile
{
    my ($filename) = @_;
    my $data;

    open (IN, "$filename") || die "Can't open '$filename': $!";
    $/ = undef;
    $data = <IN>;
    $/ = "\n";
    close(IN);

    return $data;
}

### writeFile( $filename, $fileinput )
#
# create the inputs to the ssl program at $filename, appending the common name to the
# stream in the process
#

sub writeFile
{
    my ($filename, $fileinput) = @_;

    #
    # test for a valid $filename
    #

    if ( !defined($filename) || (length($filename) lt 1) )
    {
        die "Filename is undefined";
    }

    if ( ( -e "$filename" ) && ( ! -w "$filename" ) )
    {
        die "Cannot write to filename '$filename'";
    }

    #
    # write the output to $filename
    #

    open(OUT, ">$filename");
    print OUT "$fileinput";
    close(OUT);
}

#
# Just need a minimal action() subroutine for now..
#

sub action
{
    my ($command) = @_;

    printf "$command\n";

    my $result = system("LD_LIBRARY_PATH=\"$gpath/lib:\$LD_LIBRARY_PATH\"; $command 2>&1");

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

    if ( grep(/\s/, $bar) )
    {
        # this is debatable.  all whitespace means 'default'

        $bar = $default;
    }
    elsif ($bar ne $default)
    {
        # everything else means 'nondefault'.

        $bar = $nondefault;
    }
    else
    {
        # extraneous step.  to get here, $bar should be eq to $default anyway.

        $bar = $default;
    }

    return $bar;
}

### absolutePath( $file )
#
# converts a given pathname into a canonical path using the abs_path function.
#

sub absolutePath
{
    my($file) = @_;
    my $home = $ENV{'HOME'};
    $file =~ s!~!$home!;
    my $startd = cwd();
    $file =~ s!^\./!$startd/!;
    $file = "$startd/$file" if $file !~ m!^\s*/!;
    $file = abs_path($file);
    return $file;
}
