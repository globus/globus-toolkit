#!/usr/bin/perl
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
# Include standard modules
#

use Getopt::Long;
use Cwd;
use Cwd 'abs_path';

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

#
# script-centred variable initialization
#

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

#
# standard key types and their root file name mappings
#

my $keyfiles = {
                 "dsa" => "ssh_host_dsa_key",
                 "rsa" => "ssh_host_rsa_key",
                 "rsa1" => "ssh_host_key",
               };

#
# argument specification.  we offload some processing work from later functions
# to verify correct args by using anon subs in various places.
#

my($interactive, $force, $verbose);

GetOptions(
            'interactive!' => \$interactive,
            'force' => \$force,
            'verbose' => \$verbose,
          ) or pod2usage(2);

#
# main execution.  This should find its way into a subroutine at some future
# point.
#

print "$myname: Configuring package 'gsi_openssh'...\n";
print "---------------------------------------------------------------------\n";
print "Hi, I'm the setup script for the gsi_openssh package!  I will create\n";
print "a number of configuration files based on your local system setup.  I\n";
print "will also attempt to copy or create a number of SSH key pairs for\n";
print "this machine.\n";
print "\n";
print "(Loosely, if I find a pair of host keys in /etc/ssh, I will copy them\n";
print "into \$GLOBUS_LOCATION/etc/ssh.  Otherwise, I will generate them for\n";
print "you.)\n";
print "\n";

if ( isForced() )
{
    print "WARNING:\n";
    print "\n";
    print "    Using the '-force' flag will cause all gsi_openssh_setup files to\n";
    print "    be removed and replaced by new versions!  Backup any critical\n";
    print "    SSH configuration files before you choose to continue!\n";
    print "\n";
}

$response = query_boolean("Do you wish to continue with the setup package?","y");
if ($response eq "n")
{
    print "\n";
    print "Exiting gsi_openssh setup.\n";

    exit 0;
}

print "\n";

makeConfDir();
copyPRNGFile();
$keyhash = determineKeys();
runKeyGen($keyhash->{gen});
copyKeyFiles($keyhash->{copy});
copyConfigFiles();

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

### initPRNGHash( )
#
# initialize the PRNG pathname hash
#

sub initPRNGHash( )
{
    #
    # standard prng to executable conversion names
    #

    addPRNGCommand("\@PROG_LS\@", "ls");
    addPRNGCommand("\@PROG_NETSTAT\@", "netstat");
    addPRNGCommand("\@PROG_ARP\@", "arp");
    addPRNGCommand("\@PROG_IFCONFIG\@", "ifconfig");
    addPRNGCommand("\@PROG_PS\@", "ps");
    addPRNGCommand("\@PROG_JSTAT\@", "jstat");
    addPRNGCommand("\@PROG_W\@", "w");
    addPRNGCommand("\@PROG_WHO\@", "who");
    addPRNGCommand("\@PROG_LAST\@", "last");
    addPRNGCommand("\@PROG_LASTLOG\@", "lastlog");
    addPRNGCommand("\@PROG_DF\@", "df");
    addPRNGCommand("\@PROG_SAR\@", "sar");
    addPRNGCommand("\@PROG_VMSTAT\@", "vmstat");
    addPRNGCommand("\@PROG_UPTIME\@", "uptime");
    addPRNGCommand("\@PROG_IPCS\@", "ipcs");
    addPRNGCommand("\@PROG_TAIL\@", "tail");

    print "Determining paths for PRNG commands...\n";

    $paths = determinePRNGPaths();

    return;
}

### getDirectoryPaths( )
#
# return an array ref containing all of the directories in which we should search
# for our listing of executable names.
#

sub getDirectoryPaths( )
{
    #
    # read in the PATH environmental variable and prepend a set of 'safe'
    # directories from which to test PRNG commands.
    #

    $path = $ENV{PATH};
    $path = "/bin:/usr/bin:/sbin:/usr/sbin:/etc:" . $path;
    @dirs = split(/:/, $path);

    #
    # sanitize each directory listed in the array.
    #

    @dirs = map {
                  $tmp = $_;
                  $tmp =~ s:/+:/:g;
                  $tmp =~ s:^\s+|\s+$::g;
                  $tmp;
                } @dirs;

    return \@dirs;
}

### addPRNGCommand( $prng_name, $exec_name )
#
# given a PRNG name and a corresponding executable name, add it to our list of
# PRNG commands for which to find on the system.
#

sub addPRNGCommand
{
    my($prng_name, $exec_name) = @_;

    prngAddNode($prng_name, $exec_name);
}

### copyPRNGFile( )
#
# read in ssh_prng_cmds.in, translate the program listings to the paths we have
# found on the local system, and then write the output to ssh_prng_cmds.
#

sub copyPRNGFile
{
    my($fileInput, $fileOutput);
    my($mode, $uid, $gid);
    my($data);

    if ( isPresent("/dev/random") && !isForced() )
    {
        printf("/dev/random found and not forced.  Not installing ssh_prng_cmds...\n");
        return;
    }

    initPRNGHash();

    print "Fixing paths in ssh_prng_cmds...\n";

    $fileInput = "$setupdir/ssh_prng_cmds.in";
    $fileOutput = "$sysconfdir/ssh_prng_cmds";

    #
    # verify that we are prepared to work with $fileInput
    #

    if ( !isReadable($fileInput) )
    {
        printf("Cannot read $fileInput... skipping.\n");
        return;
    }

    #
    # verify that we are prepared to work with $fileOuput
    #

    if ( !prepareFileWrite($fileOutput) )
    {
        return;
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

    $data = readFile($fileInput);
    for my $k (keys %$prngcmds)
    {
        $sub = prngGetExecPath($k);
        $data =~ s:$k:$sub:g;
    }
    writeFile($fileOutput, $data);

    #
    # An attempt to revert the new file back to the original file's
    # mode/uid/gid
    #

    chmod($mode, $fileOutput);
    chown($uid, $gid, $fileOutput);

    return 0;
}

### determinePRNGPaths( )
#
# for every entry in the PRNG hash, seek out and find the path for the
# corresponding executable name.
#

sub determinePRNGPaths
{
    my(@paths, @dirs);
    my($exec_name, $exec_path);

    $dirs = getDirectoryPaths();

    for my $k (keys %$prngcmds)
    {
        $exec_name = prngGetExecName($k);
        $exec_path = findExecutable($exec_name, $dirs);
        prngSetExecPath($k, $exec_path);
    }

    return;
}

### prngAddNode( $prng_name, $exec_name )
#
# add a new node to the PRNG hash
#

sub prngAddNode
{
    my($prng_name, $exec_name) = @_;
    my($node);

    if (!defined($prngcmds))
    {
        $prngcmds = {};
    }

    $node = {};
    $node->{prng} = $prng_name;
    $node->{exec} = $exec_name;

    $prngcmds->{$prng_name} = $node;
}

### prngGetExecName( $key )
#
# get the executable name from the prng commands hash named by $key
#

sub prngGetExecName
{
    my($key) = @_;

    return $prngcmds->{$key}->{exec};
}

### prngGetExecPath( $key )
#
# get the executable path from the prng commands hash named by $key
#

sub prngGetExecPath
{
    my($key) = @_;

    return $prngcmds->{$key}->{exec_path};
}

### prngGetNode( $key )
#
# return a reference to the node named by $key
#

sub prngGetNode
{
    my($key) = @_;

    return ${$prngcmds}{$key};
}

### prngSetExecPath( $key, $path )
#
# given a key, set the executable path in that node to $path
#

sub prngSetExecPath
{
    my($key, $path) = @_;

    $prngcmds->{$key}->{exec_path} = $path;
}

### findExecutable( $exec_name, $dirs )
#
# given an executable name, test each possible path in $dirs to see if such
# an executable exists.
#

sub findExecutable
{
    my($exec_name, $dirs) = @_;

    for my $d (@$dirs)
    {
        $test = "$d/$exec_name";

        if ( isExecutable($test) )
        {
            return $test;
        }
    }

    return "undef";
}

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

                copyFile("$localsshdir/$keyfile", "$sysconfdir/$keyfile");
                copyFile("$localsshdir/$pubkeyfile", "$sysconfdir/$pubkeyfile");
            }
        }
    }
}

### isForced( )
#
# return true if the user passed in the force flag.  return false otherwise.
#

sub isForced
{
    if ( defined($force) && $force )
    {
        return 1;
    }
    else
    {
        return 0;
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

### isExecutable( $file )
#
# return true if $file is executable.  return false otherwise.
#

sub isExecutable
{
    my($file) = @_;

    if ( -x $file )
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

### isWritable( $file )
#
# given a file, return true if that file does not exist or is writable by the
# effective user id.  return false otherwise.
#

sub isWritable
{
    my($file) = @_;

    if ( ( ! -e $file ) || ( -w $file ) )
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
            if ( isForced() )
            {
                if ( isWritable("$sysconfdir/$basekeyfile") && isWritable("$sysconfdir/$basekeyfile.pub") )
                {
                     action("rm $sysconfdir/$basekeyfile");
                     action("rm $sysconfdir/$basekeyfile.pub");
                }
                else
                {
                     next;
                }
            }
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

            if ( !isPresent("$sysconfdir/$keyfile") )
            {
                action("$bindir/ssh-keygen -t $k -f $sysconfdir/$keyfile -N \"\"");
            }
        }
    }

    return 0;
}

### copySSHDConfigFile( )
#
# this subroutine 'edits' the paths in sshd_config to suit them to the current environment
# in which the setup script is being run.
#

sub copySSHDConfigFile
{
    my($fileInput, $fileOutput);
    my($mode, $uid, $gid);
    my($line, $newline);

    print "Fixing paths in sshd_config...\n";

    $fileInput = "$setupdir/sshd_config.in";
    $fileOutput = "$sysconfdir/sshd_config";

    #
    # verify that we are prepared to work with $fileInput
    #

    if ( !isReadable($fileInput) )
    {
        printf("Cannot read $fileInput... skipping.\n");
        return;
    }

    #
    # verify that we are prepared to work with $fileOuput
    #

    if ( !prepareFileWrite($fileOutput) )
    {
        return;
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
            $line = "Subsystem\tsftp\t$gpath/libexec/sftp-server\n";
            $line =~ s:/+:/:g;
        }
        elsif ( $line =~ /^\s*PidFile.*$/ )
        {
            $line = "PidFile\t$gpath/var/sshd.pid\n";
            $line =~ s:/+:/:g;
        }
        else
        {
            # do nothing
        }

        print OUT "$line";
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

### prepareFileWrite( $file )
#
# test $file to prepare for writing to it.
#

sub prepareFileWrite
{
    my($file) = @_;

    if ( isPresent($file) )
    {
        printf("$file already exists... ");

        if ( isForced() )
        {
            if ( isWritable($file) )
            {
                printf("removing.\n");
                action("rm $file");
                return 1;
            }
            else
            {
                printf("not writable -- skipping.\n");
                return 0;
            }
        }
        else
        {
            printf("skipping.\n");
            return 0;
        }
    }

    return 1;
}

### copyConfigFiles( )
#
# subroutine that copies some extra config files to their proper location in
# $GLOBUS_LOCATION/etc/ssh.
#

sub copyConfigFiles
{
    #
    # copy the sshd_config file into the ssh configuration directory and alter
    # the paths in the file.
    #

    copySSHDConfigFile();

    #
    # do straight copies of the ssh_config and moduli files.
    #

    printf("Copying ssh_config and moduli to their proper location...\n");

    copyFile("$setupdir/ssh_config", "$sysconfdir/ssh_config");
    copyFile("$setupdir/moduli", "$sysconfdir/moduli");

    #
    # copy and alter the SXXsshd script.
    #

    copySXXScript("$setupdir/SXXsshd.in", "$sbindir/SXXsshd");
}

### copyFile( $src, $dest )
#
# copy the file pointed to by $src to the location specified by $dest.  in the
# process observe the rules regarding when the '-force' flag was passed to us.
#

sub copyFile
{
    my($src, $dest) = @_;

    if ( !isReadable($src) )
    {
        printf("$src is not readable... not creating $dest.\n");
        return;
    }

    if ( !prepareFileWrite($dest) )
    {
        return;
    }

    action("cp $src $dest");
}

### copySXXScript( $in, $out )
#
# parse the input file, substituting in place the value of GLOBUS_LOCATION, and
# write the result to the output file.
#

sub copySXXScript
{
    my($in, $out) = @_;

    if ( !isReadable($in) )
    {
        printf("$in is not readable... not creating $out.\n");
        return;
    }

    if ( !prepareFileWrite($out) )
    {
        return;
    }

    $data = readFile($in);
    $data =~ s|\@GLOBUS_LOCATION\@|$gpath|g;
    writeFile($out, $data);
    action("chmod 755 $out");
}

### readFile( $filename )
#
# reads and returns $filename's contents
#

sub readFile
{
    my($filename) = @_;
    my($data);

    open(IN, "$filename") || die "Can't open '$filename': $!";
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
    my($filename, $fileinput) = @_;

    #
    # test for a valid $filename
    #

    if ( !defined($filename) || (length($filename) lt 1) )
    {
        die "Filename is undefined";
    }

    #
    # verify that we are prepared to work with $filename
    #

    if ( !prepareFileWrite($filename) )
    {
        return;
    }

    #
    # write the output to $filename
    #

    open(OUT, ">$filename");
    print OUT "$fileinput";
    close(OUT);
}

### action( $command )
#
# run $command within a proper system() command.
#

sub action
{
    my($command) = @_;

    printf "$command\n";

    my $result = system("LD_LIBRARY_PATH=\"$gpath/lib:\$LD_LIBRARY_PATH\"; $command 2>&1");

    if (($result or $?) and $command !~ m!patch!)
    {
        die "ERROR: Unable to execute command: $!\n";
    }
}

### query_boolean( $query_text, $default )
#
# query the user with a string, and expect a response.  If the user hits
# 'enter' instead of entering an input, then accept the default response.
#

sub query_boolean
{
    my($query_text, $default) = @_;
    my($nondefault, $foo, $bar);

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
