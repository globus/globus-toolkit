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
    exitDie("ERROR: GLOBUS_LOCATION needs to be set before running this script!\n");
}

#
# Include standard modules
#

use Getopt::Long;
use Cwd;
use Cwd 'abs_path';

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
$bindir = "${exec_prefix}/bin/ssh.d";
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

my($prompt, $force, $verbose);

$prompt = 1;
$verbose = 0;

GetOptions(
            'prompt!' => \$prompt,
            'force' => \$force,
            'verbose' => \$verbose,
          ) or pod2usage(2);

#
# miscellaneous initialization functions
#

setPrivilegeSeparation(0);

#
# main execution.  This should find its way into a subroutine at some future
# point.
#

debug0("Configuring gsi_openssh\n");
debug0("------------------------------------------------------------\n");
debug0("Executing...\n");

makeConfDir();
$keyhash = determineKeys();
runKeyGen($keyhash->{gen});
linkKeyFiles($keyhash->{link});
copyConfigFiles();

my $metadata = new Grid::GPT::Setup(package_name => "gsi_openssh_setup");

$metadata->finish();

debug0("\n");
debug0("Notes:\n\n");

if ( getPrivilegeSeparation() )
{
    debug0("  o Privilege separation is on.\n");
}
elsif ( !getPrivilegeSeparation() )
{
    debug0("  o Privilege separation is off.\n");
}

debug0("  o GSI-OpenSSH website is <http://grid.ncsa.uiuc.edu/ssh/>.\n");
debug0("------------------------------------------------------------\n");
debug0("Finished configuring gsi_openssh.\n");

exit;

#
# subroutines
#

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

### linkKeyFiles( $linklist )
#
# given an array of keys to link, link both the key and its public variant into
# the gsi-openssh configuration directory.
#

sub linkKeyFiles
{
    my($linklist) = @_;
    my($regex, $basename);

    if (@$linklist)
    {
        debug1("Linking ssh host keys...\n");

        for my $f (@$linklist)
        {
            $f =~ s:/+:/:g;

            if (length($f) > 0)
            {
                $keyfile = "$f";
                $pubkeyfile = "$f.pub";

                linkFile("$localsshdir/$keyfile", "$sysconfdir/$keyfile");
                linkFile("$localsshdir/$pubkeyfile", "$sysconfdir/$pubkeyfile");
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

        debug1("${sysconfdir} already exists and is not a directory!\n");
        exit;
    }

    debug1("Could not find ${sysconfdir} directory... creating.\n");
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
    $keyhash->{link} = [];  # a list of files to link

    $genlist = $keyhash->{gen};
    $linklist = $keyhash->{link};

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
        # if we can find a copy of the keys in /etc/ssh, we'll link them to the user's
        # globus location
        #

        $mainkeyfile = "$localsshdir/$basekeyfile";
        $mainpubkeyfile = "$localsshdir/$basekeyfile.pub";

        if ( isPresent($mainkeyfile) && isPresent($mainpubkeyfile) )
        {
            push(@$linklist, $basekeyfile);
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
        debug1("Generating ssh host keys...\n");

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
    my($privsep_enabled);

    debug1("Fixing paths in sshd_config...\n");

    $fileInput = "$setupdir/sshd_config.in";
    $fileOutput = "$sysconfdir/sshd_config";

    #
    # verify that we are prepared to work with $fileInput
    #

    if ( !isReadable($fileInput) )
    {
        debug1("Cannot read $fileInput... skipping.\n");
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
    # check to see whether we should enable privilege separation
    #

    if ( userExists("sshd") && ( -d "/var/empty" ) && ( getOwnerID("/var/empty") eq 0 ) )
    {
        setPrivilegeSeparation(1);
    }
    else
    {
        setPrivilegeSeparation(0);
    }

    if ( getPrivilegeSeparation() )
    {
        $privsep_enabled = "yes";
    }
    else
    {
        $privsep_enabled = "no";
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

    # #
    # # alter the PidFile config
    # #
    # 
    # $text = "PidFile\t$gpath/var/sshd.pid";
    # $data =~ s:^[\s|#]*PidFile.*$:$text:gm;

    #
    # set the sftp directive
    #

    @sftp_dirs = ("$gpath/libexec", "$gpath/share/globus");
    $sftp_server_path =
      findExecutable("sftp-server", \@sftp_dirs);
    if ($sftp_server_path ne "undef") {
      $text = "Subsystem\tsftp\t$sftp_server_path";
      $data =~ s:^[\s|#]*Subsystem\s+sftp\s+.*$:$text:gm;
    } else {
      debug0("\nWARNING: sftp-server not found. $fileOutput requires manual configuration for sftp subsystem.\n");
    }

    #
    # set the privilege separation directive
    #

    $text = "UsePrivilegeSeparation\t${privsep_enabled}";
    $data =~ s:^[\s|#]*UsePrivilegeSeparation.*$:$text:gm;

    #
    # dump the modified output to the config file
    #

    writeFile($fileOutput, $data);

    #
    # An attempt to revert the new file back to the original file's
    # mode/uid/gid
    #

    chmod($mode, $fileOutput);
    chown($uid, $gid, $fileOutput);

    return 0;
}

### setPrivilegeSeparation( $value )
#
# set the privilege separation variable to $value
#

sub setPrivilegeSeparation
{
    my($value) = @_;

    $privsep = $value;
}

### getPrivilegeSeparation( )
#
# return the value of the privilege separation variable
#

sub getPrivilegeSeparation
{
    return $privsep;
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
        debug1("$file already exists... ");

        if ( isForced() )
        {
            if ( isWritable($file) )
            {
                debug1("removing.\n");
                action("rm $file");
                return 1;
            }
            else
            {
                debug1("not writable -- skipping.\n");
                return 0;
            }
        }
        else
        {
            debug1("skipping.\n");
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

    debug1("Copying ssh_config and moduli to their proper location...\n");

    copyFile("$setupdir/ssh_config", "$sysconfdir/ssh_config");
    copyFile("$setupdir/moduli", "$sysconfdir/moduli");

    #
    # copy and alter the SXXsshd script.
    #

    copySXXScript("$setupdir/SXXsshd.in", "$sbindir/SXXsshd");
}

### linkFile( $src, $dest )
#
# create a symbolic link from $src to $dest.
#

sub linkFile
{
    my($src, $dest) = @_;

    if ( !isPresent($src) )
    {
        debug1("$src is not readable... not creating $dest.\n");
        return;
    }

    if ( !prepareFileWrite($dest) )
    {
        return;
    }

    action("ln -s $src $dest");
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
        debug1("$src is not readable... not creating $dest.\n");
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
    my($tmpgpath);

    if ( !isReadable($in) )
    {
        debug1("$in is not readable... not creating $out.\n");
        return;
    }

    if ( !prepareFileWrite($out) )
    {
        return;
    }

    #
    # clean up any junk in the globus path variable
    #

    $tmpgpath = $gpath;
    $tmpgpath =~ s:/+:/:g;
    $tmpgpath =~ s:([^/]+)/$:\1:g;

    #
    # read in the script, substitute globus location, then write it back out
    #

    $data = readFile($in);
    $data =~ s|\@GLOBUS_LOCATION\@|$tmpgpath|g;
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

    open(IN, "$filename") || exitDie("ERROR: Can't open '$filename': $!\n");
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
        exitDie("ERROR: Filename is undefined!\n");
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

### debug1( $arg1, $arg2 )
#
# Print out a debugging message at level 1.
#

sub debug1
{
    debug(string => \@_, level => 1);
}

### debug0( $arg1, $arg2 )
#
# Print out a debugging message at level 0.
#

sub debug0
{
    debug(string => \@_, level => 0);
}

### debug( string => $string, level => $level )
#
# Print out debugging messages at various levels.  Feel free to use debugN() directly
# which in turn calls this subroutine.
#

sub debug
{
    my %args = @_;

    if (!defined($args{'level'}))
    {
        $args{'level'} = 0;
    }

    if ($verbose >= $args{'level'})
    {
        printf(@{$args{'string'}});
    }
}

### action( $command )
#
# run $command within a proper system() command.
#

sub action
{
    my($command) = @_;

    debug1("$command\n");

    my $result = system("$command >/dev/null 2>&1");

    if (($result or $?) and $command !~ m!patch!)
    {
        exitDie("ERROR: Unable to execute $command: $!\n");
    }
}

### exitDie( $error )
#
# a horribly named method meant to look like die but only exit, thereby not causing
# gpt-postinstall to croak.
#

sub exitDie
{
    my($error) = @_;

    print $error;
    exit;
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

    if ( !$prompt )
    {
        print "Prompt suppressed.  Continuing...\n";
        return "y";
    }

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
    elsif ($bar eq '')
    {
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

### getOwnerID( $file )
#
# return the uid containing the owner ID of the given file.
#

sub getOwnerID
{
    my($file) = @_;
    my($uid);

    #
    # call stat() to get the mode of the file
    #

    $uid = (stat($file))[4];

    return $uid;
}

### getMode( $file )
#
# return a string containing the mode of the given file.
#

sub getMode
{
    my($file) = @_;
    my($tempmode, $mode);

    #
    # call stat() to get the mode of the file
    #

    $tempmode = (stat($file))[2];
    if (length($tempmode) < 1)
    {
        return "";
    }

    #
    # call sprintf to format the mode into a UNIX-like string
    #

    $mode = sprintf("%04o", $tempmode & 07777);

    return $mode;
}

### userExists( $username )
#
# given a username, return true if the user exists on the system.  return false
# otherwise.
#

sub userExists
{
    my($username) = @_;
    my($uid);

    #
    # retrieve the userid of the user with the given username
    #

    $uid = getpwnam($username);

    #
    # return true if $uid is defined and has a length greater than 0
    #

    if ( defined($uid) and (length($uid) > 0) )
    {
        return 1;
    }
    else
    {
        return 0;
    }
}
