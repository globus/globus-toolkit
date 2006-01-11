#!/usr/bin/perl
#
# convert-filelist.pl
#
# Modifies an old-style GPT filelist (one file entry per line) to the new
# XML-based GPTFilelist format.
#
# Send comments/fixes/suggestions to:
# Chase Phillips <cphillip@ncsa.uiuc.edu>
#

#
# Get user's GPT_LOCATION since we may be installing this using a new(er)
# version of GPT.
#

my $gpath = $ENV{GPT_LOCATION};

if (!defined($gpath))
{
    $gpath = $ENV{GLOBUS_LOCATION};
}

if (!defined($gpath))
{
    die("GPT_LOCATION or GLOBUS_LOCATION needs to be set before running this script");
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

@INC = ("$gpath/lib/perl", @INC);

#
# script-centred variable initialization
#

my $globusdir = $gpath;
my $myname = "convert-filelist.pl";

#
# Set up path prefixes for use in the path translations
#

$prefix = ${globusdir};

#
# argument specification.  we offload some processing work from later functions
# to verify correct args by using anon subs in various places.
#

my($interactive, $force, $verbose, $modify);

GetOptions(
            'interactive!' => \$interactive,
            'force' => \$force,
            'verbose' => \$verbose,
            'modify' => \$modify,
          ) or pod2usage(2);

my @files = @ARGV;

#
# main execution.  This should find its way into a subroutine at some future
# point.
#

for my $f (@files)
{
    alterFilelist($f);
}

exit;

#
# subroutines
#

### alterFilelist( )
#
# this subroutine 'edits' the paths in sshd_config to suit them to the current environment
# in which the setup script is being run.
#

sub alterFilelist
{
    my($fileInput) = @_;
    my($mode, $uid, $gid);

    if ( defined($modify) && $modify )
    {
        $fileOutput = "$fileInput";
    }
    else
    {
        $fileOutput = "$fileInput.new";
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

    #
    # prepend and append all the text needed for every line in the filelist
    #

    $text_prepend = "    <File><Path>";
    $text_append = "</Path></File>";

    $data =~ s:^(.*)$:$text_prepend\1$text_append:gm;

    #
    # fill out the rest of the file
    #

    $text  = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    $text .= "<!DOCTYPE gpt_package_filelist SYSTEM \"gpt_filelist.dtd\">\n";
    $text .= "<PackageFilelist Name=\"\" FormatVersion=\"0.01\">\n";
    $text .= "  <PackageType></PackageType>\n";
    $text .= "  <Flavor></Flavor>\n";
    $text .= "  <Files>\n";

    $data = $text . $data;

    $text  = "  </Files>\n";
    $text .= "</PackageFilelist>\n";

    $data = $data . $text;

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
