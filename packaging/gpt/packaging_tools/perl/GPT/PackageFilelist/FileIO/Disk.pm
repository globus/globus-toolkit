package Grid::GPT::PackageFilelist::FileIO::Disk;

$VERSION = 1.00;

use strict;
use vars qw( $AUTOLOAD @ISA @EXPORT ); # Keep 'use strict' happy
use Carp;
use Cwd;

require Exporter;
require AutoLoader;
require Grid::GPT::GPTObject;

@ISA = qw(Exporter AutoLoader Grid::GPT::GPTObject);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw(
);

#
# include standard modules
#

#
# data internal to the class
#

my $_count = 0;

#
# Class methods
#

sub get_count
{
    $_count;
}

sub _incr_count { ++$_count }
sub _decr_count { --$_count }

### new( $caller, %args )
#
# Object Constructor
#

sub new
{
    my $caller = shift;
    my(%args) = @_;
    my $caller_is_obj = ref($caller);
    my $class = $caller_is_obj || $caller;

    #
    # bless $self and up the ref count
    #

    my $self = bless {}, $class;

    if ( scalar(@_) == 0 )
    {
        $self->_incr_count();
        return $self;
    }

    #
    # handle arguments
    #

    my $td = $args{'typeData'};
    my $path = $td->{'path'};
    $self->setPath( path => $path );

    $self->_incr_count();

    return $self;
}

sub DESTROY
{
    $_[0]->_decr_count();
}

sub AUTOLOAD {
    use vars qw($AUTOLOAD);
    my $self = shift;
    my $type = ref($self) || croak "$self is not an obj";
    my $name = $AUTOLOAD;
    $name =~ s/.*://;   # strip fully-qualified portion
    unless (exists $self->{$name} ) {
        croak "Can't access `$name' field in obj of class $type";
    }
    if (@_) {
        return $self->{$name} = shift;
    } else {
        return $self->{$name};
    }
}

END { }

#
# Standard methods
#

sub setPath
{
    my $self = shift;
    my(%args) = @_;

    my $path = $args{'path'};

    if (defined($path))
    {
        $path =~ s:/+:/:g;
        $self->set( path => $path );
    }
}

sub getPath
{
    my $self = shift;
    my($arg) = @_;

    return $self->get("path");
}

### readFile( )
#
# reads and returns the file's contents based using the specified retrieval method
#

sub readFile
{
    my $self = shift;
    my (%args) = @_;

    my $data;
    my $path = $self->getPath();

    local ($/);

    open (IN, $path) || die "ERROR: cannot open '$path': $!";
    $/ = undef;
    $data = <IN>;
    $/ = "\n";
    close(IN);

    return $data;
}

### writeFile( data => $data )
#

sub writeFile
{
    my $self = shift;
    my (%args) = @_;

    my $data = $args{'data'};
    my $path = $self->getPath();

    #
    # write the output to $path
    #

    if ( ! -e $path )
    {
        $self->mkdirPath($path);
    }

    open(OUT, ">$path") || die "ERROR: cannot open '$path': $!";
    print OUT $data;
    close(OUT);

    return $data;
}

sub testOpen
{
    my $self = shift;
    my(%args) = @_;

    my $path = $self->getPath();

    if ( ! -f $path )
    {
        return 0;
    }

    return 1;
}

sub testSave
{
    my $self = shift;
    my(%args) = @_;

    my $path = $self->getPath();
    my $tmpPath = $path;

    if ( ! -e $path )
    {
        $tmpPath =~ s:(.*)(/[^/]*)/*$:$1:g;
        return $self->isCreatable($path);
    }

    #
    # $path exists...
    #

    if ( ! -f $path )
    {
        return 0;
    }

    #
    # $path is a file...
    #

    if ( -w $path )
    {
        return 1;
    }
}

sub isCreatable
{
    my $self = shift;
    my($path) = @_;

    while (length($path) > 0)
    {
        #
        # we take the easy way out here.  If the path exists and is writable we
        # return true.  If the path exists but isn't writable, we return false.
        #

        if ( -e $path )
        {
            if ( -d $path and -w $path )
            {
                return 1;
            }
            else
            {
                return 0;
            }
        }

        #
        # strip the last segment off the path to test for the next round.
        # eg.
        #     "/foo/bar" should become "/foo"
        #     "/foo" should become ""
        #     NOTE: if "/" doesn't exist, it's likely the system has bigger
        #           problems than trying to get the NCSA CA recognized.
        #

        $path =~ s:(.*)(/[^/]*)/*$:$1:g;
    }
}

### mkdirPath( $dirpath )
#
# given a path of one or more directories, build a complete path in the
# filesystem to match it.
#

sub mkdirPath
{
    my $self = shift;
    my($dirpath) = @_;

    #
    # watch out for extra debug stuff
    #

    $dirpath =~ s:/+:/:g;
    my $absdir = absolutePath($dirpath);

    my @directories = split(/\//, $absdir);
    my @newdirs = map { my $x = $_; $x =~ s:^\s+|\s+$|\n+::g; $x; }
                  grep { /\S/ } @directories;

    #
    # prepare for our loop
    #

    my $current_path = "";

    for my $d (@newdirs)
    {
        $current_path = $current_path . "/" . $d;

        #
        # cases where we should just go to the next iteration
        #

        if ( -d $current_path )
        {
            next;
        }

        #
        # we bomb out if we find something that exists in the filesystem
        # (and isn't a directory)
        #

        if ( -e $current_path )
        {
            return 0;
        }

        #
        # time to get to work
        #

        if ( ! myMkdir($current_path) )
        {
            return 0;
        }
    }

    return 1;
}

### myMkdir( $dir )
#
# try to create a directory
#

sub myMkdir
{
    my $self = shift;
    my($dir) = @_;
    my $result;

    # Perform the mkdir
    $result = system("mkdir $dir 2>&1");

    if ($result or $?)
    {
        return 0;
    }

    return 1;
}

### absolutePath( $file )
#
# accept a list of files and, based on our current directory, make their pathnames absolute
#

sub absolutePath
{
    my $self = shift;
    my($file) = @_;
    my $cwd = cwd();

    if ($file !~ /^\//)
    {
        $file = $cwd . "/" . $file;
    }

    return $file;
}

1; # Ensure that the module can be successfully use'd

__END__

=head1 NAME

Grid::GPT::PackageFilelist::FileIO::Disk - Perl extension for reading disk-based filelists

=head1 SYNOPSIS

  use Grid::GPT::PackageFilelist::FileIO::Disk;
  my $ac = new Grid::GPT::PackageFilelist::FileIO::Disk( );

  #
  # set/get the path of the current Disk object
  #

  $ac->setPath( path => $path );
  my $path = $ac->getPath( );

  #
  # Test this accessors open and save ability.
  #

  if ( $ac->testOpen() )
  {
      ...
  }

  if ( $ac->testSave() )
  {
      ...
  }

  #
  # Read the contents of the file and return them as a string.
  #

  my $contents = $ac->readFile( );

  #
  # Write a string to a file (this wipes out the current contents of
  # the file completely).
  #

  $ac->writeFile( data => $data );

=head1 DESCRIPTION

I<Grid::GPT::PackageFilelist::FileIO::Disk> is a file accessor designed to
work solely on files stored on a locally accessible disk.  It provides the
necessary FileIO API, and the two main functions, readFile() and writeFile()
do all of the heavy lifting regarding opening, reading, saving, and closing
files.

=head2 Type Data

One piece of information is needed for this type: the path to the file which will
be manipulated.

  $typeData = { path => $path };

=head1 AUTHOR

Chase Phillips <cphillip@ncsa.uiuc.edu>

=head1 SEE ALSO

perl(1) Grid::GPT::PackageFilelist::FileIO(1) Grid::GPT::PackageFilelist::FileIO::Tar(1)

=cut
