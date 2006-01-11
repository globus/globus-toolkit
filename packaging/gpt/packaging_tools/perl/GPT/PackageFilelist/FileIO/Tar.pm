package Grid::GPT::PackageFilelist::FileIO::Tar;

$VERSION = 1.00;

use strict;
use vars qw( $AUTOLOAD @ISA @EXPORT ); # Keep 'use strict' happy
use Carp;

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
    my $tar = $td->{'tar'};
    my $path = $td->{'path'};
    $self->setPath( tar => $tar, path => $path );

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

    if (defined($args{'path'}))
    {
        $self->set( path => $args{'path'} );
    }

    if (defined($args{'tar'}))
    {
        $self->set( tar => $args{'tar'} );
    }
}

sub getPath
{
    my $self = shift;
    my($arg) = @_;

    return $self->get("path");
}

sub getTar
{
    my $self = shift;
    my($arg) = @_;

    return $self->get("tar");
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
    my $tar = $self->getTar();
    my $path = $self->getPath();
    $path =~ s:\.:\\\.:g;       # just in case the . in the string is causing a match on '_', as well

    my @tarfiles = $tar->list_files();
    my @gptfiles = grep { /$path$/ } @tarfiles;    # we match at the end of the string (the filelist
                                                   # is not a directory descriptor

    if (! @gptfiles)
    {
        return undef;
    }

    if (@gptfiles > 1) {
        print "Warning: multiple filelists found.\n";
        for (@gptfiles) {
            print "$_\n";
        }
    }

    $data = $tar->get_content($gptfiles[0]);

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

    return undef;
}

sub testOpen
{
    my $self = shift;
    my(%args) = @_;

    my $tar = $self->getTar();

    if (!defined($tar))
    {
        return 0;
    }

    return 1;
}

sub testSave
{
    my $self = shift;
    my(%args) = @_;

    return 0;
}

1; # Ensure that the module can be successfully use'd

__END__

=head1 NAME

Grid::GPT::PackageFilelist::FileIO::Tar - Perl extension for reading tar-based filelists

=head1 SYNOPSIS

  use Grid::GPT::PackageFilelist::FileIO::Tar;
  my $ac = new Grid::GPT::PackageFilelist::FileIO::Tar( );

  #
  # set/get the path of the current Disk object
  #

  $ac->setPath( path => $path, tar => $tar );
  my $path = $ac->getPath( );
  my $tar = $ac->getTar( );

  #
  # Test this accessors open and save ability.  Test save always returns
  # 0. (We can't save to files through tar objects - yet.)
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

I<Grid::GPT::PackageFilelist::FileIO::Tar> is a file accessor designed to
work solely on files stored within a tar object.  It provides the necessary
FileIO API, and the two main functions, readFile() and writeFile() do all of
the heavy lifting regarding opening, reading, and closing files.

=head2 Type Data

Two pieces of information are needed for this type: the path to the file which
will be manipulated, and a reference to the tar object through which the file
can be accessed.  Note that $path can be a partial path since we are currently
searching through the tar for any sufficient matches.

  $typeData = { path => $path, tar => $tar };

=head1 AUTHOR

Chase Phillips <cphillip@ncsa.uiuc.edu>

=head1 SEE ALSO

perl(1) Grid::GPT::PackageFilelist::FileIO(1) Grid::GPT::PackageFilelist::FileIO::Disk(1)

=cut
