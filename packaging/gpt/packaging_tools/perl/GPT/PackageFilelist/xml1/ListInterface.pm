package Grid::GPT::PackageFilelist::xml1::ListInterface;

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

require Grid::GPT::PackageFile;

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
 
    my (
         $packageList,
       ) = (
         $args{'packageList'},
       );

    #
    # store the packageList object
    #

    if (!defined($packageList))
    {
        die("ERROR: package list is undefined");
    }

    $self->{'packageList'} = $packageList;

    #
    # increment refcount
    #

    $self->_incr_count();

    return $self;
}

sub DESTROY
{
    $_[0]->_decr_count();
}

sub AUTOLOAD
{
}

END { }

#
# Standard methods
#

### addFile( file => $file )
#
# add file to the package's filelist
#

sub addFile
{
    my($self, %args) = @_;

    #
    # handle arguments
    #

    my $file = $args{'file'};

    if ( !defined($file) )
    {
        die("ERROR: file object in package list is undefined");
    }

    $self->{'packageList'}->addFile( file => $file );

    return 1;
}

### getList( )
#
# return a reference to an array that contains all of the files in the
# current filelist
#

sub getList
{
    my($self, %args) = @_;

    #
    # for each of the entries in our filelist, get the path and add it to our list
    #

    my $filelist = $self->{'packageList'}->getFilelist();

    return $filelist;
}

sub isEmpty
{
    my($self, %args) = @_;

    #
    # pull our filelist array into our scope
    #

    my $filelist = $self->{'packageList'}->getFilelist();

    if ( scalar(@$filelist) eq 0 )
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

1; # Ensure that the module can be successfully use'd

__END__

=head1 NAME

Grid::GPT::PackageFilelist::xml1::ListInterface - Perl extension for List operations for xml1 filelists

=head1 SYNOPSIS

  use Grid::GPT::PackageFilelist::xml1::ListInterface;
  my $io = new Grid::GPT::PackageFilelist::xml1::ListInterface();

=head1 DESCRIPTION

I<Grid::GPT::PackageFilelist::xml1::ListInterface> handles adding to and reading
from the PackageFilelist::List object when necessary.

=head1 AUTHOR

Chase Phillips <cphillip@ncsa.uiuc.edu>

=head1 SEE ALSO

perl(1) Grid::GPT::PackageFilelist::xml1(1) Grid::GPT::PackageFilelist::xml1::IO(1)

=cut
