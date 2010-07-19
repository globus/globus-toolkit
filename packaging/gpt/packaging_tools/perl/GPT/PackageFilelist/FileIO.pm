package Grid::GPT::PackageFilelist::FileIO;

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

require Grid::GPT::PackageFilelist::FileIO::Disk;
require Grid::GPT::PackageFilelist::FileIO::Tar;

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

    my($ppkgid) = ($args{'pkgid'});
    $self->{'pkgid'} = $ppkgid->clone();

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

sub setAc
{
    my $self = shift;
    my(%args) = @_;

    my $type = $args{'type'};
    if (defined($type))
    {
        $self->{'type'} = $type;
    }
    else
    {
        $type = $self->{'type'};
    }

    if (!defined($type))
    {
        die("ERROR: media type is undefined");
    }

    my $td = $args{'typeData'};
    if (!defined($td))
    {
        $td = {};
    }
    $self->{'typeData'} = $td;

    return 0;
}

sub getAccessor
{
    my $self = shift;
    my(%args) = @_;

    my $type = $self->{'type'};
    my $td = $self->{'typeData'};

    my $ac;

    if ( ( $type eq "local" ) or ( $type eq "file" ) )
    {
        $ac = new Grid::GPT::PackageFilelist::FileIO::Disk( typeData => $td );
    }
    elsif ( $type eq "tar" )
    {
        $ac = new Grid::GPT::PackageFilelist::FileIO::Tar( typeData => $td );
    }

    return $ac;
}

sub reset
{
    my $self = shift;

    delete($self->{'type'});
    delete($self->{'typeData'});
}

1; # Ensure that the module can be successfully use'd

__END__

=head1 NAME

Grid::GPT::PackageFilelist::FileIO - Perl extension for handling IO between multiple
contexts

=head1 SYNOPSIS

  use Grid::GPT::PackageFilelist::FileIO;
  my $fileio = new Grid::GPT::PackageFilelist::FileIO();

  #
  # Set the FileIO object to use a certain file accessor type and fetch
  # an object of that type.
  #

  $self->setAc( type => $type, typeData => $typeData );
  my $ac = $self->getAccessor( );

  #
  # Reset the FileIO object so that it doesn't know about any particular
  # file accessor type.
  #

  $self->reset( );

=head1 DESCRIPTION

I<Grid::GPT::PackageFilelist::FileIO> is a filelist file accessor
factory.  It's meant to only be used by the PackageFilelist object.
Based on the types of files it will be accessing it will return
different objects, but they should all have the same simple API.

=head1 Types

=head2 local, file

Specifies that the input is of type file, and that, upon a call to getAccessor(),
a file accessor of that type will be returned to the calling routine.

=head2 tar

Specifies that the input is of type tar, and that, upon a call to getAccessor(),
a file accessor of that type will be returned to the calling routine.

=head1 AUTHOR

Chase Phillips <cphillip@ncsa.uiuc.edu>

=head1 SEE ALSO

perl(1) Grid::GPT::PackageFilelist(1) Grid::GPT::PackageFilelist::FileIO::Tar(1) Grid::GPT::PackageFilelist::FileIO::Disk(1)

=cut
