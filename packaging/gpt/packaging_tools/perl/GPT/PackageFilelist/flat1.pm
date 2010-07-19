package Grid::GPT::PackageFilelist::flat1;

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

require Grid::GPT::PackageFilelist::flat1::ListInterface;
require Grid::GPT::PackageFilelist::flat1::IO;

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

    my %args = (installdir => $ENV{'GLOBUS_LOCATION'}, @_);

    my $installdir = $args{'installdir'};
    my $packageList = $args{'packageList'};
    my $pkginfo = $args{'pkginfo'};
    my $relativePath = $args{'relativePath'};
    my $isSourceFilelist = $args{'isSourceFilelist'};

    #
    # verify we have all of our needed arguments
    #

    if ( defined($pkginfo) )
    {
        $self->{'pkginfo'} = $pkginfo;
    }

    #
    # store the packageList object
    #

    if (!defined($packageList))
    {
        die("ERROR: package list is undefined");
    }

    $self->{'packageList'} = $packageList;

    #
    # create new Filelist object and store a reference to it in $self
    #

    my $filelistobj = new Grid::GPT::PackageFilelist::flat1::ListInterface( packageList => $packageList );
    $self->{'filelistobj'} = $filelistobj;

    if ( $isSourceFilelist )
    {
        $self->setFilelist( read => "filelist" );
    }
    else
    {
        my($name, $pkgtype, $flavor);

        $name = $pkginfo->pkgname();
        $flavor = $pkginfo->flavor();
        $pkgtype = $pkginfo->pkgtype();

        my $tmpPath = "etc/globus_packages/" . $name . "/" . $flavor . "_" . $pkgtype . ".filelist";
        $self->setFilelist( read => $tmpPath );
    }

    #
    # create an IO object to handle reading and writing the filelist
    #

    my $io = new Grid::GPT::PackageFilelist::flat1::IO( pkginfo => $pkginfo, relativePath => $relativePath );

    if (!defined($io))
    {
        die("ERROR: filelist io object is undefined");
        return undef;
    }

    $self->{'io'} = $io;

    #
    # increment our object count
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

sub addMetadataFiles
{
    my $self = shift;
    my(%args) = @_;

    my $packageList = $self->{'packageList'};

    $packageList->addMetadataFile( file => $self->getFilelist( type => "read" ) );
    $packageList->addMetadataFile( file => $self->getFilelist( type => "write" ) );
}

sub setAc
{
    my $self = shift;
    my(%args) = @_;

    $self->{'io'}->setAc( read => $args{'read'}, write => $args{'read'} );

    return 1;
}

sub setFilelist
{
    my $self = shift;
    my(%args) = @_;

    $self->{'readFilelistName'} = $args{'read'};
    $self->{'writeFilelistName'} = $args{'read'};

    return 1;
}

sub getFilelist
{
    my $self = shift;
    my(%args) = @_;

    my $type = $args{'type'};

    if (defined($type))
    {
        if ($type eq "read")
        {
            return $self->{'readFilelistName'};
        }
        elsif ($type eq "write")
        {
            return $self->{'writeFilelistName'};
        }
    }

    return undef;
}

sub open
{
    my($self, %args) = @_;

    #
    # pull the filelist data object into our scope
    #

    my $filelist = $self->{'filelistobj'};
    my $io = $self->{'io'};

    if ( ! $io->testOpen() )
    {
        return 0;
    }

    $io->readFilelist(filelistobj => $filelist);

    return 1;
}

sub save
{
    my($self, %args) = @_;

    #
    # pull the filelist data object into our scope
    #

    my $filelist = $self->{'filelistobj'};
    my $io = $self->{'io'};

    if ( ! $io->testSave() )
    {
        return 0;
    }

    $io->writeFilelist(filelistobj => $filelist);

    return 1;
}

sub getType
{
    my($self, %args) = @_;

    return "flat1";
}

1; # Ensure that the module can be successfully use'd

__END__

=head1 NAME

Grid::GPT::PackageFilelist::flat1 - Perl extension for reading version 1 flat filelists

=head1 SYNOPSIS

  use Grid::GPT::PackageFilelist::flat1;
  my $fl = new Grid::GPT::PackageFilelist::flat1();

=head1 DESCRIPTION

I<Grid::GPT::PackageFilelist::flat1> is the extension for reading in
filelist data from version 1 flat filelists, which was the only format
available in versions of GPT earlier than 2.2.  This should generally
be self-contained within the PackageFilelist grouping.

=head1 AUTHOR

Chase Phillips <cphillip@ncsa.uiuc.edu>

=head1 SEE ALSO

perl(1) Grid::GPT::PackageFilelist(1)

=cut
