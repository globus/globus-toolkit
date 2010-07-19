package Grid::GPT::PackageFilelist::flat1::IO;

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

    my $pkginfo = $args{'pkginfo'};
    my $relativePath = $args{'relativePath'};

    if ( defined($pkginfo) )
    {
        $self->{'pkginfo'} = $pkginfo;
    }

    #
    # verify we have all of our needed arguments
    #

    $self->{'relativePath'} = $relativePath;

    #
    # incr refcount
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

sub setAc
{
    my $self = shift;
    my(%args) = @_;

    $self->{'readAc'} = $args{'read'};
    $self->{'writeAc'} = $args{'write'};

    return 1;
}

### readFilelist( filelistobj => $filelistobj, data => $data )
#
# reads in the filelist data, adding each entry to an internal Filelist object
#

sub readFilelist
{
    my $self = shift;
    my(%args) = @_;

    #
    # pull the filelist data object into our scope
    #

    my $filelistobj = $args{'filelistobj'};
    my $data = $self->{'readAc'}->readFile();

    #
    # read in the entire list
    #

    my @list = split(/\n/, $data);
    chomp @list; # remove carriage returns

    #
    # remove any duplicates from the list
    #

    for my $e (@list)
    {
        $e =~ s:^\s+|\s+$::g;
        $e =~ s:/+:/:g;
        $e =~ s:^/+::g;
        if (length($e) < 1)
        {
            next;
        }

        #
        # create a new File object to handle the incoming path
        #

        my $file = new Grid::GPT::PackageFile(
                          pkginfo => $self->{'pkginfo'},
                          relativePath => $self->{'relativePath'},
                          );

        $file->setPath( path => $e );
        $filelistobj->addFile( file => $file );
    }

    return;
}

### writeFilelist( filelistobj => $filelistobj )
#
# saves the filelist data to the package's filelist
#

sub writeFilelist
{
    my ($self, %args) = @_;

    #
    # pull the filelist data object into our scope
    #

    my $filelistobj = $args{'filelistobj'};

    #
    # get the list of files from the Filelist object
    #

    my $list = $filelistobj->getList();

    #
    # write out the entire list
    #

    my $data;
    for my $f (@$list)
    {
        my $path = $f;
        $path =~ s:/+:/:g;         # only one slash at a time
        $path =~ s:^\s+|\s+$::g;   # remove leading and trailing whitespace
        $path =~ s:^/+::g;         # remove leading slash

        $data .= "/$path\n";
    }

    $self->{'writeAc'}->writeFile( data => $data );

    return 1;
}

### testOpen( )
#
# test the filelist path to see if a filelist for this object is present
#

sub testOpen
{
    my($self, %args) = @_;

    #
    # pull the filelist data object into our scope
    #

    return $self->{'readAc'}->testOpen();
}

### testSave( )
#
# test the filelist path to see if a filelist for this object is writable
#

sub testSave
{
    my($self, %args) = @_;

    #
    # pull the filelist data object into our scope
    #

    return $self->{'writeAc'}->testSave();
}

1; # Ensure that the module can be successfully use'd

__END__

=head1 NAME

Grid::GPT::PackageFilelist::flat1::IO - Perl extension for I/O operations for flat1 filelists

=head1 SYNOPSIS

  use Grid::GPT::PackageFilelist::flat1::IO;
  my $io = new Grid::GPT::PackageFilelist::flat1::IO();

=head1 DESCRIPTION

I<Grid::GPT::PackageFilelist::flat1::IO> handles the actual format decisions
for flat1 filelist types.  It interfaces with the accessor which was passed
into the filelist type by the PackageFilelist object, performing tests, opens,
reads, writes, and closes.

=head1 AUTHOR

Chase Phillips <cphillip@ncsa.uiuc.edu>

=head1 SEE ALSO

perl(1) Grid::GPT::PackageFilelist::flat1(1) Grid::GPT::PackageFilelist::flat1::ListInterface(1)

=cut
