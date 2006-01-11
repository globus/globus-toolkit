package Grid::GPT::PackageFilelist::List;

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
    my $masterFilelist = $args{'masterFilelist'};
    my $relativePath = $args{'relativePath'};

    if ( defined($pkginfo) )
    {
        $self->{'pkginfo'} = $pkginfo;
    }

    #
    # store our relativePath
    #

    $self->{'relativePath'} = $relativePath;

    #
    # store a reference to our master filelist
    #

    $self->setMasterFilelist( mf => $masterFilelist );

    #
    # create our internal filelist structure
    #

    $self->{'filelist'} = {};
    $self->{'filelistOrder'} = [];

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

### addToMasterFilelist( )
#
# add all of the files stored internally to the master filelist
#

sub addToMasterFilelist
{
    my($self, %args) = @_;

    if (defined($self->{'masterFilelist'}))
    {
        my $list = $self->getFilelistObjects();

        for my $f (@$list)
        {
            $self->{'masterFilelist'}->addFile( file => $f );
        }
    }
}

### setMasterFilelist( mf => $masterFilelist )
#
# set the master filelist to which we should add files
#

sub setMasterFilelist
{
    my($self, %args) = @_;

    $self->{'masterFilelist'} = $args{'mf'};
}

### addFile( file => $file )
#
# add file to our internal filelist
#

sub addFile
{
    my($self, %args) = @_;

    #
    # handle arguments
    #

    my $file = $args{'file'};
    my $filePath = $file->getPath();

    if ( !defined($file) )
    {
        die("ERROR: file object in package list is undefined");
    }

    if ( ! grep { $file->isEqual($_) } values %{$self->{'filelist'}} )
    {
        # add the file to our internal filelist
        $self->{'filelist'}->{$filePath} = $file;
        push(@{$self->{'filelistOrder'}}, $filePath);

        if (defined($self->{'masterFilelist'}))
        {
            $self->{'masterFilelist'}->addFile( file => $file );
        }

        return 1;
    }

    # the file is in our internal list already, but lets check to see if this listing
    # has any extra information

    my $storedFile = $self->{'filelist'}->{$filePath};

    if ( !$file->md5IsAllowed() )
    {
        $storedFile->turnOffMD5();
    }

    if ( $storedFile->groomMD5( file => $file ) )
    {
        return 1;
    }

    return 0;
}

### addFilePath( path => $path )
#
# add our file matching path to our internal filelist
#

sub addFilePath
{
    my($self, %args) = @_;

    #
    # handle arguments
    #

    my $filePath = $args{'path'};
    my $file = new Grid::GPT::PackageFile(
                      pkginfo => $self->{'pkginfo'},
                      relativePath => $self->{'relativePath'},
                      );

    $file->setPath( path => $filePath );

    return $self->addFile( file => $file );
}

### removeFile( file => $file )
#
# remove our file from our internal filelist
#

sub removeFile
{
    my($self, %args) = @_;

    #
    # handle arguments
    #

    my $file = $args{'file'};
    my $filePath = $file->getPath();

    if ( !defined($file) )
    {
        die("ERROR: file object in package list is undefined");
    }

    if (defined($self->{'masterFilelist'}))
    {
        $self->{'masterFilelist'}->removeFile( file => $file );
    }

    if ( grep { $file->isEqual($_) } values %{$self->{'filelist'}} )
    {
        # add the file to our internal filelist
        delete($self->{'filelist'}->{$filePath});

        my @neworder = map { $_ }
                       grep
                       {
                          $_ ne $filePath;
                       } @{$self->{'filelistOrder'}};

        $self->{'filelistOrder'} = \@neworder;

        return 1;
    }

    return 0;
}

### removeFilePath( path => $path )
#
# remove our file matching path from our internal filelist
#

sub removeFilePath
{
    my($self, %args) = @_;

    #
    # handle arguments
    #

    my $filePath = $args{'path'};

    if ( defined($self->{'filelist'}->{$filePath}) )
    {
        $self->{'filelist'}->{$filePath}->active(0);
    }

    return 1;
}

sub cleanupList
{
    my $self = shift;

    #
    # cleanup the filelist hash
    #

    if (defined($self->{'filelist'}))
    {
        map {
                if ( defined($self->{'filelist'}->{$_}) and !$self->{'filelist'}->{$_}->isActive() )
                {
                    delete($self->{'filelist'}->{$_});
                }
            } keys %{$self->{'filelist'}};
    }

    #
    # cleanup the filelistOrder array
    #

    my @newOrder;

    if (defined($self->{'filelistOrder'}))
    {
        @newOrder = map { $_; }
                    grep {
                             if ( defined($self->{'filelist'}->{$_}) and $self->{'filelist'}->{$_}->isActive() )
                             {
                                 $_;
                             }
                         } @{$self->{'filelistOrder'}};
        $self->{'filelistOrder'} = \@newOrder;
    }
}

### getList( )
#
# return a reference to an array that contains all of the files in the
# current filelist
#

sub getList
{
    my $self = shift;

    $self->cleanupList();

    #
    # in order of the filelist order array, create a list of entries that contains
    # each of the files in the internal filelist.
    #

    my @list = map { $self->{'filelist'}->{$_} } @{$self->{'filelistOrder'}};

    return \@list;
}

sub sort
{
    my $self = shift;

    my @sorted = sort(keys %{$self->{'filelist'}});
    $self->{'filelistOrder'} = \@sorted;

    return 1;
}

### getFilelist( )
#
# return a reference to an array that contains all of the files in the
# current filelist
#

sub getFilelist
{
    my $self = shift;

    return $self->getList();
}

### stamp( type => $type )
#
# stamp each of the files in our list with their current md5 checksums
#

sub stamp
{
    my $self = shift;
    my(%args) = @_;

    my $type = $args{'type'};

    for my $f (values %{$self->{'filelist'}})
    {
        $f->stamp(type => $type);
    }

    return 1;
}

sub addMetadataFile
{
    my $self = shift;
    my(%args) = @_;

    if ( !defined($self->{'metadataFiles'}) )
    {
        $self->{'metadataFiles'} = [];
    }

    my $file = $args{'file'};

    if ( ! grep(/^$file$/, @{$self->{'metadataFiles'}}) )
    {
        push(@{$self->{'metadataFiles'}}, $file);
    }
}

sub triageMetadataFiles
{
    my $self = shift;

    #
    # add each of the entries in our metadata filelist to our internal filelist
    #

    my $metadataFiles = $self->{'metadataFiles'};

    for my $f (@{$self->{'metadataFiles'}})
    {
        $self->addFilePath( path => $f );
    }

    #
    # now we go through our internal filelist and turn off md5 checksums for each of the entries
    #

    my $list = $self->{'filelist'};

    my @metadataKeys = map { $_ } grep { my $x = $_; grep(/^\Q$x\E$/, @$metadataFiles); } keys %$list;

    for my $m (@metadataKeys)
    {
        $list->{$m}->turnOffMD5();
    }
}

sub isEmpty
{
    my $self = shift;

    #
    # pull our filelist array into our scope
    #

    my $filelist = $self->getList();

    if ( scalar(@$filelist) eq 0 )
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

sub setFilelist
{
    my $self = shift;
    my(%args) = @_;

    #
    # read in the list of objects
    #

    my @list = @{$args{'list'}};
    my $tmpFilelist = \@list;

    #
    # nuke the old filelist data
    #

    $self->{'filelist'} = {};
    $self->{'filelistOrder'} = [];

    for my $file (@$tmpFilelist)
    {
        my $tmpFile = $file->clone();
        my $path = $tmpFile->getPath();

        $tmpFile->setPkgNode( node => $self->{'pkginfo'} );

        $self->{'filelist'}->{$path} = $tmpFile;
        if ( !grep(/^$path$/, @{$self->{'filelistOrder'}}) )
        {
            push(@{$self->{'filelistOrder'}}, $path);
        }
    }
}

sub addFilelist
{
    my $self = shift;
    my(%args) = @_;

    #
    # read in the list of objects
    #

    my @list = @{$args{'list'}};
    my $tmpFilelist = \@list;

    for my $file (@$tmpFilelist)
    {
        my $tmpFile = $file->clone();
        my $path = $tmpFile->getPath();

        $tmpFile->setPkgNode( node => $self->{'pkginfo'} );

        $self->{'filelist'}->{$path} = $tmpFile;
        if ( !grep(/^$path$/, @{$self->{'filelistOrder'}}) )
        {
            push(@{$self->{'filelistOrder'}}, $path);
        }
    }
}

sub getFilelistFiles
{
    my $self = shift;

    if ( $self->isEmpty() )
    {
        return [];
    }

    my $tempList = $self->getList();
    my @list = map { $_->getPath() } @$tempList;

    return \@list;
}

sub getFilelistObjects
{
    my $self = shift;

    if ( $self->isEmpty() )
    {
        return [];
    }

    my $list = $self->getList();

    return $list;
}

1; # Ensure that the module can be successfully use'd

__END__

=head1 NAME

Grid::GPT::PackageFilelist::List - Perl extension for storing internal file
object listings

=head1 SYNOPSIS

  use Grid::GPT::PackageFilelist::List;
  my $md5 = new Grid::GPT::PackageFilelist::List(
                           masterFilelist => $masterFilelist,
                           pkginfo => $pkginfo,
                           relativePath => $relativePath,
                           );

=head1 DESCRIPTION

I<Grid::GPT::PackageFilelist::List> is the internal list of file objects
that each of the filelist types add to via their ListInterface objects.  This
List object also optionally stores a reference to the master filelist object
and will, if this master filelist is defined, add each file object to it
as well as adding it to its internal list.

=head1 AUTHOR

Chase Phillips <cphillip@ncsa.uiuc.edu>

=head1 SEE ALSO

perl(1) Grid::GPT::PackageFilelist(1) Grid::GPT::GPTFilelist(1)

=cut
