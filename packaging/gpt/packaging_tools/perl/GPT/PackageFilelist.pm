package Grid::GPT::PackageFilelist;

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
require Grid::GPT::PackageFilelist::flat1;
require Grid::GPT::PackageFilelist::xml1;
require Grid::GPT::PackageFilelist::List;
require Grid::GPT::PackageFilelist::FileIO;

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

    my %args = (convert => 0, @_);
    my ( $context,
         $contextData,
         $masterFilelist,
         $convert,
         $pkgname,
         $flavor,
         $pkgtype,
         $pkgnode,
       ) = (
         $args{'context'},
         $args{'contextData'},
         $args{'masterFilelist'},
         $args{'convert'},
         $args{'pkgname'},
         $args{'flavor'},
         $args{'pkgtype'},
         $args{'pkgnode'},
       );

    my $noAbsentError = $args{'noAbsentError'};
    $self->{'noAbsentError'} = $noAbsentError;

    #
    # verify we have all of our needed arguments
    #

    if (!defined($context))
    {
        die("ERROR: read context is required but undefined");
    }

    if (!defined($contextData))
    {
        die("ERROR: read data is required but undefined");
    }

    $self->{'context'} = $context;
    $self->{'contextData'} = $contextData;

    if ( defined($pkgnode) )
    {
        $self->setPkgInfo( pkgnode => $pkgnode );
    }

    $self->parseContextData( );

    #
    # store convert flag in object
    #

    if ($convert)
    {
        $self->set( convert => 1 );
    }
    else
    {
        $self->set( convert => 0 );
    }

    #
    # create our main filelist packageList object
    #

    my $packageList = new Grid::GPT::PackageFilelist::List(
                               pkginfo => $self->getPkgInfo(),
                               masterFilelist => $masterFilelist,
                               relativePath => $self->{'relativePath'},
                               );

    if (!defined($packageList))
    {
        die("ERROR: could not create list object for PackageFilelist");
    }

    $self->{'packageList'} = $packageList;

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

sub setMasterFilelist
{
    my $self = shift;
    my(%args) = @_;

    my $masterFilelist = $args{'mf'};

    $self->{'packageList'}->setMasterFilelist( mf => $args{'mf'} );
}

sub addToMasterFilelist
{
    my $self = shift;

    my $packageList = $self->{'packageList'};

    if (defined($packageList))
    {
        $packageList->addToMasterFilelist();
    }
}

sub getPkgInfo
{
    my $self = shift;
    my(%args) = @_;

    return $self->{'pkginfo'};
}

sub setPkgInfo
{
    my $self = shift;
    my(%args) = @_;

    if ( defined($self->{'pkginfo'}) )
    {
        return $self->{'pkginfo'};
    }

    if ( defined($args{'pkgnode'}) )
    {
        $self->{'pkginfo'} = $args{'pkgnode'};
        return $self->{'pkginfo'};
    }

    return undef;
}

sub parseContextData
{
    my $self = shift;
    my(%args) = @_;

    my $ctx = $self->{'context'};
    my $data = $self->{'contextData'};

    my $pd = {};
    $self->{'parsedContextData'} = $pd;

    if ($ctx eq "srcdir")
    {
        $pd->{'dir'} = $data->{'dir'};
        $self->{'relativePath'} = $pd->{'dir'};
        $self->isSourceFilelist(1);
    }
    elsif ($ctx eq "srctar")
    {
        $pd->{'tar'} = $data->{'tar'};
        $self->{'relativePath'} = "(null)";
        $self->isSourceFilelist(1);
    }
    elsif ($ctx eq "installdir")
    {
        $pd->{'dir'} = $data->{'dir'};
        $self->{'relativePath'} = $pd->{'dir'};
        $self->isSourceFilelist(0);
    }
    elsif ($ctx eq "installtar")
    {
        $pd->{'tar'} = $data->{'tar'};
        $self->{'relativePath'} = "(null)";
        $self->isSourceFilelist(0);
    }
    else
    {
        die("ERROR: unknown context type '$ctx'");
    }

    return 1;
}

sub conversionRequested
{
    my($self, %args) = @_;

    if ( $self->get("convert") )
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

sub open
{
    my $self = shift;
    my(%args) = @_;

    #
    # we use a hash for its key collision handling properties
    #

    my $filelistTypes = {};

    my $saveFilelistTypes = {};
    $self->{'saveFilelistTypes'} = $saveFilelistTypes;

    my $xml1 = $self->getXml1( );
    my $flat1 = $self->getFlat1( );

    $filelistTypes->{$xml1->getType()} = $xml1;
    $filelistTypes->{$flat1->getType()} = $flat1;

    #
    # store our triaged objects in the $typeCodes hash
    #

    my $typeCodes = {};
    $typeCodes->{'absent'} = {};
    $typeCodes->{'success'} = {};
    $typeCodes->{'error'} = {};

    #
    # for each of the filelist types, we'll attempt to open them.  based on the return code 
    # given by the type, it is triaged into one of three major groups.
    #

    my $retval;
    for my $t (values %$filelistTypes)
    {
        $retval = $t->open();
        if ($retval eq 0)
        {
            #
            # filelist of this type didn't exist
            #

            $typeCodes->{'absent'}->{$t->getType()} = $t;
        }
        elsif ($retval eq -1)
        {
            #
            # some error occurred when opening the filelist
            #

            $typeCodes->{'error'}->{$t->getType()} = $t;
        }
        elsif ($retval eq 1)
        {
            #
            # success!
            #

            $typeCodes->{'success'}->{$t->getType()} = $t;
        }
    }

    #
    # we've completed (attempting to) open all of our filelist types.  let's review and
    # act accordingly.
    #

    if ( !$self->{'noAbsentError'} and ( scalar(keys %{$typeCodes->{'success'}}) eq 0 ) )
    {
        #
        # could not find at least one suitable filelist type
        #

        return 0;
    }

    #
    # add the successful filelist types to our internal list
    #

    if ( scalar(keys %{$typeCodes->{'success'}}) > 0 )
    {
        for my $t (values %{$typeCodes->{'success'}})
        {
            $saveFilelistTypes->{$t->getType()} = $t;
        }
    }

    #
    # if conversion is needed then we add the absent filelist types to our internal list
    #

    if ( ( scalar(keys %{$typeCodes->{'absent'}}) > 0 ) and $self->conversionRequested() )
    {
        for my $t (values %{$typeCodes->{'absent'}})
        {
            $saveFilelistTypes->{$t->getType()} = $t;
        }
    }

    $self->addPackageMetadataFiles( );

    # #
    # # consider checkpointing the filelist types at this point
    # #
    # 
    # $self->save();

    return 1;
}

### addPackageMetadataFiles( )
#
# add the package metadata files to our filelist
#

sub addPackageMetadataFiles
{
    my $self = shift;
    my(%args) = @_;

    if ( $self->isSourceFilelist() )
    {
        return 0;
    }

    if ( scalar(keys %{$self->{'saveFilelistTypes'}}) > 0 )
    {
        for my $t (values %{$self->{'saveFilelistTypes'}})
        {
            $t->addMetadataFiles();
        }
    }

    #
    # make sure we add our own filelist when we build our filelist entries
    #

    $self->{'packageList'}->addMetadataFile( file => $self->getMetadataPath() );
    $self->{'packageList'}->triageMetadataFiles();

    return 1;
}

sub getMetadataPath
{
    my $self = shift;
    my(%args) = @_;

    if (!defined($self->getPkgInfo()))
    {
        return undef;
    }

    my $str = "etc/globus_packages/"
##    my $str = "etc/gpt/packages/"
              . $self->getPkgInfo()->pkgname()
              . "/pkg_data_"
              . $self->getPkgInfo()->flavor()
              . "_"
              . $self->getPkgInfo()->pkgtype()
              . ".gpt"; 

    return $str;
}

sub getXml1
{
    my $self = shift;
    my(%args) = @_;

    my $relativePath = $self->getRelativePath();

    #
    # return ref to xml1 if it's already created
    #

    my $xml1 = $self->{'xml1'};

    if (defined($xml1))
    {
        return $xml1;
    }

    #
    # create xml1
    #

    $xml1 = new Grid::GPT::PackageFilelist::xml1(
                     installdir => $self->{'installdir'},
                     pkginfo => $self->getPkgInfo(),
                     packageList => $self->{'packageList'},
                     relativePath => $relativePath,
                     isSourceFilelist => $self->isSourceFilelist(),
                     );

    if (!defined($xml1))
    {
        die("ERROR: filelist object is undefined");
        return undef;
    }

    #
    # get xml1's filelist names
    #

    my $baseName = $xml1->getFilelist( type => "read" );

    #
    # create the file accessor factory
    #

    my $fileio = new Grid::GPT::PackageFilelist::FileIO();

    #
    # build the file accessor object for reads and writes
    # pass the objects into the main filelist type object
    #

    my $readAc = $self->fetchAccessor( fileio => $fileio, baseName => $baseName );

    if ( !defined($readAc) )
    {
        die("ERROR: file accessor for filelist is undefined");
    }

    $xml1->setAc( read => $readAc, write => $readAc );

    $self->{'xml1'} = $xml1;

    return $xml1;
}

sub getRelativePath
{
    my $self = shift;
    my(%args) = @_;

    return $self->{'relativePath'};
}

sub fetchAccessor
{
    my $self = shift;
    my(%args) = @_;

    my $ctx = $self->{'context'};
    my $pd = $self->{'parsedContextData'};
    my $fileio = $args{'fileio'};
    my $file = $args{'baseName'};
    my($path, $tar);

    $fileio->reset();

    if ($ctx eq "srcdir")
    {
        $path = $pd->{'dir'} . "/" . $file;
        $fileio->setAc( type => "file", typeData => { path => $path } );
    }
    elsif ($ctx eq "srctar")
    {
        $path = $file;
        $tar = $pd->{'tar'};
        $fileio->setAc( type => "tar", typeData => { path => $path, tar => $tar } );
    }
    elsif ($ctx eq "installdir")
    {
        $path = $pd->{'dir'} . "/" . $file;
        $fileio->setAc( type => "file", typeData => { path => $path } );
    }
    elsif ($ctx eq "installtar")
    {
        $path = $file;
        $tar = $pd->{'tar'};
        $fileio->setAc( type => "tar", typeData => { path => $path, tar => $tar } );
    }
    else
    {
        die("ERROR: unknown context type '$ctx'");
    }

    my $ac = $fileio->getAccessor();

    return $ac;
}

sub getFlat1
{
    my $self = shift;
    my(%args) = @_;

    my $relativePath = $self->getRelativePath();

    #
    # return ref to flat1 if it's already created
    #

    my $flat1 = $self->{'flat1'};

    if (defined($flat1))
    {
        return $flat1;
    }

    #
    # create flat1
    #

    $flat1 = new Grid::GPT::PackageFilelist::flat1(
                     installdir => $self->{'installdir'},
                     pkginfo => $self->getPkgInfo(),
                     packageList => $self->{'packageList'},
                     relativePath => $relativePath,
                     isSourceFilelist => $self->isSourceFilelist(),
                     );

    if (!defined($flat1))
    {
        die("ERROR: filelist object is undefined");
        return undef;
    }

    #
    # get flat1's filelist name
    #

    my $baseName = $flat1->getFilelist( type => "read" );

    #
    # create the file accessor factory
    #

    my $fileio = new Grid::GPT::PackageFilelist::FileIO();

    #
    # build the file accessor object for reads and writes
    # pass the objects into the main filelist type object
    #

    my $readAc = $self->fetchAccessor( fileio => $fileio, baseName => $baseName );

    if ( !defined($readAc) )
    {
        die("ERROR: file accessor for filelist is undefined");
    }

    $flat1->setAc( read => $readAc, write => $readAc );

    $self->{'flat1'} = $flat1;

    return $flat1;
}

sub save
{
    my $self = shift;
    my $list;

    if ( scalar(keys %{$self->{'saveFilelistTypes'}}) > 0 )
    {
        $self->sort();
        $list = $self->{'packageList'}->getFilelist();

        for my $t (values %{$self->{'saveFilelistTypes'}})
        {
            $t->setFilelist( list => $list );
            $t->save();
        }
    }
}

sub stamp
{
    my($self, %args) = @_;

    my $type = $args{'type'};

    return $self->{'packageList'}->stamp( type => $type );
}

sub sort
{
    my($self, %args) = @_;

    return $self->{'packageList'}->sort( );
}

sub addFilePath
{
    my($self, %args) = @_;

    my($path) = ($args{'path'});
    return $self->{'packageList'}->addFilePath( path => $path );
}

sub removeFilePath
{
    my($self, %args) = @_;

    my($path) = ($args{'path'});
    return $self->{'packageList'}->removeFilePath( path => $path );
}

sub isEmpty
{
    my $self = shift;
    my(%args) = @_;

    return $self->{'packageList'}->isEmpty();
}

sub getFilelistFiles
{
    my $self = shift;
    my(%args) = @_;

    return $self->{'packageList'}->getFilelistFiles();
}

sub getFilelistObjects
{
    my $self = shift;
    my(%args) = @_;

    return $self->{'packageList'}->getFilelistObjects();
}

sub copyFilelist
{
    my $self = shift;
    my($src) = @_;

    my $list = $src->getFilelistObjects();
    $self->{'packageList'}->setFilelist( list => $list );
    $self->addPackageMetadataFiles( );
    $self->sort();
}

sub addFilelist
{
    my $self = shift;
    my($src) = @_;

    my $list = $src->getFilelistObjects();
    $self->{'packageList'}->addFilelist( list => $list );
    $self->sort();
}

sub isSourceFilelist
{
    my $self = shift;
    my($val) = @_;

    if (defined($val))
    {
        if ($val)
        {
            $self->{'isSourceFilelist'} = 1;
        }
        else
        {
            $self->{'isSourceFilelist'} = 0;
        }
    }

    if ($self->{'isSourceFilelist'})
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

Grid::GPT::PackageFilelist - Perl extension for reading packaging filelists

=head1 SYNOPSIS

  use Grid::GPT::PackageFilelist;
  my $fileset = new Grid::GPT::PackageFilelist(
                         context => $context,
                         contextData => $contextData,
                         pkgnode => $object,
                         masterFilelist => $me->masterFilelist,
                         convert => $convert,
                         );

  #
  # Standard filelist open and save.
  #

  $filelist->open();
  $filelist->save();

  #
  # Copy the logical filelist data from $src to $dest.
  #

  $dest->copyFilelist( $src );

=head1 DESCRIPTION

I<Grid::GPT::PackageFilelist> is used to open and save filelists of
different formats.  As part of its functioning, it applies general rules
to how each of the filelist types are used.  None of these filelist types
should be used directly.  Only the PackageFilelist object should use the
methods on these internal objects.

=head1 Contexts

This module recognizes four different contexts in which filelists exist.  It
applies different rules to each of these contexts, and policies for if/when
saving should happen.

=head2 srcdir

This represents the context where a source package resides within a certain
directory on disk.

=head2 Context Data

The data required for this context is the directory in which the package
resides.

  $contextData = { dir => $dir };

=head2 srctar

This represents the context where a source package resides within a tar
object.

=head2 Context Data

The data required for this context is the tar object.

  $contextData = { tar => $tar };

=head2 installdir

The most common context is 'installdir', given that this context is used to
read in filelists from installed packages within a GLOBUS_LOCATION on disk.

=head2 Context Data

The data required for this context is the directory in which the installation
resides.

  $contextData = { dir => $dir };

=head2 installtar

This represents the context where an entire installation resides within a tar
object.  In this context we are typically called from the PkgDist module.

=head2 Context Data

The data required for this context is the tar object.

  $contextData = { tar => $tar };

=head1 AUTHOR

Chase Phillips <cphillip@ncsa.uiuc.edu>

=head1 SEE ALSO

perl(1) Grid::GPT::PackageFilelist::flat1(1) Grid::GPT::PackageFilelist::xml1(1) Grid::GPT::PackageFile(1) Grid::GPT::GPTFilelist(1)

=cut
