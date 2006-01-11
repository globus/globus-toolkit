package Grid::GPT::PackageFilelist::xml1::IO;

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

require Grid::GPT::V1::XML;
require Grid::GPT::PackageFile;
require Grid::GPT::GPTIdentity;

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

### readFilelist( filelistobj => $filelistobj )
#
# reads in the filelist data, adding each entry to an internal Filelist object
#

sub readFilelist
{
    my($self, %args) = @_;

    #
    # pull the filelist data object into our scope
    #

    my $filelistobj = $args{'filelistobj'};
    my $data = $self->{'readAc'}->readFile();

    if (!defined($data))
    {
        return 0;
    }

    #
    # start reading in the xml file
    #

    my $xml = new Grid::GPT::V1::XML;
    $xml->read($data);

    my $root = $xml->{'roottag'};

    my $fm = {};

    $fm->{'Name'} = $root->{'attributes'}->{'Name'};
    $filelistobj->set( formatVersion => $root->{'attributes'}->{'FormatVersion'} );

    # Check to see if we can understand this format

    $fm->{'doctype'} = $xml->{'doctype'};
    $fm->{'system'} = $xml->{'system'};

    for my $c (@{$root->{'contents'}})
    {
        next if ref($c) ne 'HASH';

        #
        # Note: We're not reading the PackagingTool information right now.  FYI, this filelist type may
        # be changed in the future to behave in certain ways based on FormatVersion and PackagingTool.
        #

        if ($c->{'name'} eq 'PackageType')
        {
            $fm->{'PackageType'} = $c->{'contents'}->[0];
            next;
        }

        if ($c->{'name'} eq 'Flavor')
        {
            $fm->{'Flavor'} = $c->{'contents'}->[0];
            next;
        }

        if ($c->{'name'} eq 'Files')
        {
            # Extract each file
            for my $bc (@{$c->{'contents'}})
            {
                next if ref($bc) ne 'HASH';

                if ($bc->{'name'} eq 'File')
                {
                    #
                    # create a new File object to handle the incoming data
                    #

                    my $file = new Grid::GPT::PackageFile(
                                     pkginfo => $self->{'pkginfo'},
                                     relativePath => $self->{'relativePath'},
                                     );

                    #
                    # create a new temporary file structure
                    #

                    # Extract each file's metadata
                    for my $cc (@{$bc->{'contents'}})
                    {
                        next if ref($cc) ne 'HASH';

                        if ($cc->{'name'} eq 'Path')
                        {
                            # $file->{'path'} = $cc->{'contents'}->[0];
                            my $filePath = $cc->{'contents'}->[0];
                            $filePath =~ s:^\s+|\s+$::g;
                            $filePath =~ s:/+:/:g;
                            $filePath =~ s:^/+::g;

                            $file->setPath( path => $filePath );
                            next;
                        }

                        if ($cc->{'name'} eq 'Checksums')
                        {
                            my $md5 = {};

                            # Extract each file's checksum information
                            for my $dc (@{$cc->{'contents'}})
                            {
                                next if ref($dc) ne 'HASH';

                                if ($dc->{'name'} eq 'Stamp')
                                {
                                    my $md5_type = $dc->{'attributes'}->{'Type'};
                                    my $md5_value = $dc->{'contents'}->[0];
                                    $file->setMD5( type => $md5_type, value => $md5_value );
                                    $md5->{$md5_type} = $md5_value;
                                }
                            }

                            next;
                        }
                    }

                    #
                    # we have a file structure.  call addFile on the filelist object
                    #

                    $filelistobj->addFile( file => $file );
                }
            }

            next;
        }
    }

    return 1;
}

sub writeFilelist
{
    my($self, %args) = @_;

    #
    # pull the filelist data object into our scope
    #

    my $filelistobj = $args{'filelistobj'};
    my $writer = new Grid::GPT::V1::XML();
    my $fm = $self->{fm};
  
    $writer->doctype("gpt_package_filelist","gpt_filelist.dtd");
    my $pkgname = "";
    $pkgname = $self->{'pkginfo'}->pkgname() if defined($self->{'pkginfo'});
    $writer->startTag("PackageFilelist", Name => $pkgname, FormatVersion => "0.01");
    $writer->characters("\n");

    #
    # write out the packaging tool and version that made this xml file.
    #

    $writer->emptyTag("PackagingTool", ToolName => "GPT", ToolVersion => Grid::GPT::GPTIdentity::gpt_version());
    $writer->characters("\n");

    # Write out Flavor
    my $flavor = "";
    $flavor = $self->{'pkginfo'}->flavor() if defined($self->{'pkginfo'});
    if (defined $flavor)
    {
        $writer->dataElement('Flavor', $flavor);
        $writer->characters("\n");
    }

    # Write out PackageType
    my $pkgtype = "";
    $pkgtype = $self->{'pkginfo'}->pkgtype() if defined($self->{'pkginfo'});
    if (defined $pkgtype)
    {
        $writer->dataElement('PackageType', $pkgtype);
        $writer->characters("\n");
    }

    #Write out Filelist
    if ( !$filelistobj->isEmpty() )
    {
        $writer->startTag("Files");
        $writer->characters("\n");

        for my $f (@{$filelistobj->getList()})
        {
            $writer->startTag("File");
            $writer->characters("\n");

            my $path = $f->path();
            $path =~ s:/+:/:g;         # only one slash at a time
            $path =~ s:^\s+|\s+$::g;   # remove leading and trailing whitespace
            $path =~ s:^/+::g;         # remove leading slash

            $writer->dataElement('Path', $path);
            $writer->characters("\n");

            if ( $f->hasMD5() )
            {
                $writer->startTag("Checksums");
                $writer->characters("\n");

                my %stamps = $f->getMD5();
                for my $s (keys %stamps)
                {
                    if (defined($stamps{$s}))
                    {
                        my %args;
                        $args{'Type'} = $s if defined $stamps{$s};
                        $writer->dataElement('Stamp', $stamps{$s}, %args);
                        $writer->characters("\n");
                    }
                }

                $writer->endTag("Checksums");
                $writer->characters("\n");
            }

            $writer->endTag("File");
            $writer->characters("\n");
        }

        $writer->endTag("Files");
        $writer->characters("\n");
    }

    $writer->endTag("PackageFilelist");
    $self->{'writeAc'}->writeFile( data => $writer->dump() );
}

### testOpen( )
#
# test the filelist path to see if a filelist for this object is present
#

sub testOpen
{
    my($self, %args) = @_;

    return $self->{'readAc'}->testOpen();
}

### testSave( )
#
# test the filelist path to see if a filelist for this object is writable
#

sub testSave
{
    my($self, %args) = @_;

    return $self->{'writeAc'}->testSave();
}

1;

__END__

=head1 NAME

Grid::GPT::PackageFilelist::xml1::IO - Perl extension for I/O operations for xml1 filelists

=head1 SYNOPSIS

  use Grid::GPT::PackageFilelist::xml1::IO;
  my $io = new Grid::GPT::PackageFilelist::xml1::IO();

=head1 DESCRIPTION

I<Grid::GPT::PackageFilelist::xml1::IO> handles the actual format decisions
for xml1 filelist types.  It interfaces with the accessor which was passed
into the filelist type by the PackageFilelist object, performing tests, opens,
reads, writes, and closes.

=head1 AUTHOR

Chase Phillips <cphillip@ncsa.uiuc.edu>

=head1 SEE ALSO

perl(1) Grid::GPT::PackageFilelist::xml1(1) Grid::GPT::PackageFilelist::xml1::ListInterface(1)

=cut
