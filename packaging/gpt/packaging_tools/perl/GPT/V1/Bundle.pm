package Grid::GPT::V1::Bundle;

use Archive::Tar;
use File::Copy;
use File::Basename;
use strict;
use Carp;
use Cwd;

use Grid::GPT::V1::Package;
use Grid::GPT::V1::XML;
use Grid::GPT::V1::BuildFlavors;
use Grid::GPT::PkgDist;
use Grid::GPT::GPTObject;
use Grid::GPT::PkgDefsSet;
use Grid::GPT::V1::Version;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

# set the version for version checking
$VERSION     = 0.01;

@ISA         = qw(Exporter Grid::GPT::GPTObject);
@EXPORT      = qw(&open_metadata_file &func2 &func4);
%EXPORT_TAGS = ( );     # eg: TAG => [ qw!name1 name2! ],

# make all your functions, whether exported or not;
# remember to put something interesting in the {} stubs


sub new 
{
  my ($class, %args) = @_;

  my $self  = {
               PackageList   => undef,
               BundleDocs    => undef,
               Version       => undef,
               Description   => undef,
               bundleStab    => undef,
               versionLabel  => undef,
               ContactInfo   => undef,
               Name          => undef,
               Packages      => undef,
               PkgDefs       => undef,
               BundleDefFile => undef,
               FileName      => undef,
               tmpdir        => $args{'tmpdir'},
               log           => $args{'log'},
  };

  bless $self, $class;
  return $self;
} 


sub read_metadata_file 
{
  my $self                 = shift; 
  my $file                 = shift;

  if (!defined $file)
  {
    return undef;
  }

  $self->{'BundleDefFile'} = $file;

  my $xml                  = new Grid::GPT::V1::XML;

  $xml->read($file);

  my $root                 = $xml->{'roottag'};

  $self->{'Name'}          = $root->{'attributes'}->{'Name'};

# Check to see if we can understand this format

  $self->{'doctype'}       = $xml->{'doctype'};
  $self->{'system'}        = $xml->{'system'};

  for my $c (@{$root->{'contents'}}) 
  {
    next if ref($c) ne 'HASH';

    if( $c->{'name'} eq 'FileName' )
    {
      $self->{'FileName'} = $c->{'contents'}->[0];
      next;
    }

    if ($c->{'name'} eq 'BundleInfo') 
    {
      for my $sc (@{$c->{'contents'}}) 
      {
        next if ref($sc) ne 'HASH';

        if ($sc->{'name'} eq 'Description') 
        {
          $self->{'Description'} = $sc->{'contents'}->[0];
          next;
        }

        if ($sc->{'name'} eq 'PackagingTool') 
        {
          $self->addPackagingTool( tool => $sc->{'attributes'}->{'ToolName'},
                                   ver  => $sc->{'attributes'}->{'ToolVersion'}
                                 );
          next;
        }

        if ($sc->{'name'} eq 'ContactInfo') 
        {
          $self->addContact( name  => $sc->{'attributes'}->{'ContactName'},
                             email => $sc->{'attributes'}->{'ContactEmail'}
                           );
          next;
        }

        if ($sc->{'name'} eq 'BundleDocs') 
        {
          $self->addBundleDoc( desc => $sc->{'attributes'}->{'BundleDocsDesc'},
                               url  => $sc->{'attributes'}->{'BundleDocsURL'}
                             );
          next;
        }

        if ($sc->{'name'} eq 'ComponentInformation') 
        {
          $self->addComponentName( $sc->{'attributes'}->{'ComponentName'} );

          for my $dc (@{$sc->{'contents'}}) 
          {
            next if ref($dc) ne 'HASH';

            if ($dc->{'name'} eq 'Description') 
            {
              $self->addComponentDesc( $dc->{'contents'}->[0] );
              next;
            }

            if ($dc->{'name'} eq 'VersionLabel') 
            {
               $self->addComponentVer( $dc->{'contents'}->[0] );
              next;
            }
          }
          next;
        }
      }
      next;
    }

    if ($c->{'name'} eq 'BundleReleaseInfo') 
    {
      for my $sc (@{$c->{'contents'}}) 
      {
        next if ref($sc) ne 'HASH';

        if ($sc->{'name'} eq 'BundleStability') 
        {
          $self->{'bundleStab'}   = $sc->{'attributes'}->{'Release'};
          next;
        }

        if( $sc->{'name'} eq 'BundleVersion' )
        {
          $self->{'Version'} = new Grid::GPT::V1::Version(obj => $sc );
        }

        if ($sc->{'name'} eq 'VersionLabel') 
        {
          $self->{'versionLabel'} = $sc->{'contents'}->[0];
          next;
        }

        if ($sc->{'name'} eq 'TypeOfBundle') 
        {
          $self->{'TypeOfBundle'} = $sc->{'attributes'}->{'ContentsType'};
          next;
        }
      }
      next;
    }


    if ($c->{'name'} eq 'PackageList') 
    {

      for my $sc (@{$c->{'contents'}}) 
      {
        next if ref($sc) ne 'HASH';

        if( $sc->{'name'} eq 'PackagesInBundle' )
        {
          $self->addIncludedPackage( 
                             pkgName => $sc->{'attributes'}->{'PackageName'},
                             pkgVer  => $sc->{'attributes'}->{'PackageVersion'},
                             pkgFlav => $sc->{'attributes'}->{'PackageFlavor'},
                           );
          next;
        }         

        if( $sc->{'name'} eq 'IncludedPackages' )
        {
          for my $in (@{$sc->{'contents'}})
          { 
            next if ref($in) ne 'HASH';
            my $version = 
              new Grid::GPT::V1::Version(label => 
                                         $in->{'attributes'}->{'PackageVersion'}
                                        );

            $self->addIncludedPackage( 
                             pkgName => $in->{'attributes'}->{'PackageName'},
##                             pkgVer  => $in->{'attributes'}->{'PackageVersion'},
                             pkgVer  => $version,
                             pkgFlav => $in->{'attributes'}->{'PackageFlavor'},
                             pkgType => $in->{'attributes'}->{'PackageType'}
                           );
            next;
          }
          next;
        }         

        if( $sc->{'name'} eq 'ExcludedPackages' )
        {
          for my $ex (@{$sc->{'contents'}})
          {
            next if ref($ex) ne 'HASH';

            $self->addExcludedPackage( 
                             pkgName => $ex->{'attributes'}->{'PackageName'},
                             pkgVer  => $ex->{'attributes'}->{'PackageVersion'},
                             pkgFlav => $ex->{'attributes'}->{'PackageFlavor'},
                             pkgType => $ex->{'attributes'}->{'PackageType'}
                           );
          }
          next;
        }         

        if( $sc->{'name'} eq 'PackageFlags' )
        {
          for my $flag (@{$sc->{'contents'}})
          {
            next if ref($flag) ne 'HASH';

            $self->setFlag( flag => $flag->{'name'} );
          }
        }
      }
      next;
    }
  }
}

sub output_metadata_file 
{
  my $self       = shift;
  my ($filename) = @_;

  my $writer     = new Grid::GPT::V1::XML($filename);
  
  $writer->doctype("GPTBundleData","gpt_bundle.dtd");

  $writer->startTag("GPTBundleData", Name => $self->{'Name'});
  $writer->characters("\n");

  $writer->startTag("BundleInfo");
  $writer->characters("\n");

  my $desc = defined($self->{'Description'}) ? $self->{'Description'}
                                             : "EMPTY";
  $writer->dataElement('Description', $desc);
  $writer->characters("\n");
  
  if( $self->{'PackagingTool'} )
  {
    for my $c (@{$self->{'PackagingTool'}})
    {
      my $tool = defined($c->{'tool'}) ? $c->{'tool'}
                                       : "GPT";
      my $ver  = defined($c->{'ver'})  ? $c->{'ver'}
                                       : Grid::GPT::GPTIdentity::gpt_version();
      $writer->emptyTag( "PackagingTool", 
                         ToolName     => $tool, 
                         ToolVersion  => $ver 
                       );
      $writer->characters("\n");
    }
  }
  else
  {
    my $ver = Grid::GPT::GPTIdentity::gpt_version();
    $writer->emptyTag( "PackagingTool", 
                       ToolName     => 'GPT', 
                       ToolVersion  => $ver 
                     );
    $writer->characters("\n");
  }

  if( $self->{'ContactInfo'} )
  {
    for my $c (@{$self->{'ContactInfo'}})
    {
      my $name = defined($c->{'name'})  ? $c->{'name'}
                                           : "EMPTY";
      my $mail = defined($c->{'email'}) ? $c->{'email'}
                                           : "EMPTY";

      $writer->emptyTag( 'ContactInfo', 
                         ContactEmail => $mail, 
                         ContactName  => $name 
                       );
      $writer->characters("\n");
    }
  }
  else
  {
    $writer->emptyTag( 'ContactInfo', 
                       ContactEmail => 'EMPTY', 
                       ContactName  => 'EMPTY' 
                     );
    $writer->characters("\n");
  }
  
  if( $self->{'BundleDocs'} )
  {
    for my $c (@{$self->{'BundleDocs'}})
    {
      my $desc = defined($c->{'desc'})  ? $c->{'desc'}
                                           : "EMPTY";
      my $url  = defined($c->{'url'})  ? $c->{'url'}
                                           : "EMPTY";
      $writer->emptyTag( "BundleDocs", 
                         BundleDocsDesc => $desc, 
                         BundleDocsURL  => $url 
                       );
      $writer->characters("\n");
    }
  }
  else
  {
    $writer->emptyTag( "BundleDocs", 
                       BundleDocsDesc => 'EMPTY', 
                       BundleDocsURL  => 'EMPTY'
                     );
    $writer->characters("\n");
  }

  if( $self->{'ComponentName'} )
  {
    $writer->startTag("ComponentInformation", ComponentName => $self->getComponentName());
    $writer->characters("\n");
    
    my $clabel = defined($self->getComponentVer()) ? $self->getComponentVer()
                                                  : "EMPTY";
    $writer->dataElement( 'VersionLabel', $clabel );
    $writer->characters("\n");
    my $cdesc  = defined($self->getComponentDesc()) ? $self->getComponentDesc()
                                                   : "EMPTY";

    $writer->dataElement( 'Description', $cdesc );
    $writer->characters("\n");

    $writer->endTag("ComponentInformation");
    $writer->characters("\n");
  }

  $writer->endTag("BundleInfo");
  $writer->characters("\n");

  $writer->startTag("BundleReleaseInfo");
  $writer->characters("\n");

  my $stab = defined($self->{'bundleStab'}) ? $self->{'bundleStab'}
                                            : "EMPTY";
  $writer->emptyTag( 'BundleStability', Release => $stab );
  $writer->characters("\n");

  if( defined($self->{'Version'}) )
  {
    $writer->emptyTag( "BundleVersion", 
                       Major => $self->{'Version'}->{'major'}, 
                       Minor => $self->{'Version'}->{'minor'},
                       Age   => $self->{'Version'}->{'age'}
                     );
  }
  else
  {
    $writer->emptyTag( "BundleVersion", 
                       Major => "EMPTY", 
                       Minor => "EMPTY",
                       Age   => "EMPTY" 
                     );
  }
  $writer->characters("\n");

  my $label = defined($self->{'versionLabel'}) ? $self->{'versionLabel'}
                                               : "EMPTY";
  $writer->dataElement( 'VersionLabel', $label );
  $writer->characters("\n");

  $stab = defined($self->{'TypeOfBundle'}) ? $self->{'TypeOfBundle'}
                                              : "EMPTY";
  $writer->emptyTag( 'TypeOfBundle', ContentsType => $stab );
  $writer->characters("\n");

  $writer->endTag("BundleReleaseInfo");
  $writer->characters("\n");




  my $file_name = defined($self->{'FileName'}) ? $self->{'FileName'}
                                              : "EMPTY";
  $writer->dataElement('FileName', $file_name);
  $writer->characters("\n");


  $writer->startTag("PackageList");
  $writer->characters("\n");

  if( $self->{'PackageList'} )
  {
    $writer->startTag("IncludedPackages");
    $writer->characters("\n");
    for my $c (@{$self->{'PackageList'}->{'Included'}})
    {

##      my $ver;
##      if( ref( $c->{'pkgVer'} ) eq "Grid::GPT::V1::Version" )
##      {
##       $ver = "$c->{'pkgVer'}->{'major'}.$c->{'pkgVer'}->{'minor'}";
##      }
##      else
##      {
##        $ver = $c->{'pkgVer'};
##      }
      my $ver;
      if( ref( $c->{'pkgVer'} ) eq "Grid::GPT::V1::Version" )
      {
        $ver = "$c->{'pkgVer'}->{'major'}.$c->{'pkgVer'}->{'minor'}";
      }
      else
      {
        $ver = $c->{'pkgVer'};
      }

      $writer->emptyTag( "Package", 
                         PackageName    => $c->{'pkgName'}, 
                         PackageFlavor  => $c->{'pkgFlav'}, 
                         PackageVersion => $ver, 
                         PackageType    => $c->{'pkgType'}
                       );
      $writer->characters("\n");
    }
    $writer->endTag("IncludedPackages");
    $writer->characters("\n");

    $writer->startTag("ExcludedPackages");
    $writer->characters("\n");
    for my $c (@{$self->{'PackageList'}->{'Excluded'}})
    {

##      my $ver;
##      if( ref( $c->{'pkgVer'} ) eq "Grid::GPT::V1::Version" )
##      {
##        $ver = "$c->{'pkgVer'}->{'major'}.$c->{'pkgVer'}->{'minor'}";
##      }
##      else
##      {
##        $ver = $c->{'pkgVer'};
##      }
      my $ver;
      if( ref( $c->{'pkgVer'} ) eq "Grid::GPT::V1::Version" )
      {
        $ver = "$c->{'pkgVer'}->{'major'}.$c->{'pkgVer'}->{'minor'}";
      }
      else
      {
        $ver = $c->{'pkgVer'};
      }
      $writer->emptyTag( "Package",
                         PackageName    => $c->{'pkgName'},
                         PackageFlavor  => $c->{'pkgFlav'},
                         PackageVersion => $ver,
                         PackageType    => $c->{'pkgType'}
                       );
      $writer->characters("\n");
    }
    $writer->endTag("ExcludedPackages");
    $writer->characters("\n");

    $writer->startTag("PackageFlags");
    $writer->characters("\n");

    for my $c (@{$self->{'PackageList'}->{'Flags'}})
    {
      $writer->dataElement($c);
      $writer->characters("\n");
    }
    $writer->endTag("PackageFlags");
    $writer->characters("\n");
  }
  else
  {
    $writer->startTag("IncludedPackages");
    $writer->characters("\n");
    $writer->endTag("IncludedPackages");
    $writer->characters("\n");

    $writer->startTag("ExcludedPackages");
    $writer->characters("\n");
    $writer->endTag("ExcludedPackages");
    $writer->characters("\n");

    $writer->startTag("PackageFlags");
    $writer->characters("\n");
    $writer->endTag("PackageFlags");
    $writer->characters("\n");
  }
  
  $writer->endTag("PackageList");
  $writer->characters("\n");

  $writer->endTag("GPTBundleData");

  $writer->write($filename);
}

sub addContact
{
  my $self        = shift;
  my (%args)      = @_;

  my $contactInfo = { name => $args{'name'}, email => $args{'email'} };
  push @{$self->{'ContactInfo'}}, $contactInfo;
}  

sub addPackagingTool 
{
  my $self       = shift;
  my (%args)     = @_;

  my $packagingTool = { tool => $args{'tool'}, ver => $args{'ver'} };
  push @{$self->{'PackagingTool'}}, $packagingTool;
}  

sub addBundleDoc
{
  my $self       = shift;
  my (%args)     = @_;

  my $bundleDocs = { desc => $args{'desc'}, url => $args{'url'} };
  push @{$self->{'BundleDocs'}}, $bundleDocs;
}  

sub addComponentName
{
  my ($self, $name) =  @_;

  $self->{'ComponentName'} =  $name;
}

sub getComponentName
{
  my ($self, %args) =  @_;

  return $self->{'ComponentName'};
}

sub addComponentVer
{
  my ($self, $ver) =  @_;

  $self->{'ComponentVer'} =  $ver;
}

sub getComponentVer
{
  my ($self, %args) =  @_;

  return $self->{'ComponentVer'};
}

sub addComponentDesc
{
  my ($self, $desc) =  @_;

  $self->{'ComponentDesc'} =  $desc;
}

sub getComponentDesc
{
  my ($self, %args) =  @_;

  return $self->{'ComponentDesc'};
}
  

sub _addPackage
{
  my $self    = shift;
  my (%args)  = @_;

  my $where   = $args{'type'};

  my $pkgVer  = (!defined($args{'pkgVer'}))  ? "ANY" : $args{'pkgVer'};
  my $pkgFlav = (!defined($args{'pkgFlav'})) ? "ANY" : $args{'pkgFlav'};
  my $pkgType = (!defined($args{'pkgType'})) ? "ANY" : $args{'pkgType'};
  my $pkgName = $args{'pkgName'};

  for my $p (@{$self->_getFullBundlePackageList( $where )})
  {
    if( $p->{'Name'} eq $pkgName )
    {
      return if( ($pkgVer  eq "ANY" || $p->{'Version'} eq $pkgVer) &&
                 ($pkgFlav eq "ANY" || $p->{'Flavor'}  eq $pkgFlav) &&
                 ($pkgType eq "ANY" || $p->{'Type'}    eq $pkgType) );
    }
  }

  my $package = { pkgName => $args{'pkgName'}, 
                  pkgVer  => $pkgVer, 
                  pkgFlav => $pkgFlav,
                  pkgType => $pkgType };

  push @{$self->{'PackageList'}->{$where}}, $package;
}  

sub addIncludedPackage
{
  my $self    = shift;
  my (%args)  = @_;

  $self->_addPackage( pkgName => $args{'pkgName'},
                      pkgVer  => $args{'pkgVer'},
                      pkgFlav => $args{'pkgFlav'}, 
                      pkgType => $args{'pkgType'},
                      type    => 'Included' );
}

sub addExcludedPackage
{
  my $self    = shift;
  my (%args)  = @_;

  $self->_addPackage( pkgName => $args{'pkgName'},
                      pkgVer  => $args{'pkgVer'},
                      pkgFlav => $args{'pkgFlav'}, 
                      pkgType => $args{'pkgType'},
                      type    => 'Excluded' );
}

sub setVersionLabel
{
  my ($self, %args) =  @_;

  $self->{'versionLabel'} =  $args{'label'};
}

sub setBundleVersion
{
  my ($self, %args) =  @_;

  if (! %args) 
  {
    $self->{'Style'}      = 'OLD';
    return;
  }

  if( defined($args{'version'}) )
  {
    $self->{'Version'} =
      new Grid::GPT::V1::Version(label => $args{'version'});
    return;
  }

  if( !defined($self->{'Version'}) )
  {
     $self->{'Version'} = new Grid::GPT::V1::Version;
  }

  $self->{'Version'}->{'major'} = $args{'Major'} if defined $args{'Major'};
  $self->{'Version'}->{'minor'} = $args{'Minor'} if defined $args{'Minor'}; 
  $self->{'Version'}->{'age'}   = $args{'age'}   if defined $args{'age'}; 

  $self->{'Version'}->{'type'} = 'aging';

  if ($args{'major'} eq 'EMPTY') 
  {
    $self->{'Style'}      = 'OLD';
    return;
  }

  $self->{'Style'}      = 'NEW';
}

sub setFlag
{
  my $self   = shift;
  my (%args) = @_;

  my $flag   = $args{'flag'};
  for my $c (@{$self->{'PackageList'}->{'Flags'}})
  {
    return if( $c eq $flag );
  }

  push @{$self->{'PackageList'}->{'Flags'}}, $flag; 
}

sub setFileName
{
  my $self   = shift;
  my (%args) = @_;

  if( defined( $args{'file_name'} ) )
  {
    $self->{'FileName'} = $args{'file_name'};
  }
}
sub getFlags
{
  my $self   = shift;
  my @flags  = undef;

  for my $c (@{$self->{'PackageList'}->{'Flags'}})
  {
    push @flags, $c;
  }

  return @flags;
}

sub read_bundle_from_tar
{
  my ($self, %args)        = @_;

  my $file                 = $args{'file'};
  my $tar                  = Archive::Tar->new();

  $file                    = Grid::GPT::FilelistFunctions::abspath($file);
  $self->{'tarfile'}       = $file;

  my $ret = $tar->read($file);
  confess "Unreadable TAR file: $file"  if !defined( $ret );


  if( !defined($self->{'tarfiles'}) )
  {
    @{$self->{'tarfiles'}} = $tar->list_files();
  }

  my @pkglist              = grep {/\.gpt-bundle\.xml/} @{$self->{'tarfiles'}};

  if( @pkglist )
  {
    $self->{'BundleFile'}  = $pkglist[0];
    my $bndlDef            = $tar->get_content($pkglist[0]);
    $self->read_metadata_file( $bndlDef );

    $self->{'Style'}       = 'NEW';

    return;
  }

  if( ! @pkglist)
  {
    @pkglist               = grep { /packagelist|packaging_list/ } @{$self->{'tarfiles'}};

    if( @pkglist )
    {
      my ($rootname) = $file =~ m!/([^/]+)$!;
      ($self->{'Name'})    = $rootname =~ m!([^\.]+)(?:-\d|\.)!;

      die "ERROR: Cannot parse a bundle name from $file\n"
        if ! defined $self->{'Name'};

      if (! defined $self->{'Packages'}) 
      {
        $self->unpack_tar_bundle(file => $file);
      }

      for my $p (@{ ( $self->{'Packages'}->pkgs() )}) 
      {
        my $pkgname        = $p->pkgname();
        my $pkgflv         = $p->flavor();
        my $pkgtype        = $p->pkgtype();
        my $pkgver         = $p->{'version'};

        $self->addIncludedPackage( pkgName => $pkgname, 
                                   pkgVer  => $pkgver, 
                                   pkgFlav => $pkgflv,
                                   pkgType => $pkgtype );
      }

      $self->{'BundleFile'} = $pkglist[0] . ".gpt-bundle.xml";
      $self->setBundleVersion();
    }
    return;
  }

  die "ERROR: $file is not a bundle\n";
}

sub unpack_tar_bundle 
{
  my $self          = shift;		
  my %args          = @_;

  my $tmpdir        = $self->{'tmpdir'};
  my $file          = defined $args{'file'} ? $args{'file'} : 
                                              $self->{'tarfile'};
  my $tar           = Archive::Tar->new();
  $file             = Grid::GPT::FilelistFunctions::abspath($file);

  my $currentdir    = cwd();

  my $ret = $tar->read($file);
  confess "Unreadable TAR file: $file"  if !defined( $ret );

  my @tarfiles      = $tar->list_files();

  chdir $tmpdir;

  my $result = `pwd`;

  my $retval        = $tar->extract(@{$self->{'tarfiles'}});

  if (!($retval))
  {
    print $tar->error();
    print $retval, "is the return from extract\n";
    print "did not successfully unpack $file \n";
    print "$currentdir was the current dir \n";
  }

  chdir $currentdir;

  my @pkglst = grep {/packagelist|packaging_list/} @tarfiles;
  $self->create_pkgdist($pkglst[0]);
}

sub save_bundle_def
{
  my $self      = shift;		
  my $globusdir = shift;

  my $bndlDir   = "$globusdir/etc/gpt/bundles/$self->{'Name'}";

  if (!(-e "$bndlDir"))
  {
    Grid::GPT::FilelistFunctions::mkinstalldir($bndlDir);
  }

  if( !defined($self->{'BundleFile'}) )
  {
    $self->{'BundleFile'} = $self->{'Name'} . "_bundle\.gpt-bundle\.xml";
  }

  my $tmp = $bndlDir . "/" . $self->{'BundleFile'};

  if( -e "$tmp" )
  {
    unlink( $tmp );
  }

  $self->output_metadata_file("$tmp");
}	

sub get_bundle_def
{
  my $self      = shift;		
  my (%args)    = @_;

  my $globusdir = $args{'globusdir'};
  my $file      = $args{'file'};

  my $bndlDir   = "$globusdir/etc/gpt/bundles/$file";

  opendir(DIR, $bndlDir) || die "can't opendir $bndlDir: $!";
  my @dots      = grep { /$file\.gpt-bundle\.xml/ } readdir(DIR);
  closedir DIR;

  return $bndlDir . "/" . $dots[0];
}

sub remove_bundle_def
{
  my $self                = shift;		
  my $globusdir           = shift;

  my $bndlDir             = "$globusdir/etc/gpt/bundles/$self->{'Name'}";

  if( !defined($self->{'BundleFile'}) )
  {
    $self->{'BundleFile'} = "$self->{'Name'}.gpt-bundle.xml";
  }

  my $tmp                 = "$bndlDir/$self->{'BundleFile'}";

  if( -e "$tmp" )
  {
    print "Remove Bendle Def: $tmp\n";
    unlink( $tmp );
  }
}

sub _clearBundlePackageList
{
  my $self = shift;
  my $type = shift;

  $self->{'PackageList'}->{$type} = [];
}

sub _getBundlePackageList
{
  my $self = shift;
  my $type = shift;

  my @packageList;

  for my $p (@{$self->{'PackageList'}->{$type}})
  {
    my $pkg = "$p->{'pkgName'}-$p->{'pkgFlav'}_$p->{'pkgType'}";
    push @packageList, $pkg;
  }

  return @packageList;
}

sub getBundleIncludedPackageList
{
  my $self = shift;

  return $self->_getBundlePackageList( 'Included' );
}

sub clearBundleIncludedPackageList
{
  my $self = shift;

  $self->_clearBundlePackageList( 'Included' );
}

sub getFullBundleIncludedPackageList
{
  my $self = shift;

  return $self->_getFullBundlePackageList( 'Included' );
}

sub getBundleExcludedPackageList
{
  my $self = shift;

  return $self->_getBundlePackageList( 'Excluded' );
}
sub clearBundleExcludedPackageList
{
  my $self = shift;

  $self->_clearBundlePackageList( 'Excluded' );
}

sub getFullBundleExcludedPackageList
{
  my $self = shift;

  return $self->_getFullBundlePackageList( 'Excluded' );
}

sub _getFullBundlePackageList
{
  my $self            = shift;
  my $type            = shift;
  my @packageList;

  for my $p (@{$self->{'PackageList'}->{$type}})
  {
    my $pkg           = {
                         Name    => $p->{'pkgName'},
                         Version => $p->{'pkgVer'},
                         Flavor  => $p->{'pkgFlav'},
                         Type    => $p->{'pkgType'},
                        };
    push @packageList, $pkg;
  }

  return \@packageList;
}

sub decode_tar_bundle
{
  my $self      = shift;
  my (%args)    = @_;

  my $globusdir = $args{'globusdir'};
  my $tmpdir    = $self->{'tmpdir'};
  my $file      = $args{'file'}; 

  $self->read_bundle_from_tar( $file );
  $self->unpack_tar_bundle( $tmpdir, $file );
  return $self->getBundleIncludedPackageList();
}

sub set_bundlefile_name
{
  my $self      = shift;
  my (%args)    = @_;

  $self->{'BundleFile'} = $args{'Name'} . "_bundle\.gpt-bundle\.xml";
}
	
sub tmpdir_cleanup
{
  my $self      = shift;
  my $tar       = $self->{tarfile};
  my $tmpdir    = $self->{tmpdir};
  my @tarfiles  = $tar->list_files();
	
  foreach my $file (@tarfiles)
  {
    my $name    = $tmpdir . "/" . $file;
    unlink($name) or warn "couldn't unlink $name: $!";
  }

  rmdir ($tmpdir) or warn "couldn't remove $tmpdir/$$: $!"; 
}

sub AUTOLOAD 
{
  use vars qw($AUTOLOAD);
  my $self = shift;
  my $type = ref($self) || croak "$self is not an object";
  my $name = $AUTOLOAD;

  $name =~ s/.*://;   # strip fully-qualified portion

  unless (exists $self->{$name} ) 
  {
    croak "Can't access `$name' field in object of class $type";
  } 

  if (@_) 
  {
    return $self->{$name} = shift;
  } 
  else 
  {
    return $self->{$name};
  } 
}

sub create_pkgdist
{
  my ($self, $list) = @_;

  $self->{'Packages'} = new Grid::GPT::PkgDist(
                                         with_filelists => 1,
                                         prefix         => $self->{'tmpdir'},
                                         pkglist        => $list );
}


sub create_pkgdefs_set
{
  my ($self) = @_;

  $self->{'PkgDefs'} = new Grid::GPT::PkgDefsSet(log => $self->{'log'});

  for my $p (@{$self->getFullBundleIncludedPackageList()})
  {

##    my $version = new Grid::GPT::V1::Version(label => $p->{'Version'});
my $version = $p->{'Version'};

    $self->{'PkgDefs'}->add_package( pkgname => $p->{'Name'},
                                     flavor  => $p->{'Flavor'},
                                     pkgtype => $p->{'Type'},
                                     version => $version,
                                     bundle  => $self );
  }
}

sub is_same
{
  my $self          = shift;
  my $other         = shift;

  return 0 if $self->{'Name'} ne $other->{'Name'};
  return $self->{'Version'}->is_equal( $other->{'Version'} );
}

sub compare_bundle_2_bundle
{
  my ($self, %args) = @_;

  my @conflict;
  my @missing;
my @self_conf;
my @other_conf;
  my $otherBundle   = $args{'bundle'};

  my $match;

  for my $b1 (@{$self->getFullBundleIncludedPackageList()})
  {
    $match = 0;

    for my $b2 (@{$otherBundle->getFullBundleIncludedPackageList()})
    {

      if( $b1->{'Name'}   eq $b2->{'Name'} &&
          $b1->{'Type'}   eq $b2->{'Type'} &&
          $b1->{'Flavor'} eq $b2->{'Flavor'} )
      {
        $match = 1;
        if( $b1->{'Version'} ne $b2->{'Version'} )
        {
my $self_c = "$self->{'Name'}-$self->{'versionLabel'}:\t$b1->{'Name'}-$b1->{'Flavor'}-" . $b1->{'Version'}->comp_id();
my $other_c = "$otherBundle->{'Name'}-$otherBundle->{'versionLabel'}:\t$b2->{'Name'}-$b2->{'Flavor'}-" . $b2->{'Version'}->comp_id();


##          print "Conflict between:\n" .
##                "\t$self->{'Name'}-$self->{'versionLabel'}:\t$b1->{'Name'}-$b1->{'Flavor'}-" . 
##                $b1->{'Version'}->comp_id() . "\n" .
##                "\t$otherBundle->{'Name'}-$otherBundle->{'versionLabel'}:\t$b2->{'Name'}-$b2->{'Flavor'}-" .
##                $b2->{'Version'}->comp_id() . "\n";


push @self_conf, $self_c;
push @other_conf, $other_c;
        }
      }
    }

    if( !$match )
    {
      my $miss = "$b1->{'Name'}-$b1->{'Flavor'}-$b1->{'Type'}-" .
                 $b1->{'Version'}->comp_id();


##      print "$b1->{'Name'}-$b1->{'Flavor'}-$b1->{'Type'}-" . 
##             $b1->{'Version'}->comp_id() .
##            " in $self->{'Name'}-$self->{'versionLabel'} Missing from $otherBundle->{'Name'}-$otherBundle->{'versionLabel'}\n";


      push @missing, $miss;
    }
  }

  if( @missing )
  {
    print "$otherBundle->{'Name'}-$otherBundle->{'versionLabel'} is missing:\n";
    for my $m (@missing)
    {
      print "\t$m\n";
    }
  }

  if( @self_conf )
  { 
    print "\nBundle package defferences:\n";
    my $i = @self_conf;
    for my $j ( 0 .. $i-1 )
    {
      print "\t$self_conf[$j]\n"; 
      print "\t$other_conf[$j]\n"; 
    }
  }
  return( \@conflict, \@missing );
}

sub find_package
{
  my ($self, %args)  = @_;

  my @pkgs;
  my $val;
  my $p              = $args{'package'};

  my $installed_pkgs = $self->{'Packages'}->query( pkgname => $p->{'Name'},
                                         flavor  => $p->{'Flavor'},
                                         pkgtype => $p->{'Type'} );

  if( defined(@$installed_pkgs) )
  {
    for my $c (@$installed_pkgs)
    {
      my $ver        = "$c->{'version'}->{'major'}.$c->{'version'}->{'minor'}";

      if( $ver eq $p->{'Version'} )
      {
        $val         = $c;
      }
    }
  }

  return( $val );
}

sub compare_bundle_2_installation
{
  my ($self, %args)    = @_;

  my $inst             = $args{'inst'};

  for my $p (@{($self->{'PackageList'}->{'Included'})})
  {
    my $installed_pkgs = $inst->query( pkgname => $p->{'pkgName'},
                                       flavor  => $p->{'pkgFlav'},
                                       pkgtype => $p->{'pkgType'} 
                                     );
    if ($p->{'pkgType'} =~ m!pgm!) {
      my $pkgtype = $p->{'pkgType'} eq 'pgm' ? 'pgm_static' : 'pgm';
     my $more_pkgs = $inst->query( pkgname => $p->{'pkgName'},
                                   flavor  => $p->{'pkgFlav'},
                                   pkgtype => $pkgtype 
                                 );
      push @$installed_pkgs, @$more_pkgs;
   }

    if( !(@$installed_pkgs) )
    {
      print "Package $p->{'pkgName'}-$p->{'pkgType'}-$p->{'pkgFlav'} ver: ",
        $p->{'pkgVer'}->comp_id()," is missing from installation\n";
      next;
    }

    my @matches = 
      grep {$p->{'pkgVer'}->is_equal($_->{'depnode'}->{'Version'})}
        @$installed_pkgs;

    if (! @matches) 
    {
      print "\nPackage Specification $p->{'pkgName'}-$p->{'pkgType'}-$p->{'pkgFlav'} ver: ",
            $p->{'pkgVer'}->comp_id() , "\n";

      for my $m (@$installed_pkgs) 
      {
        my $relate = $p->{'pkgVer'}->is_newer($m->{'depnode'}->{'Version'});
        $relate = ($m->{'depnode'}->{'Version'}->is_newer($p->{'pkgVer'}) == 1
                   ? -1 : 0) if ! $relate;

        my $msg = "\t is a mismatch of installed pkg ";
        $msg = "\t is older than installed pkg " if $relate < 0;
        $msg = "\t is newer than installed pkg " if $relate > 0;

        print $msg, $m->label(), " ver: ", 
              $m->{'depnode'}->{'Version'}->label(), "\n";
      }
    }
  }
}

sub match_installed_pkgs {
  my ($self, %args)    = @_;

  my $pkginst = $args{'pkginst'};
  my $installed_pkgs = new Grid::GPT::PkgDefsSet(log => $self->{'log'});


  for my $d (@{$self->{'PkgDefs'}->{'pkgs'}}) {

    my @matches = $pkginst->query(
                                  pkgname => $d->pkgname(),
                                  flavor => $d->flavor(),
                                  pkgtype => $d->pkgtype(),
                                 );

    @matches = grep { $d->{'versions'}->is_equal($_->{'version'})} @matches;
    $installed_pkgs->add_package(pkgnode => $matches[0]);
  }

  return $installed_pkgs;
}

sub is_old_style
{
  my ($self)            = @_;

  return( $self->version_label() eq 'NONE' );
}

sub label {

  my ($self) = @_;

  return $self->{'Name'};
}

# need this for SetFunctions.pm
sub name {

  my ($self) = @_;

  return $self->{'Name'};
}

sub version_label {

  my ($self) = @_;

  return $self->{'versionLabel'} if defined $self->{'versionLabel'} 
    and $self->{'versionLabel'} ne 'EMPTY';
  my $version;
  $version = $self->{'Version'}->label() if defined $self->{'Version'};
  return "NONE" if ! defined $version;
  return "NONE" if $version =~ m!EMPTY!;
  return $version;

}

END { }       # module clean-up code here (global destructor)

1;
