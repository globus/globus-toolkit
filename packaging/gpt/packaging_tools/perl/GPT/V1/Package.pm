package Grid::GPT::V1::Package;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
use Data::Dumper;
use Grid::GPT::V1::XML;
use Grid::GPT::V1::Version;
use Grid::GPT::V1::BaseDependency;
use Grid::GPT::V1::SourceDependency;
use Grid::GPT::V1::BinaryDependency;
use Grid::GPT::V1::BuildFlavors;
use Grid::GPT::DepIndexes;

# set the version for version checking
$VERSION     = 0.01;


sub new { 
    my ($that, %args)  = @_;
    my $class = ref($that) || $that;
    my $self  = {
                 Name => undef,
                 Version => undef,
                 Format_Version => undef,
                 Package_Type => undef,
                 Flavor => undef,
                 ColocateLibraries => 'yes',
                 Components => [],
                 Version_Label => undef,
                 With_Flavor => undef,
                 Description => undef,
                 Functional_Group => undef,
                 Version_Stability => undef,
                 PackageIdentifier => undef,
                 Source_Dependencies => undef,
                 Binary_Dependencies => undef,
                 Setup_Dependency => undef,
                 Source_Setup_Dependencies => undef,
                 cflags => undef,
                 external_includes => undef,
                 pkg_libs => undef,
                 external_libs => undef,
                 Filelist => undef,
                 Setup_Name => undef,
                 Setup_Version => undef,
                 Post_Install_Message => undef,
                 Post_Install_Program => undef,
                 system => undef,
                 Build_Instructions => undef,
                 SrcDir => undef,
                };

    for  my $f (sort keys %args) { 
      $self->{$f} = $args{$f};
    } 
    bless $self, $class;

if((defined $args{installed_pkg})&&
   (defined $args{flavor})&&
   (defined $args{type}))
{ 
  $self->path_namer($args{installed_pkg}, $args{flavor}, $args{type});
} 
else
{  
  if((!(defined $args{installed_pkg}))&&
     (!(defined $args{flavor}))&&
     (!(defined $args{type})))
  { 
    return $self;
  }  
  else
  { 
    die "ERROR: Please specify name flavor and type: $!\n";
  } 
} 
return $self;
}

sub path_namer
{
  my ($self, $name, $f, $t)=@_;
  my $globus=$ENV{GLOBUS_LOCATION};
  my $path="$globus/etc/globus_packages/$name/pkg_data_".$f."_$t.gpt";
 
  $self->read_metadata_file($path);
}
 	
sub read_metadata_file {
  # my (%metadata);
  my $self=shift;
  my ($filename,$pkg_type) = @_;
  my $disable_version_checking = 1;
  $filename= "$ {filename}_$pkg_type.gpt" if(defined($pkg_type));
  my $xml = new Grid::GPT::V1::XML;
  $xml->read($filename);

  my $root = $xml->{'roottag'};

  $self->{'Name'} = $root->{'attributes'}->{'Name'};
  $self->{'Format_Version'} = $root->{'attributes'}->{'Format_Version'};

# Check to see if we can understand this format

  die "ERROR: Cannot parse $filename
      You need to upgrade your packaging tools" 
    if $self->{'Format_Version'} >= 2.0;

  $self->{'doctype'} = $xml->{'doctype'};
  $self->{'system'} = $xml->{'system'};

#  print Dumper $xml;
  for my $c (@{$root->{'contents'}}) {
    next if ref($c) ne 'HASH';

    if ($c->{'name'} eq 'Aging_Version') {
      $self->{'Version'} = new Grid::GPT::V1::Version(obj => $c);
      next;
    }

    if ($c->{'name'} eq 'Description') {
      $self->{'Description'} = $c->{'contents'}->[0];
      next;
    }

    if ($c->{'name'} eq 'Functional_Group') {
      $self->{'Functional_Group'} = $c->{'contents'}->[0];
      next;
    }

    if ($c->{'name'} eq 'Version_Stability') {
      $self->{'Version_Stability'} = $c->{'attributes'}->{'Release'};
      next;
    }

    if ($c->{'name'} eq 'VersionLabel') {
      $self->{'Version_Label'} = $c->{'contents'}->[0];
      next;
    }

    if ($c->{'name'} eq 'ComponentInformation') {
      $self->add_component($c);
      next;
    }

    if ($c->{'name'} eq 'PackageIdentifier') {
      $self->{'PackageIdentifier'} = $c->{'attributes'}->{'Release'};
      next;
    }
    if ($c->{'name'} eq 'PackagingTool') {
      $self->{'ToolName'} = $c->{'attributes'}->{'ToolName'};
      $self->{'ToolVersion'} = $c->{'attributes'}->{'ToolVersion'};
      $disable_version_checking = $self->{'disable_version_checking'};
      next;
    }

    if ($c->{'name'} =~ m!(.+)_pkg$!) {
      $self->{'Package_Type'} = $1;

      if ($self->{'Package_Type'} eq 'src') {
	$self->{'Source_Dependencies'} = 
          new Grid::GPT::DepIndexes(disable_version_checking =>
                                    $self->{'disable_version_checking'});
      } else {
	  $self->{'Binary_Dependencies'} = 
            new Grid::GPT::DepIndexes(disable_version_checking => 
                                      $disable_version_checking);
      }

      for my $sc (@{$c->{'contents'}}) {
	next if ref($sc) ne 'HASH';

	# With_Flavor's value is an attribute
	if ($sc->{'name'} eq 'With_Flavors') {
	  $self->{'With_Flavors'} = $sc->{'attributes'}->{'build'};
	  $self->{'ColocateLibraries'} = 
            defined $sc->{'attributes'}->{'ColocateLibraries'} ? 
              $sc->{'attributes'}->{'ColocateLibraries'} : 'yes';
	  next;
	}

        if ($sc->{'name'} eq 'Setup') {
          $self->{'Setup_Name'} = $sc->{'attributes'}->{'Name'};
          for my $setc (@{$sc->{'contents'}}) {
            next if ref($setc) ne 'HASH';
            if ($setc->{'name'} eq 'Aging_Version') {
              $self->{'Setup_Version'} = new Grid::GPT::V1::Version(obj => $setc);
              last;
            }
          }
        }

        if ($sc->{'name'} eq 'Post_Install_Message') {
          $self->{'Post_Install_Message'} = $sc->{'contents'}->[0];
          next;
        }

        if ($sc->{'name'} eq 'Post_Install_Program') {
          $self->{'Post_Install_Program'} = $sc->{'contents'}->[0];
          next;
        }

	# Pass any SourceDependency XML to SourceDependencies.pm
	if ($sc->{'name'} eq 'Source_Dependencies') {

          Grid::GPT::V1::BaseDependency::add_xml_to(
                                                xml =>$sc, 
                                                depindexes => 
                                                $self->{'Source_Dependencies'});
	  next;
        }


	# Build Environment data is a list in contents
	if ($sc->{'name'} eq 'Build_Environment') {

	  for my $bc (@{$sc->{'contents'}}) {
	    next if ref($bc) ne 'HASH';
	    my $name = $bc->{'name'};
	    # Each build environment field has its value in the content array 
	    # which has 1 element
	    $self->{$name} = $bc->{'contents'}->[0];
	  }
	  next;
	}

	# Build Instructions is a list of Build_Step elements in contents
	if ($sc->{'name'} eq 'Build_Instructions') {

          $self->{'SrcDir'} = $sc->{'attributes'}->{'SrcDir'} 
            if defined $sc->{'attributes'};

	  for my $bc (@{$sc->{'contents'}}) {
	    next if ref($bc) ne 'HASH';
	    my $name = $bc->{'name'};
            if ($name eq 'Build_Step') {
              $self->{'Build_Instructions'} = [] 
                if ! defined $self->{'Build_Instructions'};
              my ($command, $args) = (
                                      $bc->{'contents'}->[0],
                                      $bc->{'attributes'}->{'Macro_Args'}
                                     );
              $command =~ s!\n$!!s;
              my $buildstep = {command => $command, args => $args};
              push @{$self->{'Build_Instructions'}}, $buildstep;
              next;
            }
            if ($name eq 'flavors') {
              $self->{'Build_Flavor_Choices'} = 
                new Grid::GPT::V1::BuildFlavors(xml => $bc);
            }
	  }
	  next;
	}

	# Filelist data has a couple of attributes and a list of files in the contents
	if ($sc->{'name'} eq 'Filelist') {
	  $self->{Filelists} = [] if ! defined $self->{Filelists};
	  # Grab the Dir and Flavored attributes
	  my $filelist = $sc->{'attributes'};
	  $filelist->{'Files'} = [];
	  # Extract each filename
	  for my $bc (@{$sc->{'contents'}}) {
	    next if ref($bc) ne 'HASH';
	    my $name = $bc->{'name'};
	    # Each File field has its value in the content array 
	    # which has 1 element
	    push @{$filelist->{'Files'}}, $bc->{'contents'}->[0];
	  }
	  push @{$self->{Filelists}}, $filelist;
	  next;
	}

	if ($sc->{'name'} eq 'Flavor') {
	    # Flavor has its value in the content array 
	    # which has 1 element
	  $self->{'ColocateLibraries'} =
            defined $sc->{'attributes'}->{'ColocateLibraries'} ?
              $sc->{'attributes'}->{'ColocateLibraries'} : 'yes';
	  $self->{'Flavor'} = $sc->{'contents'}->[0];
	  next;
	}

	if ($sc->{'name'} eq 'Source_Setup_Dependency') {
	  my $setuppkg = $sc->{'attributes'}->{'PkgType'};
          for my $ssc (@{$sc->{'contents'}}) {
            next if ref($ssc) ne 'HASH';
            $self->add_setup_dep($ssc, $setuppkg);
          }
	  next;
	}

	if ($sc->{'name'} eq 'Version_Label') {
	    # Version_Label has its value in the content array 
	    # which has 1 element
	  $self->{'Version_Label'} = $sc->{'contents'}->[0];
	  next;
	}

	# Pass any BinaryDependency XML to BinaryDependencies.pm
	if ($sc->{'name'} eq 'Binary_Dependencies') {

          Grid::GPT::V1::BaseDependency::add_xml_to(xml => $sc,
                                                flavor => $self->{'Flavor'},
                                                depindexes =>  
                                                $self->{'Binary_Dependencies'});
	  next;
	}
	if ($sc->{'name'} eq 'Setup_Dependency') {
          $self->add_setup_dep($sc);
	  next;
	}
      }      
    }
  }
}

sub add_setup_dep
  {
    my ($self, $setup, $pkgtype) = @_;
    my $name = $setup->{'attributes'}->{'Name'};
    my $versions;
    for my $v(@{$setup->{'contents'}}) {
      next if ref $v ne 'HASH';
      $versions = Grid::GPT::V1::Version::create_version_list($v);
    }
    my $dep;
    if (defined $pkgtype) {

      $dep = new Grid::GPT::V1::SourceDependency(name => $name,
                                                type => 'Setup',
                                                versions => $versions,
                                                pkg_type => $pkgtype
                                                );
      $self->{Source_Dependencies}->add_dependency(dep => $dep);
    } else {

      $dep = new Grid::GPT::V1::BinaryDependency(name => $name,
                                                type => 'Setup',
                                                versions => $versions,
                                                pkg_type => 'pgm',
                                                my_pkg_type => $self->{'Package_Type'},
                                                );
      $self->{Binary_Dependencies}->add_dependency(dep => $dep);
      
    }

  }

sub add_component {
    my ($self, $xml) = @_;

    my $component = { Name => undef, VersionLabel => undef, 
                      Description => undef};
    $component->{'Name'} = $xml->{'attributes'}->{'Name'};

    for my $cc (@{$xml->{'contents'}}) {
      next if ref($cc) ne 'HASH';
      if ($cc->{'name'} eq 'VersionLabel') {
        $component->{'VersionLabel'} = $cc->{'contents'}->[0];
        next;
      }
      if ($cc->{'name'} eq 'Description') {
        $component->{'Description'} = $cc->{'contents'}->[0];
        next;
      }
    }

    push @{$self->{'Components'}}, $component;
}

sub convert_metadata {		
  #takes pkg_type and flavor as its arguments
  #returns reference to new (converted) metadata
	my $self=shift;
	my ($pkg_type, $flavor) = @_;
	my $converted=new Grid::GPT::V1::Package;

	for my $n ('Name', 'Version', 'Format_Version', 'doctype', 'system',
                   'Description', 'Version_Stability', 'Functional_Group',
                  'PackageIdentifier', 'ToolName', 'ToolVersion', 
                   'Components') {
	  $converted->{$n} = $self->{$n};
	}

	$converted->{'Package_Type'} = $pkg_type;
	if (! defined $Grid::GPT::V1::Definitions::noflavor_pkg_types{$pkg_type}) {
		$converted->{'Flavor'} = $flavor;
                
                $converted->{'ColocateLibraries'} = 
                  $self->{'ColocateLibraries'};
	}else{
		$converted->{'Flavor'} = "noflavor";
	}


        for my $n ('Post_Install_Message', 'Post_Install_Program', 
                   'Setup_Name', 'Version_Label') {
          $converted->{$n} = $self->{$n};
        }
        $converted->{'Setup_Version'} = $self->{'Setup_Version'}->clone() 
          if defined $self->{'Setup_Version'};
        
        $converted->{'Binary_Dependencies'} = 
          Grid::GPT::V1::SourceDependency::get_bindeps_from($self->{'Source_Dependencies'}, $pkg_type);

        my $setdeps = $self->{'Source_Dependencies'}->query(deptype =>'Setup');
        if (defined $setdeps) {
        for my $setup (@$setdeps) {
          if (($pkg_type eq $setup->pkgtype()) || ($setup->pkgtype() eq "pgm" and $pkg_type eq "pgm_static")) {
            my $bdepnode = $setup->depnode();
            my $bsetup = new Grid::GPT::V1::BinaryDependency(name => $bdepnode->{'name'},
                                                type => 'Setup',
                                                versions => $bdepnode->{'versions'},
                                                my_pkg_type => $pkg_type,
                                                );
            $converted->{Binary_Dependencies}->add_dependency(dep => $bsetup);
          }
        }
      }
	if ($pkg_type eq 'dev') {
	  for my $n ('cflags' , 'external_includes', 'pkg_libs', 'external_libs') {

	    $converted->{$n} = $self->{$n};
            next if ! defined $converted->{$n};
	    if ($n eq 'pkg_libs') {
	      $converted->{$n} =~ s!(-l\w+)\s+!$ {1}_$flavor !g;
	      $converted->{$n} =~ s!(-l\w+)$!$ {1}_$flavor!;
	    }
	  }
	}

return $converted
}

sub rpm {
    my $self = shift;
    die "ERROR: rpm's can only be generated from binary packages\n" 
      if $self->{'Package_Type'} eq 'src';
    my $rpmname = "$self->{'Name'}_$self->{'Flavor'}_$self->{'Package_Type'}";
    my $rpmprovidename = "$self->{'Name'}";
    $rpmprovidename .= "_$self->{'Flavor'}" if $self->{'Package_Type'} eq 'rtl' or
      $self->{'Package_Type'} eq 'dev';
    $rpmprovidename .= $self->{'Package_Type'} ne 'pgm_static' ? 
      "_$self->{'Package_Type'}" : '_pgm';
    my $rpmsummary = 
      "$self->{'Name'}_$self->{'Flavor'}_$self->{'Package_Type'} $self->{'Version_Stability'} version";

    my $rpmobj = {
                  GPT_SUMMARY_GPT => $rpmsummary,
                  GPT_DESCRIPTION_GPT => $self->{'Description'},
                  GPT_GROUP_GPT => $self->{'Functional_Group'},
                  GPT_NAME_GPT => $self->{'Name'},
                  GPT_FLAVOR_GPT => $self->{'Flavor'},
                  GPT_PKGTYPE_GPT => $self->{'Package_Type'},
                  GPT_PACKAGE_GPT => $rpmname,
                  GPT_VERSION_GPT => $self->{'Version'}->label(),
                  GPT_PROVIDES_GPT => $self->{'Version'}->rpm($rpmprovidename),
                  GPT_REQUIRES_GPT => 
                  Grid::GPT::V1::BaseDependency::get_rpm_from($self->{'Binary_Dependencies'}, 
                                                          $self->{'Flavor'}),
                 };
    return $rpmobj;
}

sub is_same {
  my ($me, $other) = @_;


  return 0 if $me->{'Name'} ne $other->{'Name'};

  return 0 if $me->{'Package_Type'} eq 'src' and 
    $other->{'Package_Type'} ne 'src';

  return $me->{'Version'}->is_equal($other->{'Version'})
    if $me->{'Package_Type'} eq 'src' and 
      $other->{'Package_Type'} eq 'src';

#  if (! defined $other->{'Flavor'} or defined $other->{'Package_Type'}) {
#    use Data::Dumper;
#    print "Other: ", Dumper($other);
#  }

#  if (! defined $me->{'Flavor'} or defined $me->{'Package_Type'}) {
#    use Data::Dumper;
#    print "Me: ", Dumper($me);
#  }

  

  return 0 if defined $me->{'Flavor'} and ! defined $other->{'Flavor'};
  return 0 if ! defined $me->{'Flavor'} and defined $other->{'Flavor'};
  return 0 if $me->{'Flavor'} ne $other->{'Flavor'};

#This hack is to compensate for GPT labeling a noflavor pkg pgm_static
  return 0 if defined $me->{'Package_Type'} and ! defined $other->{'Package_Type'};
  return 0 if ! defined $me->{'Package_Type'} and defined $other->{'Package_Type'};
  return 0 if $me->{'Package_Type'} ne $other->{'Package_Type'} 
    and ! ( $me->{'Package_Type'} =~ m!pgm! and 
            $other->{'Package_Type'} =~ m!pgm! );

  return 0 if $me->{'Flavor'} ne 'noflavor' 
    and $me->{'Package_Type'} ne  $other->{'Package_Type'}
      and $me->{'Package_Type'} =~ m!pgm! 
        and $other->{'Package_Type'} =~ m!pgm!;

  return $me->{'Version'}->is_equal($other->{'Version'});
}

sub is_newer {
  my ($me, $other) = @_;

  return 0 if $me->{'Name'} ne $other->{'Name'};
  return 0 if $me->{'Package_Type'} ne $other->{'Package_Type'};
  return 0 if $me->{'Flavor'} ne $other->{'Flavor'};
  return $me->{'Version'}->is_newer($other->{'Version'});
}

sub version_label {
    my $me = shift;
    my $version_label = "pkg version: " . $me->{'Version'}->comp_id();
    $version_label .= " software version: $me->{'Version_Label'}" 
      if defined $me->{'Version_Label'};
    return $version_label;
}

sub clone {
    my $self = shift;
    my $clone = new();
    replicate($self, $clone);
    return $clone;
}

sub replicate {
  my ($rold) = @_;
  if (ref(\$rold) eq 'SCALAR') {
    return $rold;
  } elsif (ref($rold) eq 'ARRAY') {
    my @list = @$rold;
    return \@list;
  } elsif (ref($rold) eq 'HASH') {
    my $rnew = {};
    for my $e (sort keys %$rold) {
      $rnew->{$e} = replicate($rold->{$e});
    }
    return $rnew
  }
}

sub output_metadata_file {
  my $self=shift;
  my ($filename)=@_;
  my $writer = new Grid::GPT::V1::XML($filename);

  $writer->doctype("gpt_package_metadata","globus_package.dtd");
  $writer->startTag("gpt_package_metadata", Name => $self->{'Name'},
		    Format_Version => $self->{'Format_Version'});
  $writer->characters("\n");
  
  $self->{'Version'}->write_tag($writer);
  $writer->dataElement('Description', $self->{'Description'});
  $writer->characters("\n");
  $writer->dataElement('Functional_Group', $self->{'Functional_Group'});
  $writer->characters("\n");
  $writer->emptyTag("Version_Stability", Release=> $self->{'Version_Stability'});
  $writer->characters("\n");

  for my $co (@{$self->{'Components'}}) {
    $writer->startTag("ComponentInformation", Name => $co->{'Name'});
    $writer->characters("\n");

    $writer->dataElement('Description', $co->{'Description'}) 
      if defined $co->{'Description'};
    $writer->characters("\n") if defined $co->{'Description'};

    $writer->dataElement('VersionLabel', $co->{'VersionLabel'}) 
      if defined $co->{'VersionLabel'};
    $writer->characters("\n") if defined $co->{'VersionLabel'};

    $writer->endTag("ComponentInformation");
    $writer->characters("\n");

  }

  if (defined $self->{'PackageIdentifier'} ) {
    $writer->emptyTag("PackageIdentifier", 
                      Release=> $self->{'PackageIdentifier'}
                     );
    $writer->characters("\n");
  }

  require Grid::GPT::GPTIdentity;
  $writer->emptyTag('PackagingTool', ToolName => "GPT", 
                    ToolVersion => Grid::GPT::GPTIdentity::gpt_version());
  $writer->characters("\n");
 
  $writer->startTag("$self->{'Package_Type'}_pkg");

  $writer->characters("\n");


  # Write With_Flavors data
  if (defined $self->{'With_Flavors'}) {
    $writer->emptyTag("With_Flavors", build=> $self->{'With_Flavors'},
                     	  ColocateLibraries => $self->{'ColocateLibraries'});
  $writer->characters("\n");
  }
  
  # Write out Flavor
  if (defined $self->{'Flavor'}) {
    $writer->dataElement('Flavor', $self->{'Flavor'}, 
                     	  ColocateLibraries => $self->{'ColocateLibraries'});
    $writer->characters("\n");
  }
  # Write out Version_Label
  if (defined $self->{'Version_Label'}) {
    $writer->dataElement('Version_Label', $self->{'Version_Label'});
    $writer->characters("\n");
  }
  # Write Dependency Data
  if (defined($self->{'Source_Dependencies'})) {
    Grid::GPT::V1::BaseDependency::get_xml_from($self->{'Source_Dependencies'}, 
                                            $writer,
                                            'Source_Dependencies')
  }
  
  if (defined($self->{'Binary_Dependencies'})) {
    Grid::GPT::V1::BaseDependency::get_xml_from($self->{'Binary_Dependencies'}, 
                                            $writer,
                                            'Binary_Dependencies')
    }


  my $setdeps = $self->{'Source_Dependencies'}->query(deptype =>'Setup')
    if defined $self->{'Source_Dependencies'};
  $setdeps = $self->{'Binary_Dependencies'}->query(deptype =>'Setup') 
    if defined $self->{'Binary_Dependencies'};
  
  if (defined($setdeps)) {
    for my $t (@$setdeps) {
      write_setup_deps->($writer, $t);
    }
  }
  

  #Write out Build Enviromnment
  if ($self->{'Package_Type'} eq 'src' or $self->{'Package_Type'} eq 'dev' ) {
    $writer->startTag("Build_Environment");
    $writer->characters("\n");
    for my $n ('cflags' , 'external_includes', 'pkg_libs', 'external_libs') {
      next if ! defined $self->{$n};
      $writer->dataElement($n, $self->{$n});
      $writer->characters("\n");
    }
    $writer->endTag("Build_Environment");
    $writer->characters("\n");
  }

  #Write out Build Instructions
  if ($self->{'Package_Type'} eq 'src' and 
      defined $self->{'Build_Instructions'}) {
    my %srcdir;
    $srcdir{'SrcDir'} = $self->{'SrcDir'} if defined $self->{'SrcDir'};
    $writer->startTag("Build_Instructions", %srcdir);
    $writer->characters("\n");
    for my $s (@{$self->{'Build_Instructions'}}) {
      my %args;
      $args{'Macro_Args'} = $s->{'args'}
        if defined $s->{'args'};
     $writer->dataElement('Build_Step', $s->{'command'},%args);
      $writer->characters("\n");
    }
    $self->{'Build_Flavor_Choices'}->write_xml_choices($writer) 
      if defined $self->{'Build_Flavor_Choices'};
    $writer->endTag("Build_Instructions");
    $writer->characters("\n");
  }

  if (defined $self->{'Post_Install_Message'}) {
    $writer->dataElement('Post_Install_Message', 
                         $self->{'Post_Install_Message'});
    $writer->characters("\n");
  }

  if (defined $self->{'Post_Install_Program'}) {
    $writer->dataElement('Post_Install_Program', 
                         $self->{'Post_Install_Program'});
    $writer->characters("\n");
  }

  # Write out setup package fields
  

  if (defined $self->{'Setup_Name'}) {

    $writer->startTag('Setup', Name => $self->{'Setup_Name'});
    $writer->characters("\n");
    $self->{'Setup_Version'}->write_tag($writer);
    $writer->endTag('Setup');    
    $writer->characters("\n");
  }


  $writer->endTag("$self->{'Package_Type'}_pkg");
  $writer->characters("\n");
  $writer->endTag('gpt_package_metadata');
  $writer->write($filename);
}

sub write_setup_deps
  {
    my ($writer, $setup) = @_;
    my ($name, $pkgtype, $versions) = 
      ( $setup->pkgname(), $setup->pkgtype(), $setup->versions());
    $writer->startTag("Source_Setup_Dependency", PkgType => $pkgtype) 
      if ref($setup->depnode()) ne 'Grid::GPT::V1::BinaryDependency';
    $writer->characters("\n");
    $writer->startTag("Setup_Dependency", Name => $name);
    $writer->characters("\n");
    Grid::GPT::V1::Version::convert_version_list2xml($versions, $writer);
    $writer->endTag("Setup_Dependency");
    $writer->characters("\n");
    $writer->endTag("Source_Setup_Dependency") 
      if ref($setup->depnode()) ne 'Grid::GPT::V1::BinaryDependency';
    $writer->characters("\n");
  }

sub AUTOLOAD {
  use vars qw($AUTOLOAD);
  my $self = shift;
  my $type = ref($self) || croak "$self is not an object";
  my $name = $AUTOLOAD;
  $name =~ s/.*://;   # strip fully-qualified portion
  unless (exists $self->{$name} ) {
    croak "Can't access `$name' field in object of class $type";
  } 
  if (@_) {
    return $self->{$name} = shift;
  } else {
    return $self->{$name};
  } 
}

sub DESTROY {}
END { }       # module clean-up code here (global destructor)

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Grid::GPT::V1::Package - Perl extension for reading packaging metadata files

=head1 SYNOPSIS

  use Grid::GPT::V1::Package;
  my $pkg = new Grid::GPT::V1::Package;

  $pkg->read_metadata_file('src_metadata.xml');
  my $bin_pkg = $pkg->convert_metadata($type, $build_flavor);
  $bin_pkg->output_metadata_file("$ {type}_metadata.xml");

=head1 DESCRIPTION

I<Grid::GPT::V1::Package> is used to manage (ie. read, write, convert)
packaging metadata. The data is stored in XML format that follows the
file F<package.dtd>.

=head1 Metadata Fields

=over 4

=item Name

Name of the package.

=item Version

A L<Grid::GPT::V1::Version|Grid::GPT::V1::Version> object.

=item Format_Version

A number which defines the metadata format version.

=item Package_Type

The package type one of "data", "dev", "doc", "pgm",
"pgm_static", "rtl", "src", or virtual.

=item Flavor

The build flavor a binary package was generated with. N/A to src
packages.

=item Version_Label

For a virtual package, this field contains the version description of
the external library.

=item With_Flavor

Yes or no if the src package should be built using build flavors. N/A
to binary packages.

=item Description

A paragraph or two that adds information about this package release.
This is not used by any tools.

=item Functional_Group

A "/" delimited string that indicates what group the package is a part
of.  This is used for bundles.

=item Version_Stability

An indicater about the stibility of the package release. Can be one of
I<experimental>, I<alpha>, I<beta>, or I<production>.

=item Source_Dependencies

Hash of hashes of
L<Grid::GPT::V1::SourceDependency|Grid::GPT::V1::SourceDependency> objects.
The top level hash is keyed by the dependency type. The lower level
hashes are keyed by a combination of package name and package
type. N/A to binary packages.

=item Binary_Dependencies

Hash of hashes of
L<Grid::GPT::V1::BinaryDependency|Grid::GPT::V1::BinaryDependency> objects.
The top level hash is keyed by the dependency type. The lower level
hashes are keyed by a combination of package name and package
type. N/A to src packages.

=item Setup_Dependency

Gives the name and version requirements of a setup package.  Setup
packages are packages that need to be configured or "setup" by the
package installer.

=item Source_Setup_Dependencies

A list of Setup_Dependencies paired with the binary package type that
needs it.  Only for src packages.

=item cflags

String of flags to include for preprocessing.  Only applicable to src
and dev packages.

=item external_includes

String of flags to include external directories containing header
files.  Only applicable to src and dev packages.


=item pkg_libs

String of flags which are used to link libraries provided by the
package.  Only applicable to src and dev packages.  Note that when a
package is converted from src to dev, each library will be appended
with "_<flavor>".


=item external_libs

String of flags to include external libraries.  Only applicable to src
and dev packages.


=item Filelist

For virtual and setup packages only, a Package object can contain a
list of Filelist references. Each reference contains a directory
(Dir), A flag on whether the files are flavored or not (Flavored), A
field indicating which binary package the files belong to
(Package_Type), and a list of filename (Files).  Flavored files in
setup packages are currently not supported.


=item Setup_Name

A Package object can contain the name of a setup package format.  This
name is used for setup dependencies. This name gets passed on to pgm
and pgm_static types.

=item Setup_Version

A Package object can contain the version of a setup package format.
This version is used for setup dependencies. This gets passed on
to pgm and pgm_static types.



=item Post_Install_Message

For setup packages only, a Package object can contain a setup
requirements message.  This message details the tasks that need to be
done to complete the installation of a setupo package. The message is
displayed to the user after the package is installed.


=item Post_Install_Program

For setup packages only, a Package object can contain a setup
requirements program.  This is the program that needs to be run to
complete the setup.


=item doctype

The documentation type for the XML input/output.

=item system

The dtd or schema used in the XML input/output.

=back


=head1 Methods

=over 4

=item new

Create a new I<Grid::GPT::V1::Package> object.

=item read_metadata_file(filename)

load metadata from an input file.  Any of the metadata package format
types can be used as inputs.

=item output_metadata_file(filename)

Dumps the metadata into an output file in xml format

=item convert_metadata(pkg_type)

Converts a src package metadata object into a binary metadata object
of the given package type.  The binary metadata object is returned as
a reference.

=back



=head1 AUTHOR

Eric Blau <eblau@ncsa.uiuc.edu> Michael Bletzinger <mbletzin@ncsa.uiuc,edu>

=head1 SEE ALSO

perl(1) Grid::GPT::V1::SourceDependency(1) Grid::GPT::V1::BinaryDependency(1) Grid::GPT::V1::XML(1) Grid::GPT::V1::Version(1)..

=cut
