package Grid::GPT::Localize;

use strict;
use Carp;

require Exporter;
use vars       qw($VERSION @ISA);

# set the version for version checking
$VERSION     = 0.01;

@ISA         = qw(Exporter);

{
  my $target;
  sub get_target {
    my $gpath = shift;
    return $target if defined $target;
    $target = `$gpath/share/gpt/config.guess`;
    chomp($target);
    return $target;
  }
}
sub get_tool_list {

  return (
          'gtar',
          'gzip',
          'gunzip',
          'gmake',
          'perl',
          'rpm',
          'rpmbuild',
         );
}

sub get_rpm_settings_list {

  return (
          'license',
          'vendor',
          'ftpsite',
          'url',
          'packager',
          'prefix',
         );
}

sub new {
  my ($that, %args)  = @_;

  push @INC, 
  my $class = ref($that) || $that;
  my $me  = {
             ignore_errors => $args{'ignore_errors'},
             gpath => $args{'gpath'},
             systar => $args{'systar'},
             substitutions => {
                               target => get_target($args{'gpath'}),
                               systar => defined $args{'systar'} ? '1' : '0',
                              }
            };


  bless $me, $class;

  for my $t (get_tool_list()) {
    $me->{"$ {t}_location"} = $args{$t};
  }

  return $me;

}


sub set_perl {
  my ($me, %args) = @_;
  my ($perl_location, $perl_version) = ($args{'location'}, $args{'version'});

  $perl_location = $me->{'perl_location'} if ! defined $perl_location;
  $perl_location = find_perl($perl_location, $perl_version);

  $me->setsub('perl', $perl_location);
  return $perl_location
}


sub find_perl {

  my ($perl_location, $perl_version) = @_;

  if (defined $perl_location) {

    my $test = eval_perl($perl_location, $perl_version, 1);

    return undef if ! $test;

    return $perl_location
  }

  my @paths = split /:/, $ENV{'PATH'};

  for my $d (@paths) {

    if (-f "$d/perl" ) {
      my $test = eval_perl("$d/perl", $perl_version);
      if ($test) {
        return "$d/perl";
      }
    }
  }
  return undef;
}

sub eval_perl {
  my ($perl_location, $perl_version, $print_result) = @_;

#  printf("$perl_location -e \"if (defined eval { require $perl_version})\" \\\
#-e \"{\" \\\
#-e \" print \'Perl is fine\';\" \\\
#-e \"}\" \\\
#-e \"else\" \\\
#-e \"{\" \\\
#-e \"  die \'Perl is older than $perl_version\'; \\\
#-e \"}\" " );

my  $result=`$perl_location -e \"if (defined eval { require $perl_version})\" \\\
-e \"{\" \\\
-e \" print \'Perl is fine\';\" \\\
-e \"}\" \\\
-e \"else\" \\\
-e \"{\" \\\
-e \"  print \'Perl is older than $perl_version\'; exit 1;\" \\\
-e \"}\" `;

  return 1 if $result eq 'Perl is fine';

  print STDERR "$result\n" if defined $print_result;
  return 0;

}


sub probe_for_tools {
  my ($me) = @_;

  my @paths = split /:/, $ENV{'PATH'};

  for my $d (@paths) {

    if (defined $me->{'systar'}) {
      if (! defined $me->{'gtar_location'}) {
        if (-f "$d/gtar" ) {
          my $result = `$d/gtar --version`;
          $me->{'gtar_location'} = "$d/gtar" if $result =~ m!GNU\s+tar!;
        }
        if (-f "$d/tar" ) {
          my $result = `$d/tar --version`;
          $me->{'gtar_location'} = "$d/tar" if $result =~ m!GNU\s+tar!;
        }
      }
    }

    if (! defined $me->{'gmake_location'}) {
      if (-f "$d/gmake" ) {
        my $result = `$d/gmake --version`;
        $me->{'gmake_location'} = "$d/gmake" if $result =~ m!GNU\s+[mM]ake!;
      }
      if (-f "$d/make" ) {
        my $result = `$d/make --version`;
        $me->{'gmake_location'} = "$d/make" if $result =~ m!GNU\s+[mM]ake!;
      }
    }

    if (! defined $me->{'gunzip_location'}) {
      if (-f "$d/gunzip" ) {
        my $result = `$d/gunzip --version 2>&1`;
        $me->{'gunzip_location'} = "$d/gunzip" if $result =~ m!gunzip\s+!;
      }
    }

    if (! defined $me->{'gzip_location'}) {
      if (-f "$d/gzip" ) {
        my $result = `$d/gzip --version 2>&1`;
        $me->{'gzip_location'} = "$d/gzip" if $result =~ m!gzip\s+!;
      }
    }

    if (! defined $me->{'rpm_location'}) {
      if (-f "$d/rpm" ) {
        my $result = good_rpm("$d/rpm");
        $me->{'rpm_location'} = "$d/rpm" if $result;
      }
    }
    if (! defined $me->{'rpmbuild_location'}) {
      if (-f "$d/rpmbuild" ) {
        my $result = `$d/rpmbuild --version 2>/dev/null`;
        $me->{'rpmbuild_location'} = "$d/rpmbuild" if $result =~ m!RPM!;
      }
    }
  }
}

sub set_tools {
  my ($me) = @_;
  my $msg = "";

  if (defined $me->{'systar'}) {
    $msg .= "Can't find GNU tar. Use -gtar=<location> flag" 
      if ! defined $me->{'gtar_location'};
    $me->setsub('gtar', $me->{'gtar_location'});
    $msg .= "Can't find GNU unzip. Use -gunzip=<location> flag" 
      if ! defined $me->{'gunzip_location'};
    $me->setsub('gunzip', $me->{'gunzip_location'});
    $msg .= "Can't find GNU zip. Use -gzip=<location> flag" 
      if ! defined $me->{'gzip_location'};
    $me->setsub('gzip', $me->{'gzip_location'});
  } else {
    $me->setsub('gtar', 'N/A');
    $me->setsub('gzip', 'N/A');
    $me->setsub('gunzip', 'N/A');
  }

  $msg .= "Can't find GNU make. Use -gmake=<location> flag" 
    if ! defined $me->{'gmake_location'};
  $me->setsub('gmake', $me->{'gmake_location'});
  $me->{'rpm_location'} = 'Not Available' 
    if ! defined $me->{'rpm_location'};

  $me->setsub('rpm', $me->{'rpm_location'});

  # Use rpm if rpmbuild does not exist.
  $me->{'rpmbuild_location'} = $me->{'rpm_location'}
    if ! defined $me->{'rpmbuild_location'};
  $me->setsub('rpmbuild', $me->{'rpmbuild_location'});

  if ($msg ne "") {
    die "ERROR: $msg with gpt-config\n" if ! defined $me->{'ignore_errors'};
    print STDERR "WARNING: $msg with gpt-config\n";
  }
}

sub check_ln_s {

  my $ln_s="ln -s";

  my $testresult = system ("echo >gpttest.file");
  $testresult = system ("$ln_s  gpttest.file gpttest 2>/dev/null");
  $ln_s = 'cp -rp' if -f "gpttest.exe";

  if (! $testresult) {
    $ln_s="ln";
    $testresult = system ("$ln_s  gpttest.file gpttest 2>/dev/null");
    $ln_s = 'cp -rp' if ! $testresult;
  }
  system ("rm -f gpttest gpttest.exe gpttest.file");
  return $ln_s;
}

sub check_for_usr_sbin_check {
  my ($me) = @_;

  $me->setsub('/usr/sbin/Check', 'N/A');

  return if ! -f "/usr/sbin/Check";
  $me->setsub('/usr/sbin/Check', 'Supress');

}

sub good_rpm {
  my $rpm = shift;
  return 0 if ! -x $rpm;
  my $rpmversion = `$rpm --version`;

my @d = $rpmversion =~ m!(\d+)\.(\d+)(?:\.(\d+))?!;

my $d1 = (defined($d[0])) ? $d[0] : 0;
my $d2 = (defined($d[1])) ? $d[1] : 0;
my $d3 = (defined($d[2])) ? $d[2] : 0;

my @badversions = (
                   { d1 => 4, d2 => 0, d3 => 0},
                   { d1 => 4, d2 => 0, d3 => 1},
                   { d1 => 4, d2 => 0, d3 => 2},
                  );

  for my $bv (@badversions) {
    return 0 if $d1 == $bv->{'d1'} and $d2 == $bv->{'d2'} 
      and $d1 == $bv->{'d3'};
  }

  return 1;
}



sub setsub {
  my ($me, $name, $value) = @_;
  $me->{'substitutions'}->{$name} = $value;
}

sub getsub {
  my ($me, $name) = @_;
  return $me->{'substitutions'}->{$name};
}

sub set_rpm_settings {
  my ($me) = @_;
  $me->setsub('license',"GNU");
  $me->setsub('vendor',"NCSA");
  $me->setsub('ftpsite',"ftp.ncsa.uiuc.edu");
  $me->setsub('url',"http://www.gridpackaging.org");
  $me->setsub('packager',"NCSA");
  $me->setsub('prefix',"/usr/grid");
}

sub clear_rpm_settings {
  my ($me) = @_;
  $me->setsub('license',"N/A");
  $me->setsub('vendor',"N/A");
  $me->setsub('ftpsite',"N/A");
  $me->setsub('url',"N/A");
  $me->setsub('packager',"N/A");
  $me->setsub('prefix',"N/A");
}


sub localize {
  my($me) = @_;

  my $gpath = $me->{'gpath'};

  require Grid::GPT::FilelistFunctions;
  Grid::GPT::FilelistFunctions::mkinstalldir("$gpath/var/lib/perl/Grid/GPT/");

  open INFILE, "$gpath/lib/perl/Grid/GPT/LocalEnv.pm.in";
  open OUTFILE, ">$gpath/var/lib/perl/Grid/GPT/LocalEnv.pm";
  my $link = ">$gpath/var/lib/perl/Grid/GPT/LocalEnv.pm";

  for my $l (<INFILE>) {
    while (my ($n,$v) = each(%{$me->{'substitutions'}})) {
      $v = "NOT CONFIGURED" if ! defined $v;
      $l =~ s!\@$n\@!$v!g;
    }
    print OUTFILE $l;
  }
  close INFILE;
  close OUTFILE;
}



1;
__END__
