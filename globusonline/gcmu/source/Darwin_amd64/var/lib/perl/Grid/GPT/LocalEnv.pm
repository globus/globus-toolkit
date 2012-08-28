package Grid::GPT::LocalEnv; 
use strict; 
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

require Exporter;
require AutoLoader;
use Cwd;

@ISA = qw(Exporter AutoLoader);
$VERSION = '0.01';

sub get_tool_location {
  my $program = shift;
  my %locations = (
                   gtar => "/usr/bin/gnutar",
                   gzip => "/usr/bin/gzip",
                   gunzip => "/usr/bin/gunzip",
                   gmake => "/usr/bin/make",
                   perl => "/opt/local/bin/perl",
                   rpm => "Not Available",
                   rpmbuild => "Not Available",
                  );

  return $locations{$program};

}

sub get_rpm_setting {
  my $item = shift;

  my %rpm = (
             license => "N/A",
             vendor => "N/A",
             ftpsite => "N/A",
             url => "N/A",
             packager => "N/A",
             prefix => "N/A",
             '/usr/sbin/Check' => "N/A",
            );
  return $rpm{$item};

}

sub get_target {return "i686-apple-darwin10.8.0"}
sub use_system_tar {return "1"}

sub listconfig {

  if (use_system_tar) {
    print "Using system tar and gzip programs to unpack packages\n";
    print "GNU tar located at " , get_tool_location('gtar') , "\n";
    print "GNU zip located at " , get_tool_location('gzip') , "\n";
    print "GNU unzip located at " , get_tool_location('gunzip') , "\n";
  } else {
    print "Using Archive::Tar and Compress::Zlib to unpack packages\n";
  }
  print "GNU make located at " , get_tool_location('gmake') , "\n";
  print "Perl located at " , get_tool_location('perl') , "\n";
  print "rpm located at " , get_tool_location('rpm') , "\n";
  print "rpmbuild located at " , get_tool_location('rpmbuild') , "\n";
  print "RPM Package License set to " , get_rpm_setting('license') , "\n";
  print "RPM Package Vendor set to " , get_rpm_setting('vendor') , "\n";
  print "RPM Package FTP Site set to " , get_rpm_setting('ftpsite') , "\n";
  print "RPM Package URL set to " , get_rpm_setting('url') , "\n";
  print "RPM Packager set to " , get_rpm_setting('packager') , "\n";
  print "RPM Prefix set to " , get_rpm_setting('prefix') , "\n";
  print "/usr/sbin/Check is supressed\n" 
    if get_rpm_setting('/usr/sbin/Check') eq 'Supress';
  print "GNU target platform set to " , get_target() , "\n";

}


# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
