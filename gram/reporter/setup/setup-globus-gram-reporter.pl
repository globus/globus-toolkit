my $gpath = $ENV{GPT_LOCATION};

if (!defined($gpath))
{
  $gpath = $ENV{GLOBUS_LOCATION};
}

if (!defined($gpath))
{
   die "GPT_LOCATION or GLOBUS_LOCATION needs to be set before running this script"
}

@INC = (@INC, "$gpath/lib/perl");

require Grid::GPT::Setup;

my $metadata = new Grid::GPT::Setup(package_name => "globus_gram_reporter_setup");

my $globusdir = $ENV{GLOBUS_LOCATION};
my $setupdir = "$globusdir/setup/globus/";
my $jm_conf = "$globusdir/etc/globus-job-manager.conf";
my $jm_service = "$globusdir/etc/grid-services/jobmanager";
my $need_print = 1;

my $hostname = `${setupdir}/globus-hostname`;
$hostname =~ s/\s//g; #strip whitespace

print "This entry must be added to the bottom of $globus_dir/etc/grid-info-resource-ldif.conf\n";

print "AFTER THIS LINE--------->\n";
print "# generate gram info every 30 seconds\n";
print "dn: Gram-service=jobmanager, Mds-Host-hn=${hostname}, Mds-Vo-name=local, o=grid\n";
print "objectclass: GlobusTop\n";
print "objectclass: GlobusActiveObject\n";
print "objectclass: GlobusActiveSearch\n";
print "type: exec\n";
print "path: $globusdir/libexec\n";
print "base: globus-gram-reporter\n";
print "args: -conf $globusdir/etc/globus-job-manager.conf -type fork -rdn jobmanager -dmdn=Mds-Host-hn=${hostname},Mds-Vo-name=local,o=grid\n";
print "cachetime: 30\n";
print "timelimit: 20\n";
print "sizelimit: 20\n";
print "<----------BEFORE THIS LINE\n";

$metadata->finish();
