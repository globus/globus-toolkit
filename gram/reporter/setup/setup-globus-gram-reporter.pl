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

print "\nIn the file ${globusdir}/etc/grid-info-slapd.conf\n";
print "The following line must be added after the other include statements.\n";
print "AFTER THIS LINE--------->\n";
print "include  ${globusdir}/etc/grid-info-gram-reporter.schema\n";
print "<----------BEFORE THIS LINE\n\n\n";

print "In the file ${globusdir}/etc/grid-info-resource-ldif.conf\n";
print "The following lines must be added at the bottom.\n";

print "AFTER THIS LINE--------->\n";
print "# generate gram info every 30 seconds\n";
print "dn: Mds-Software-deployment=jobmanager, Mds-Host-hn=${hostname}, Mds-Vo-name=local, o=grid\n";
print "objectclass: GlobusTop\n";
print "objectclass: GlobusActiveObject\n";
print "objectclass: GlobusActiveSearch\n";
print "type: exec\n";
print "path: $globusdir/libexec\n";
print "base: globus-gram-reporter\n";
print "args: -conf $globusdir/etc/globus-job-manager.conf -type fork -rdn jobmanager -dmdn Mds-Host-hn=${hostname},Mds-Vo-name=local,o=grid\n";
print "cachetime: 30\n";
print "timelimit: 20\n";
print "sizelimit: 20\n";
print "<----------BEFORE THIS LINE\n";

$metadata->finish();
