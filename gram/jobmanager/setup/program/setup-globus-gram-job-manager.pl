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

my $metadata = new Grid::GPT::Setup(package_name => "globus_gram_job_manager_setup");

my $globusdir = $ENV{GLOBUS_LOCATION};
my $setupdir = "$globusdir/setup/globus/";
my $jm_conf = "$globusdir/etc/globus-job-manager.conf";
my $jm_service = "$globusdir/etc/grid-services/jobmanager";
my $need_print = 1;

if ( ! -f "$jm_conf" )
{
   print "Creating job manager configuration file...\n";

   if ( ! open(CONF, ">$jm_conf") )
   {
      print STDERR "open failed for $jm_conf\n";
   }
   else
   {

      $need_print=0;

      print CONF "-home $globusdir\n";
      print CONF "-e $globusdir/libexec\n";
      print CONF "-save-logfile on_errors\n";
      close(CONF);
      print "Done\n";

   }
}

if ( ( -d "$globusdir/etc/grid-services" ) &&
     ( ! -f "$jm_service" ) )
{
   print "Creating grid service jobmanager...\n";
  
   if ( ! open(SERVICE, ">jm_service") )
   {
      print STDERR "open failed for $jm_service\n";
   }
   else
   {
      #service arguments must be on the same line
      print SERVICE "jobmanager stderr_log,local_cred - ".
                    "$globusdir/libexec/globus-job-manager ".
                    "globus-job-manager ".
                    "-conf $globusdir/etc/globus-job-manager.conf ".
                    "-type fork -rdn jobmanager -machine-type unknown ".
                    "-publish-jobs\n";

      $need_print=0;
      close(SERVICE);
      print "Done\n";
   }
}

if ( $need_print )
{
   print "Done\n";
}

$metadata->finish();
