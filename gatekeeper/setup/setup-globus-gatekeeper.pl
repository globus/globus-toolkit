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

my $metadata = new Grid::GPT::Setup(package_name => "globus_gatekeeper_setup");

my $globusdir = $ENV{GLOBUS_LOCATION};
my $setupdir = "$globusdir/setup/globus/";
my $gk_conf = "$globusdir/etc/globus-gatekeeper.conf";
my $need_print = 1;

if ( ! -f "$gk_conf" )
{
   print "Creating gatekeeper configuration file...\n";

   if ( ! open(CONF, ">$gk_conf") )
   {
      print STDERR "open failed for $gk_conf\n";
   }
   else
   {

      $need_print=0;

      print CONF <<EOF;
         -x509_cert_dir /etc/grid-security/certificates
         -x509_user_cert /etc/grid-security/hostcert.pem
         -x509_user_key /etc/grid-security/hostkey.pem
         -gridmap /etc/grid-security/grid-mapfile
         -home $globusdir
         -e libexec
         -logfile var/globus-gatekeeper.log
         -port 2119
         -grid_services etc/grid-services
         -inetd
EOF

      print "Done\n";

   }
}

if ( ! -d "$globusdir/var" )
{
   $need_print=0;
   print "Creating gatekeeper log directory...\n";
   system "mkdir -p $globusdir/var";
   print "Done\n";
}

if ( ! -d "$globusdir/etc/grid-services" )
{
   $need_print=0;
   print "Creating grid services directory...\n";
   system "mkdir -p $globusdir/etc/grid-services";
   print "Done\n";
}

if ( $need_print )
{
   print "Done\n";
}

$metadata->finish();
