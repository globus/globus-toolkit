use Getopt::Long;

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

my $x509_cert_dir  = '/etc/grid-security/certificates';
my $x509_user_cert = '/etc/grid-security/hostcert.pem';
my $x509_user_key  = '/etc/grid-security/hostkey.pem';
my $gridmap        = '/etc/grid-security/grid-mapfile';
my $help = 0;

my $result = GetOptions('-x509-cert-dir|d=s' => \$x509_cert_dir,
                     '-x509-user-cert|c=s' => \$x509_user_cert,
                     '-x509-user-key|k=s' => \$x509_user_key,
                     '-grid-mapfile|g=s' => \$gridmap,
                     '-help|h' => \$help);
if (!$result || $help)
{
    my $basename = $0;
    $basename =~ s,.*/,,;

    print "$basename $OPTIONS\n".
          "    -x509-cert-dir|-d DIR      Set X.509 Certificate Directory\n".
          "    -x509-user-cert|-c FILE    Set path to X.509 certificate\n".
          "                               for the gatekeeper\n".
          "    -x509-user-key|-k FILE     Set path to X.509 key file for \n".
          "                               the gatekeeper\n".
          "    -grid-mapfile|-g FILE      Set path for grid mapfile\n\n".
          "DEFAULTS:\n".
          "    Certificate Directory: /etc/grid-security/certificates\n".
          "    Certificate File: /etc/grid-security/hostcert.pem\n".
          "    Key File: /etc/grid-security/hostkey.pem\n".
          "    Grid Map File: /etc/grid-security/grid-mapfile\n";

    exit(1);
}

my $metadata = new Grid::GPT::Setup(package_name => "globus_gatekeeper_setup");

my $globusdir = $ENV{GLOBUS_LOCATION};
my $setupdir = "$globusdir/setup/globus/";
my $gk_conf = "$globusdir/etc/globus-gatekeeper.conf";

print "Creating gatekeeper configuration file...\n";

if ( ! open(CONF, ">$gk_conf") )
{
   die "open failed for $gk_conf";
}

print CONF <<EOF;
  -x509_cert_dir $x509_cert_dir
  -x509_user_cert $x509_user_cert
  -x509_user_key $x509_user_key
  -gridmap $gridmap
  -home $globusdir
  -e libexec
  -logfile var/globus-gatekeeper.log
  -port 2119
  -grid_services etc/grid-services
  -inetd
EOF

print "Done\n";

if ( ! -d "$globusdir/var" )
{
   print "Creating gatekeeper log directory...\n";
   system "mkdir -p $globusdir/var";
   print "Done\n";
}

if ( ! -d "$globusdir/etc/grid-services" )
{
   print "Creating grid services directory...\n";
   system "mkdir -p $globusdir/etc/grid-services";
   print "Done\n";
}

$metadata->finish();
