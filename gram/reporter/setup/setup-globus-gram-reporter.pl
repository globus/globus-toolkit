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

my $globusdir        = $ENV{GLOBUS_LOCATION};
my $setupdir         = "$globusdir/setup/globus/";
my $slapd_conf       = "${globusdir}/etc/grid-info-slapd.conf";
my $tmp_slapd_conf   = "./grid-info-slapd.conf.tmp";
my $ldif_conf        = "${globusdir}/etc/grid-info-resource-ldif.conf";
my $need_print       = 1;
my $includes_started = 0;
my $line_added       = 0;

my $hostname = `${setupdir}/globus-hostname`;
$hostname =~ s/\s//g; #strip whitespace

# Let's make sure the required files are there.
if ( ! -f "$slapd_conf" )
{
   print "Error: $slapd_conf file not found.  It is required for this setup program\n";
   exit(1);
}

if ( ! -f "$ldif_conf" )
{
   print "Error: $ldif_conf file not found.  It is required for this setup program\n";
   exit(1);
}

system("grep grid-info-gram-reporter.schema $slapd_conf >/dev/null");
if ( ! $? )
{
   print "gram reporter entry already been inserted in $slapd_conf\n";
}
else
{
   # insert line in the slapd_conf file

   open(INFO, "<$slapd_conf");
   open(TMPFILE, ">./$tmp_slapd_conf");

   while ($line = <INFO>)
   {
     chomp($line);
     $line =~ s/^\s+//g;  # remove leading whitespace

     $first7 = substr($line,0,7);

     if ($line_added==0)
     {
        if ($first7 eq "include")
        {
           $includes_started=1;
        }

        # find the first line after the include lines that is not just a newline
        if (($first7 ne "include") &&
            ($first7 ne "") &&
            ($includes_started==1))
        {
           $line_added=1;
           print "adding gram reporter entry in $slapd_conf\n";
           print TMPFILE "include  ${globusdir}/etc/grid-info-gram-reporter.schema\n";
           print TMPFILE "\n";
        }
     }

     print TMPFILE "$line\n";
   }
   close(TMPFILE);
   close(INFO);

   system("mv $tmp_slapd_conf $slapd_conf");
}

system("grep \"The following lines for fork entry added by setup-globus-gram-reporter\" $ldif_conf >/dev/null");
if ( ! $? )
{
   print "gram reporter entry already added to $ldif_conf\n";
}
else
{
   print "appending gram reporter entry to $ldif_conf\n";
   open(LDIFFILE, ">>$ldif_conf");

   print LDIFFILE "\n# The following lines for fork entry added by setup-globus-gram-reporter\n";
   print LDIFFILE "# generate gram reporter fork info every 30 seconds\n";
   print LDIFFILE "dn: Mds-Software-deployment=jobmanager, Mds-Host-hn=${hostname}, Mds-Vo-name=local, o=grid\n";
   print LDIFFILE "objectclass: GlobusTop\n";
   print LDIFFILE "objectclass: GlobusActiveObject\n";
   print LDIFFILE "objectclass: GlobusActiveSearch\n";
   print LDIFFILE "type: exec\n";
   print LDIFFILE "path: $globusdir/libexec\n";
   print LDIFFILE "base: globus-gram-reporter\n";
   print LDIFFILE "args: -conf $globusdir/etc/globus-job-manager.conf -type fork -rdn jobmanager -dmdn Mds-Host-hn=${hostname},Mds-Vo-name=local,o=grid\n";
   print LDIFFILE "cachetime: 30\n";
   print LDIFFILE "timelimit: 20\n";
   print LDIFFILE "sizelimit: 20\n";
   close(LDIFFILE);
}

$metadata->finish();
