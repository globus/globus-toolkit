use Getopt::Long;

my $selected_jm_type;
my @all_jm_types = ('condor', 'easymcs', 'fork', 'glunix', 'grd', 'loadleveler', 'lsf',
                    'nqe', 'nswc', 'pbs', 'pexec', 'prun');


GetOptions( 'type=s' => \$selected_jm_type,
            'help' => \$help)
  or pod2usage(1);

pod2usage(0) if $help;

sub pod2usage {
  my $ex = shift;
  print "setup-globus-gram-job-manager [ \\
               -help \\
               -type=[ @all_jm_types ]\\
                     (fork is default)\\
              ]\n";
  exit $ex;
}

if ( $selected_jm_type eq "" )
{
   $selected_jm_type='fork';
}

if ( ! grep {$_ eq $selected_jm_type} @all_jm_types)
{
   die "Invalid Job Manager Type, valid types are: @all_jm_types"
}

if ($selected_jm_type eq "fork")
{
   $rdn="jobmanager";
}
else
{
   $rdn="jobmanager-$selected_jm_type";
}

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

print "Setting up $selected_jm_type gram reporter\n";
print "--------------------------------\n";


system("grep grid-info-gram-reporter.schema $slapd_conf >/dev/null");
if ( ! $? )
{
   print "gram reporter entry found in $slapd_conf.  skipping...\n";
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

system("grep \"The following lines for $selected_jm_type entry added by setup-globus-gram-reporter\" $ldif_conf >/dev/null");
if ( ! $? )
{
   print "gram reporter entry for $selected_jm_type already added to $ldif_conf\n";
}
else
{
   print "appending gram reporter $selected_jm_type entry to $ldif_conf\n";
   open(LDIFFILE, ">>$ldif_conf");

   print LDIFFILE "\n# The following lines for $selected_jm_type entry added by setup-globus-gram-reporter\n";
   print LDIFFILE "# generate gram reporter $selected_jm_type info every 30 seconds\n";
   print LDIFFILE "dn: Mds-Software-deployment=$rdn, Mds-Host-hn=${hostname}, Mds-Vo-name=local, o=grid\n";
   print LDIFFILE "objectclass: GlobusTop\n";
   print LDIFFILE "objectclass: GlobusActiveObject\n";
   print LDIFFILE "objectclass: GlobusActiveSearch\n";
   print LDIFFILE "type: exec\n";
   print LDIFFILE "path: $globusdir/libexec\n";
   print LDIFFILE "base: globus-gram-reporter\n";
   print LDIFFILE "args: -conf $globusdir/etc/globus-job-manager.conf -type $selected_jm_type -rdn $rdn -dmdn Mds-Host-hn=${hostname},Mds-Vo-name=local,o=grid\n";
   print LDIFFILE "cachetime: 30\n";
   print LDIFFILE "timelimit: 20\n";
   print LDIFFILE "sizelimit: 20\n";
   close(LDIFFILE);
}

$metadata->finish();
