use Getopt::Long;
use IO::File;

my $gpath = $ENV{GPT_LOCATION};

if (!defined($gpath))
{
    $gpath = $ENV{GLOBUS_LOCATION};
}

if (!defined($gpath))
{
    die "GPT_LOCATION or GLOBUS_LOCATION needs to be set before running this script";
}

@INC = (@INC, "$gpath/lib/perl");

require Grid::GPT::Setup;

my $metadata =
    new Grid::GPT::Setup(package_name => "globus_gram_job_manager_setup");

my $globusdir	= $ENV{GLOBUS_LOCATION};
my $setupdir	= "$globusdir/setup/globus";
my $sysconfdir	= "$globusdir/etc";
my $libexecdir	= "$globusdir/libexec";
my $bindir	= "$globusdir/bin";
my $sbindir	= "$globusdir/sbin";

&setup_job_manager_conf();
&setup_script_shbang("${setupdir}/globus-job-manager-service.in",
                      "${libexecdir}/globus-job-manager-service");
&setup_script_shbang("${setupdir}/globus-job-manager-mds-provider.in",
                      "${libexecdir}/globus-job-manager-mds-provider");
&setup_script_shbang("$setupdir/globus-job-manager-script.in",
                     "$libexecdir/globus-job-manager-script.pl");
print "Done\n";

$metadata->finish();

sub setup_job_manager_conf
{
    my ($gatekeeper_port, $gatekeeper_subject);
    my ($hostname, $cpu, $manufacturer, $os_name, $os_version);
    my $jm_conf	= "${sysconfdir}/globus-job-manager.conf";
    my $conf_file;

    ($gatekeeper_subject, $gatekeeper_port) =
	&get_gatekeeper_info("${sysconfdir}/globus-gatekeeper.conf");

    ($hostname, $cpu, $manufacturer, $os_name, $os_version) = &get_system_info();

    print "Creating job manager configuration file...\n";
    $conf_file = new IO::File(">$jm_conf") || die "open failed for $jm_conf";

    print $conf_file <<EOF;
	-home \"$globusdir\"
	-globus-gatekeeper-host $hostname
	-globus-gatekeeper-port $gatekeeper_port
	-globus-gatekeeper-subject \"$gatekeeper_subject\"
	-globus-host-cputype $cpu
	-globus-host-manufacturer $manufacturer
	-globus-host-osname $os_name
	-globus-host-osversion $os_version
	-save-logfile on_errors
	-machine-type unknown
EOF
    $conf_file->close();
}

sub get_gatekeeper_info
{
    my ($gatekeeper_conf_filename) = $_[0];
    my ($host_cert_line, $host_cert_file, $subject, $port) = ();

    print "Reading gatekeeper configuration file...\n";
    if ( ! -f "$gatekeeper_conf_filename" )
    {
       die "File \"$gatekeeper_conf_filename\" not found.\n";
    }

    chomp($host_cert_line = `grep x509_user_cert $gatekeeper_conf_filename`);
    $host_cert_file = (split(/x509_user_cert/, $host_cert_line))[1];
    $host_cert_file =~ s/^\s+//; #strip leading whitespace

    if ( ! -r "$host_cert_file" )
    {
	print STDERR <<EOF;
Warning: Host cert file: $host_cert_file not found.  Re-run
         setup-globus-gram-job-manager after installing host cert file.
EOF
       $subject="unavailable at time of install";
    }
    else
    {
       chomp($subject =
             `${bindir}/grid-cert-info -subject -file $host_cert_file`);
       if ( $? != 0 )
       {
	  die "Failed getting subject from host certificate: $host_cert_file.";
       }
       else
       {
	  $subject =~ s/^\s+//; #strip leading whitespace
       }
    }

    my $port = 0;
    if ( open(GK_CONF, $gatekeeper_conf_filename) ) {
      $port = (m/^(\s*)-port\s+([0-9]+)/)[1] while( ! $port && ($_=<GK_CONF>) );
      close GK_CONF;
    }

    return ($subject, $port);
}

sub get_system_info
{
    my ($hostname, $cpu, $manufacturer, $os_name, $os_version);

    print "Determining system information...\n";
    chomp($hostname = `${bindir}/globus-hostname`);

    ($cpu, $manufacturer) = (split(/-/, `${sbindir}/config.guess`))[0,1];
    $uname_cmd = &lookup_shell_command("GLOBUS_SH_UNAME");

    chomp($os_name=`$uname_cmd -s`);
    $os_version="";

    if($os_name eq "AIX")
    {
       chomp($os_version = `$uname_cmd -v`);
       $os_version .= ".";
    }

    chomp($os_version .= `$uname_cmd -r`);

    return ($hostname, $cpu, $manufacturer, $os_name, $os_version);
}

sub lookup_shell_command
{
    my ($cmdvar, $cmd);

    $cmdvar = $_[0];

    chomp($cmd = `$bindir/globus-sh-exec -e echo \\\$$cmdvar`);

    return $cmd;
}

sub setup_script_shbang
{
    my $inname = shift;
    my $outname = shift;
    my $infile = new IO::File("<$inname");
    my $outfile = new IO::File(">$outname");
    my $perl = &lookup_shell_command("GLOBUS_PERL");

    while(<$infile>)
    {
	s/\@PERL\@/$perl/g;
	s/\@GLOBUS_LOCATION\@/$globusdir/g;

	$outfile->print($_);
    }
    $infile->close();
    $outfile->close();
    chmod 0755, $outname;
}
