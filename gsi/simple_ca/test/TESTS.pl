#!/usr/bin/env perl

sub syscmd 
{
	$cmd = shift;
	$err = shift;

	$res = system($cmd);
	if($res != 0)
	{
		print "ERROR: ", $err, "\n\n";
		exit $res;
	}
}

die "GLOBUS_LOCATION not set." if ( ! defined($ENV{GLOBUS_LOCATION}));

die "GPT_LOCATION not set." if ( ! defined($ENV{GLOBUS_LOCATION}));

$GL=$ENV{GLOBUS_LOCATION};
$GPT=$ENV{GPT_LOCATION};

die "Simple CA not installed." if ( ! -x "$GL/setup/globus/setup-simple-ca");

$pwd=$ENV{PWD};
$cadir="$pwd/TestCA";

open(INP, ">$pwd/test_input");
print INP "\n\n\n\n";
close(INP);

syscmd("$GL/setup/globus/setup-simple-ca -dir $cadir -passout pass:globus < test_input",
       "setup-simple-ca failed.");

# get hash
opendir(DIR, $cadir) || die "Can't opendir $cadir: $!";
@setup_files = grep { /globus_simple_ca/ && -f "$cadir/$_" } readdir(DIR);
closedir(DIR);

$setup_tarball = $setup_files[0];

($hash) = $setup_tarball =~ /globus_simple_ca_([^_]*)_/;

syscmd("$GL/setup/globus_simple_ca_${hash}_setup/setup-gsi -nonroot -default",
       "Failed to run setup-gsi");

$set_grid_sec_dir="GRID_SECURITY_DIR=$GL/etc;export GRID_SECURITY_DIR";
$set_x509_dir="X509_CERT_DIR=$GL/share/certificates;export X509_CERT_DIR";
$test_cert_dir="${pwd}/TestCert";

syscmd("${set_x509_dir}; ${set_grid_sec_dir}; $GL/bin/grid-cert-request -nopw -ca $hash -dir ${test_cert_dir}",
       "Failed to create certificate request.");

syscmd("${set_x509_dir}; $GL/bin/grid-ca-sign -dir $cadir -in $test_cert_dir/usercert_request.pem -out $test_cert_dir/usercert.pem -passin pass:globus",
       "Failed to create certificate.");

syscmd("${set_x509_dir}; $GL/bin/grid-proxy-init -verify -cert $test_cert_dir/usercert.pem -key $test_cert_dir/userkey.pem -out $test_cert_dir/proxy.pem",
       "Failed to create or verify proxy.");
 
