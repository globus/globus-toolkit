#!/usr/bin/perl 

# myproxy admin add user script

# generates a certificate request using grid-cert-request
# signs the request using grid-ca-sign
# and stores the credential in the repository using myproxy-alcf

#grid-cert-request

print "grid-cert-request:\n";
print "Enter common name of the user: ";
chop($common_name = <STDIN>);
print "Enter certificate prefix: [$common_name]:";
chop($prefix = <STDIN>);
if (length $prefix == 0) {
	$prefix = $common_name;
}
print "Temporary directory name [/tmp] : ";
chop($tmp_dir_name = <STDIN>);
if (length $tmp_dir_name == 0) {
	$tmp_dir_name = "/tmp";
}

@args = ("grid-cert-request", "-cn", $common_name, "-prefix", $prefix, "-dir", $tmp_dir_name,  "-force", "-ca");
if (system (@args) != 0) {
	die "grid-cert-request failed !! \n";
}

#grid-ca-sign
print "\ngrid-ca-sign:\n";

@args = ("grid-ca-sign", "-in", "${tmp_dir_name}/${prefix}cert_request.pem", "-out", "${tmp_dir_name}/${prefix}cert_signed_request.pem", "-force");

print @args;
if (system (@args) != 0) {
	die "grid-ca-sign failed !! \n";
}

#myproxy-alcf

print "\nmyproxy-alcf:\n\n";

print "Credential Storage Directory : ";
chop ($cred_store = <STDIN>);
if (length $cred_store > 0) {
	$cred_store_switch = "-s";
}
$cert_request_file = "${tmp_dir_name}/${prefix}cert_signed_request.pem";

print "|${cert_request_file}|";
print "CA Key file: ";
chop ($keyfile = <STDIN>);
if (length $keyfile > 0) {
	$keyfile_switch = "-y";
}

print "User name: ";
chop ($username = <STDIN>);
if (length $username > 0) {
	$username_switch = "-l";
}

print "Allow anonymous retrievers (y/n) [n]? ";
chop($inp = <STDIN>);
if ($inp eq "y") {
	$anon_retriever = '-a';
}
print $inp;
if ($anon_retriever ne '-a') {
	print "Allow anonymous renewers (y/n) [n]? ";
	chop ($inp = <STDIN>);
	if ($inp eq "y") {
		$anon_renewer = '-A';
	}
}
	
if ($anon_retriever ne '-a') {
	print "Retriever regex: ";
	chop ($ret_regex = <STDIN>);
	if (length $ret_regex > 0) {
		$ret_regex_switch = "-r";
	}
}

if ($anon_renewer ne '-A') {
	print "Renewer regex: ";
	chop ($ren_regex = <STDIN>);
	if (length $ren_regex > 0) {
		$ren_regex_switch = "-R";
	}
}

$regex_mode = "-X";
print "Regex matching mode (cn/dn) [cn]: ";
chop ($inp = <STDIN>);
if ($inp eq "dn") {
	$regex_mode = "-x";
}

print "Disable Passphrase (y/n) [n]? ";
chop ($inp = <STDIN>);
if ($inp eq "y") {
	$dis_pass = "-n";
}
	
print "Use DN as username (y/n) [n]? ";
chop ($inp = <STDIN>);
if ($inp eq "y") {
	$dn_as_user = "-d";
}

print "Credential Name : ";
chop ($credname = <STDIN>);
if (length $credname > 0) {
	$credname_switch = "-k";
}

print "Credential Description : ";
chop ($creddesc = <STDIN>);
$creddesc = "\"${creddesc}\"";   #description may have spaces. So enclose in quotes
if (length $creddesc > 0) {
	$creddesc_switch = "-K";
}

@args = ("myproxy-alcf", $cred_store_switch, $cred_store, "-C", $cert_request_file, $keyfile_switch, $keyfile, $username_switch, $username, $anon_retriever, $anon_renewer, $ret_regex_switch, $ret_regex, $ren_regex_switch, $ren_regex, $regex_mode, $dis_pass, $dn_as_user, $credname_switch, $credname, $creddesc_switch, $creddesc);

if (system(@args) != 0) {
	die "Error executing myproxy-alcf !! \n";
}

#end script
