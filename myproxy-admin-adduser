#!/usr/bin/perl 

# myproxy admin add user script
# generates a certificate request using grid-cert-request
# signs the request using grid-ca-sign
# and stores the credential in the repository using myproxy-alcf

use Env;  #module to access environment variables
Env::import(); #tie environment vars to local vars with same name

# read defaults from myproxy-adduser.config file

open ($CONFIG, '<', "${GLOBUS_LOCATION}/etc/myproxy-adduser.config") 
	or die "Cannot open config file: ${GLOBUS_LOCATION}/etc/myproxy-adduser.config for reading";

@fileinfo = stat($CONFIG);  

if (@fileinfo eq () ){
	die "Unable to stat config file ${GLOBUS_LOCATION}/etc/myproxy-adduser.config"
	}
sysread ($CONFIG, $FILE_CONT, @fileinfo[7]);

# filter out comments
$flag = 0;
for ($i = 0; $i < @fileinfo[7]; $i++) {
        $c  = substr ($FILE_CONT, $i, 1);
	if ($c eq '#')  {
		$flag = 1;
	}

	if ($flag == 0) {
		$xx = $xx . $c
	}
									        	if ($c eq "\n") {
	        $flag = 0;   #reset
        }
}  #end for

$FILE_CONT = $xx;

#search for various parameters
$str = "tmp_dir_name=";
$i = index ($FILE_CONT, $str);
if ($i != -1) {
	$end = index ($FILE_CONT, "\n", $i);
	$tmp_dir_name = substr($FILE_CONT, $i+length($str), $end-($i+length($str)));
	}

$str = "cred_store=";
$i = index ($FILE_CONT, $str);
if ($i != -1) {
	$end = index ($FILE_CONT, "\n", $i);
	$cred_store= substr($FILE_CONT, $i+length($str), $end-($i+length($str)));
	$cred_store_switch = "-s";
	}

$str = "keyfile=";
$i = index ($FILE_CONT, $str);
if ($i != -1) {
	$end = index ($FILE_CONT, "\n", $i);
	$keyfile = substr($FILE_CONT, $i+length($str), $end-($i+length($str)));
	$keyfile_switch = "-y";
	}

$str = "allow_anon_retrievers=";
$i = index ($FILE_CONT, $str);
if ($i != -1) {
	$end = index ($FILE_CONT, "\n", $i);
	$ans= substr($FILE_CONT, $i+length($str), $end-($i+length($str)));
	if ($ans eq "y") {
		$anon_retrievers = "-a";
		}
	}

$str = "allow_anon_renewers=";
$i = index ($FILE_CONT, $str);
if ($i != -1) {
	$end = index ($FILE_CONT, "\n", $i);
	$ans = substr($FILE_CONT, $i+length($str), $end-($i+length($str)));
	if ($ans eq "y") {
		if ($anon_retrievers eq "-a") {
			die "Anon_retrievers and anon_renewers cannot be simultaneously specified";
		}
		else {
			$anon_renewers = "-A";
		}
	}
}


$str = "ret_regex=";
$i = index ($FILE_CONT, $str);
if ($i != -1) {
	if ($anon_retrievers eq '-a') {
		die "Retriever regex cannot be specified with anonymous retriever option";
	}

	$end = index ($FILE_CONT, "\n", $i);
	$ret_regex= substr($FILE_CONT, $i+length($str), $end-($i+length($str)));
	$ret_regex_switch = "-r";
	}

$str = "ren_regex=";
$i = index ($FILE_CONT, $str);
if ($i != -1) {
	if ($anon_renewers eq '-a') {
		die "Renewer regex cannot be specified with anonymous renewer option";
	}

	$end = index ($FILE_CONT, "\n", $i);
	$ren_regex= substr($FILE_CONT, $i+length($str), $end-($i+length($str)));
	$ren_regex_switch = "-R";
	}

$str = "regex_mode=";
$i = index ($FILE_CONT, $str);
if ($i != -1) {
	$end = index ($FILE_CONT, "\n", $i);
	$ans = substr($FILE_CONT, $i+length($str), $end-($i+length($str)));
	if ($ans eq "dn") {
		$regex_mode = "-x";
	}
}

$str = "dis_pass=";
$i = index ($FILE_CONT, $str);
if ($i != -1) {
	$end = index ($FILE_CONT, "\n", $i);
	$ans = substr($FILE_CONT, $i+length($str), $end-($i+length($str)));
	if ($ans eq "y") {
		$dis_pass = "-n";
	}
}

$str = "dn_as_user=";
$i = index ($FILE_CONT, $str);
if ($i != -1) {
	$end = index ($FILE_CONT, "\n", $i);
	$ans= substr($FILE_CONT, $i+length($str), $end-($i+length($str)));
	if ($ans eq "y") {
		$dn_as_user = "-d";
	}
}


$str = "credname=";
$i = index ($FILE_CONT, $str);
if ($i != -1) {
	$end = index ($FILE_CONT, "\n", $i);
	$credname= substr($FILE_CONT, $i+length($str), $end-($i+length($str)));
	$credname_switch = "-k";
}

$str = "creddesc=";
$i = index ($FILE_CONT, $str);
if ($i != -1) {
	$end = index ($FILE_CONT, "\n", $i);
	$creddesc= substr($FILE_CONT, $i+length($str), $end-($i+length($str)));
	$creddesc_switch = "-K";
}

#grid-cert-request

print "grid-cert-request:\n";
print "Enter common name of the user: ";
chop($common_name = <STDIN>);

$prefix="myproxy_adduser_";

@args = ("grid-cert-request", "-cn", $common_name, "-prefix", $prefix, "-dir", $tmp_dir_name,  "-force", "-ca");

if (system (@args) != 0) {
	die "grid-cert-request failed !! \n";
}

#grid-ca-sign
print "\ngrid-ca-sign:\n";

@args = ("grid-ca-sign", "-in", "${tmp_dir_name}/${prefix}cert_request.pem", "-out", "${tmp_dir_name}/${prefix}cert_signed_request.pem", "-force");

if (system (@args) != 0) {
	die "grid-ca-sign failed !! \n";
}

#myproxy-alcf

print "\nmyproxy-alcf:\n\n";

$cert_request_file = "${tmp_dir_name}/${prefix}cert_signed_request.pem";

print "User name: ";
chop ($username = <STDIN>);
if (length $username > 0) {
	$username_switch = "-l";
}

@args = ("myproxy-alcf", $cred_store_switch, $cred_store, "-C", $cert_request_file, $keyfile_switch, $keyfile, $username_switch, $username, $anon_retriever, $anon_renewer, $ret_regex_switch, $ret_regex, $ren_regex_switch, $ren_regex, $regex_mode, $dis_pass, $dn_as_user, $credname_switch, $credname, $creddesc_switch, $creddesc);

if (system(@args) != 0) {
	die "Error executing myproxy-alcf !! \n";
}

#end script
