#!/usr/bin/perl

# admin_add_user_config.pl

# Generates configuration file for use by admin_add_user.pl script
# Configuration file: $GLOBUS_LOCATION/etc/myproxy-adduser.config

use Env;  #module to access environment variables
Env::import(); #tie environment vars to local vars with same name

open ($CONFIG, '>', "${GLOBUS_LOCATION}/etc/myproxy-adduser.config")
        or die "Cannot open config file: ${GLOBUS_LOCATION}/etc/myproxy-adduser.config for writing";

syswrite ($CONFIG, "#myproxy-adduser.config\n\n");
syswrite ($CONFIG, "#configuration file for admin_add_user.pl script\n");
syswrite ($CONFIG, "#created by admin_add_user_config.pl script\n\n");
syswrite ($CONFIG, "#Feel free to modify the contents\n\n");

#grid-cert-request options

print "Temporary directory name [/tmp] : ";
chop($tmp_dir_name = <STDIN>);
if (length $tmp_dir_name == 0) {
        $tmp_dir_name = "/tmp";
}
syswrite ($CONFIG, "#temporary directory\n");
syswrite ($CONFIG, "tmp_dir_name=${tmp_dir_name}\n\n");

#myproxy-admin-load-credential options	
print "Credential Storage Directory : ";
chop ($cred_store = <STDIN>);
if (length $cred_store > 0) {
	syswrite ($CONFIG, "#credential store directory\n");
	syswrite ($CONFIG, "cred_store=${cred_store}\n\n");
}

print "CA Key file: ";
chop ($keyfile = <STDIN>);
if (length $keyfile > 0) {
	syswrite ($CONFIG, "#CA key file\n");
	syswrite ($CONFIG, "keyfile=${keyfile}\n\n");
}

print "Allow anonymous retrievers (y/n) [n]? ";
print "Note: Both anonymous retrievers and anonymous renewers are not simultaneosly allowed\n";

syswrite ($CONFIG, "#Both anonymous retrievers and anonymous renewers are not simultaneously allowed\n");
syswrite ($CONFIG, "#Allow anonymous retrievers [y/n] ?\n");
chop($inp = <STDIN>);
if ($inp eq "y") {
	syswrite ($CONFIG, "allow_anon_retrievers=y\n\n");
}
else {
	syswrite ($CONFIG, "allow_anon_retrievers=n\n\n");
}

print $inp;

# anonymous renewers can be allowed only when anonymous 
# retrievers are not allowed
if ($anon_retrievers ne '-a') {
	print "Allow anonymous renewers (y/n) [n]? ";
	syswrite ($CONFIG, "#Allow anonymous renewers [y/n] ?\n");
	chop ($inp = <STDIN>);
	if ($inp eq "y") {
		syswrite ($CONFIG, "allow_anon_renewers=y\n\n");
	}
	else {
		syswrite ($CONFIG, "allow_anon_renewers=n\n\n");
	}
}

# if anonymous retrievers not allowed then accept retriever regex

syswrite ($CONFIG, "# Retriever regular expression (can be specified only when anonymous retrievers\n# are not allowed)\n");
if ($anon_retrievers ne '-a') {
	print "Retriever regex: ";
	chop ($ret_regex = <STDIN>);
	if (length $ret_regex > 0) {
		syswrite ($CONFIG, "ret_regex=${ret_regex}\n\n");
	}
	else {
		syswrite ($CONFIG, "#ret_regex=\n\n");
	}
}

# if anonymous renewers not allowed then accept renewer regex
syswrite ($CONFIG, "# Renewer regular expression (can be specified only when anonymous renewers\n# are not allowed retriever regex is not specified)\n");
if ($anon_renewers ne '-A') {
	print "Renewer regex: ";
	chop ($ren_regex = <STDIN>);
	if (length $ren_regex > 0) {
		syswrite ($CONFIG, "ren_regex=${ren_regex}\n\n");
	}
	else {
		syswrite ($CONFIG, "#ren_regex=\n\n");
	}
}

print "Regex matching mode (cn/dn) [cn]: ";
syswrite ($CONFIG, "# Regular expression mode [cn/dn]  (common name or distinguished name)\n");
chop ($inp = <STDIN>);
if ($inp eq "dn") {
	syswrite($CONFIG, "regex_mode=dn\n\n");
}
else {
	syswrite($CONFIG, "regex_mode=cn\n\n");
}

print "Disable Passphrase (y/n) [n]? ";
syswrite ($CONFIG, "# Disable passphrase [y/n] ?\n");
chop ($inp = <STDIN>);
if ($inp eq "y") {
	syswrite ($CONFIG, "dis_pass=y\n\n");
}
else {
	syswrite ($CONFIG, "dis_pass=n\n\n");
}
	
print "Use DN as username (y/n) [n]? ";
syswrite($CONFIG, "# Use DN as username [y/n] ?\n");
chop ($inp = <STDIN>);
if ($inp eq "y") {
	syswrite ($CONFIG, "dn_as_user=y\n\n");
}
else {
	syswrite ($CONFIG, "dn_as_user=n\n\n");
}

syswrite($CONFIG, "# Credential name\n");
print "Credential Name : ";
chop ($credname = <STDIN>);
if (length $credname > 0) {
	syswrite($CONFIG, "credname=${credname}\n\n");
}
else {
	syswrite($CONFIG, "#credname=\n\n");
}

syswrite($CONFIG, "# Credential description\n");
print "Credential Description : ";
chop ($creddesc = <STDIN>);
if (length $creddesc > 0) {
	syswrite($CONFIG, "creddesc=${creddesc}\n\n");
}
else {
	syswrite($CONFIG, "#creddesc=\n\n");
}

syswrite($CONFIG, "# end configuration file\n");

#end script
		    
