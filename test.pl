#!/usr/bin/perl -w

# myproxy test script
# written by Jim Basney <jbasney@ncsa.uiuc.edu>

# Assumes myproxy-server running as root on the local machine if
# MYPROXY_SERVER not set.
# Requires a valid proxy credential.
# Assumes myproxy-server.config has:
#   1. accepted_credentials, authorized_retrievers, and
#      authorized_renewers matching the proxy credential
#   2. default_renewers "none"

use Expect; # if missing, install with: perl -MCPAN -e 'install Expect'
$Expect::Log_Stdout=0; # suppress output to STDOUT

#
# make sure I have a valid proxy
#
chomp($grid_proxy_info = `which grid-proxy-info 2>/dev/null`);
die "grid-proxy-info not found, stopped" if (!(-x $grid_proxy_info));
$timeleft = `$grid_proxy_info -timeleft`;
die "grid-proxy-info failed, stopped"
    if (!defined($timeleft) || $timeleft eq "");
die "proxy expired, stopped" if ($timeleft < 60);
$cert_subject = `$grid_proxy_info -subject`;
die "grid-proxy-info -subject failed, stopped"
    if (!defined($cert_subject) || $cert_subject eq "");
$cert_subject = (split(/\/CN=proxy|\/CN=limited proxy/, $cert_subject))[0];
print STDERR $cert_subject, "\n";

#
# check for the commands I want to run
#
chomp($myproxy_init = `which myproxy-init 2>/dev/null`);
die "myproxy-init not in PATH" if (!(-x $myproxy_init));
chomp($myproxy_info = `which myproxy-info 2>/dev/null`);
die "myproxy-info not in PATH" if (!(-x $myproxy_info));
chomp($myproxy_destroy = `which myproxy-destroy 2>/dev/null`);
die "myproxy-destroy not in PATH" if (!(-x $myproxy_destroy));
chomp($myproxy_get = `which myproxy-get-delegation 2>/dev/null`);
die "myproxy-get-delegation not in PATH" if (!(-x $myproxy_get));
chomp($myproxy_passwd = `which myproxy-change-pass-phrase 2>/dev/null`);
die "myproxy-change-pass-phrase not in PATH" if (!(-x $myproxy_passwd));

#
# setup environment variables
#
if (!defined($ENV{'MYPROXY_SERVER'})) {
    $ENV{'MYPROXY_SERVER'} = "localhost";
}
if (!defined($ENV{'X509_USER_PROXY'})) {
    $ENV{'X509_USER_PROXY'} = "/tmp/x509up_u$<";
}
# make proxy from existing proxy, so we don't need to deal with long-term cred
$ENV{'X509_USER_CERT'} = $ENV{'X509_USER_PROXY'};
$ENV{'X509_USER_KEY'} = $ENV{'X509_USER_PROXY'};

srand(time||$$);
$passphrase = sprintf "%010.d", int(rand(0x7fffffff));

#
# BEGIN TESTS
#
$SUCCESSES = $FAILURES = 0;

# commands to test: myproxy-init, myproxy-info, myproxy-destroy,
#                   myproxy-get-delegation, and myproxy-change-pass-phrase

print "MyProxy Test 1 (store credential with default name): ";
($exitstatus, $output) =
    &runtest("myproxy-init -v -a -c 1 -t 1",
	     $passphrase . "\n" . $passphrase . "\n");
if ($exitstatus == 0) {
    print "SUCCEDED\n"; $SUCCESSES++;
} else {
    print "FAILED\n"; $FAILURES++; print STDERR $output;
}

print "MyProxy Test 2 (get info for stored credential): ";
($exitstatus, $output) = &runtest("myproxy-info -v", undef);
if ($exitstatus == 0 && $output =~ /default credential/) {
    print "SUCCEDED\n"; $SUCCESSES++;
} else {
    print "FAILED\n"; $FAILURES++; print STDERR $output;
}

print "MyProxy Test 3 (retrieve stored credential): ";
($exitstatus, $output) =
    &runtest("myproxy-get-delegation -t 1 -o /tmp/myproxy-test.$$ -v",
	     $passphrase . "\n" . $passphrase . "\n");
if ($exitstatus == 0 && $output =~ /A proxy has been received/) {
    print "SUCCEDED\n"; $SUCCESSES++;
} else {
    print "FAILED\n"; $FAILURES++; print STDERR $output;
}

print "MyProxy Test 4 (verify passphrase checking on retrieve): ";
($exitstatus, $output) =
    &runtest("myproxy-get-delegation -t 1 -o /tmp/myproxy-test.$$ -v",
	     "badpassphrase\nbadpassphrase\n");
if ($exitstatus != 0 && $output =~ /invalid pass phrase/) {
    print "SUCCEDED\n"; $SUCCESSES++;
} else {
    print "FAILED\n"; $FAILURES++; print STDERR $output;
}

print "MyProxy Test 5 (change passphrase for credential): ";
$old_passphrase = $passphrase;
$passphrase = sprintf "%010.d", int(rand(0x7fffffff));
($exitstatus, $output) =
    &runtest("myproxy-change-pass-phrase -v",
	     "$old_passphrase\n$passphrase\n$passphrase\n");
if ($exitstatus == 0 && $output =~ /Passphrase changed/) {
    print "SUCCEDED\n"; $SUCCESSES++;
} else {
    print "FAILED\n"; $FAILURES++; print STDERR $output;
}

print "MyProxy Test 6 (verify new passphrase): ";
($exitstatus, $output) =
    &runtest("myproxy-get-delegation -t 1 -o /tmp/myproxy-test.$$ -v",
	     $passphrase . "\n" . $passphrase . "\n");
if ($exitstatus == 0 && $output =~ /A proxy has been received/) {
    print "SUCCEDED\n"; $SUCCESSES++;
} else {
    print "FAILED\n"; $FAILURES++; print STDERR $output;
}

print "MyProxy Test 7 (verify default renewal policy): ";
($exitstatus, $output) =
    &runtest("myproxy-get-delegation -a \$X509_USER_PROXY -t 1 -o /tmp/myproxy-test.$$ -v", undef);
if ($exitstatus != 0 && $output =~ /not authorized/) {
    print "SUCCEDED\n"; $SUCCESSES++;
} else {
    print "FAILED\n"; $FAILURES++; print STDERR $output;
}

print "MyProxy Test 8 (verify old passphrase fails): ";
($exitstatus, $output) =
    &runtest("myproxy-get-delegation -t 1 -o /tmp/myproxy-test.$$ -v",
	     $old_passphrase . "\n" . $old_passphrase . "\n");
if ($exitstatus != 0 && $output =~ /invalid pass phrase/) {
    print "SUCCEDED\n"; $SUCCESSES++;
} else {
    print "FAILED\n"; $FAILURES++; print STDERR $output;
}

print "MyProxy Test 9 (remove credential from repository): ";
($exitstatus, $output) =
    &runtest("myproxy-destroy -v", undef);
if ($exitstatus == 0 && $output =~ /was succesfully removed/) {
    print "SUCCEDED\n"; $SUCCESSES++;
} else {
    print "FAILED\n"; $FAILURES++; print STDERR $output;
}

print "MyProxy Test 10 (verify credentials are removed): ";
($exitstatus, $output) =
    &runtest("myproxy-info -v", undef);
if (!($output =~ /default credential/)) {
    print "SUCCEDED\n"; $SUCCESSES++;
} else {
    print "FAILED\n"; $FAILURES++; print STDERR $output;
}

print "MyProxy Test 11 (store credentials with retrieval policies): ";
($exitstatus, $output) =
    &runtest("myproxy-init -v -r 'nobody' -k 'nobody' -c 1 -t 1",
	     $passphrase . "\n" . $passphrase . "\n");
if ($exitstatus == 0) {
    ($exitstatus, $output) =
	&runtest("myproxy-init -v -r $cert_subject -k 'mine' -c 1 -t 1",
		 $passphrase . "\n" . $passphrase . "\n");
}
if ($exitstatus == 0) {
    print "SUCCEDED\n"; $SUCCESSES++;
} else {
    print "FAILED\n"; $FAILURES++; print STDERR $output;
}

print "MyProxy Test 12 (verify retrieval policies): ";
($exitstatus, $output) =
    &runtest("myproxy-get-delegation -k 'mine' -t 1 -o /tmp/myproxy-test.$$ -v",
	     $passphrase . "\n" . $passphrase . "\n");
if ($exitstatus == 0 && $output =~ /A proxy has been received/) {
    ($exitstatus, $output) =
	&runtest("myproxy-get-delegation -k 'nobody' -t 1 -o /tmp/myproxy-test.$$ -v",
		 $passphrase . "\n" . $passphrase . "\n");
}
if ($exitstatus != 0) {
    print "SUCCEDED\n"; $SUCCESSES++;
} else {
    print "FAILED\n"; $FAILURES++; print STDERR $output;
}

#
# END TESTS
#

print "MyProxy Tests Complete: ", $SUCCESSES, " tests passed, ";
print $FAILURES, " tests failed\n";
exit $FAILURES;

#
# SUBROUTINES
#

sub runtest {
    local($command, $input) = @_;
    local($ex) = Expect->new();
    $ex->raw_pty(1);
    $ex = $ex->spawn("exec $command 2>&1");
    die "failed to run $command" if (!defined($ex));
    if (defined($input)) {
	@input = split(/\n/, $input);
	while (defined($input = shift(@input))) {
	    $ex->send($input); $ex->send("\n");
	    sleep(1);
	}
    }
    $ex->expect(undef);
    $output = $ex->before();
    $ex->soft_close();
    return ($ex->exitstatus(), $output);
}
