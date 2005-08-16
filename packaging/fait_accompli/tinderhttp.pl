#!/usr/bin/perl

use strict;
use HTTP::Request::Common qw(POST);
use LWP::UserAgent;

my $url = shift;
my $file = shift;
my $rc = 0;
my $ua = new LWP::UserAgent;

my $req = POST $url,
Content_Type => 'multipart/form-data',
Content => [ data => [$file] ];

my $res = $ua->request($req);
if ($res->is_success) 
{ 
    $rc = 0;
}
else 
{ 
    $rc = 1;
    print $res->status_line;
}
exit $rc; 
