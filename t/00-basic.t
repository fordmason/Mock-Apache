#!/usr/bin/env perl -w

use strict;

use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";

use_ok('Mock::Apache')
    or die 'cannot load Mock::Apache';

my $start_time = time;

my $mock_apache = Mock::Apache->setup_server;
my $request     = $mock_apache->new_request('http://example.com/index.html');

my $server  = $request->server;
isa_ok($server, 'Apache::Server');
is($request->server, $Apache::server, '$r->server gives same as $Apache::server object');
is($server->server_hostname, 'server.example.com',           '$s->server_hostname');
is($server->server_admin,    'webmaster@server.example.com', '$s->server_admin');

cmp_ok($request->request_time, '>=', $start_time, 'request time is sane (not earlier than start of test)');
cmp_ok($request->request_time, '<=', time,        'request time is sane (not later than now)');

done_testing();

