# Mock::Apache - a package to mock the mod_perl 1.x environment
#

# Method descriptions are taken from my book: "Mod_perl Pocket Reference",
# Andrew Ford, O'Reilly & Associates, 2001, 0-596-00047-2.  Page references,
# marked MPPR pNN, refer to the book.
#
# Copyright (C) 2013, Andrew Ford.  All rights reserved.
# This library is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Mock::Apache;

use strict;

use Apache::ConfigParser;
use Capture::Tiny qw(capture_stdout);
use Carp;
use HTTP::Headers;
use HTTP::Response;
use Module::Loaded;
use Readonly;

use parent 'Class::Accessor';

__PACKAGE__->mk_accessors(qw(server));

our $VERSION = "0.05";
our $DEBUG;

BEGIN {

    Readonly our @APACHE_CLASSES
	=> qw( Apache  Apache::SubRequest  Apache::Server  Apache::Connection
               Apache::Log  Apache::Table  Apache::URI  Apache::Util
               Apache::Constants  Apache::ModuleConfig  Apache::Symbol
	       Apache::Request  Apache::Upload  Apache::Cookie );


    # Lie about the following modules being loaded
    mark_as_loaded($_)
        for @APACHE_CLASSES;

    # alias the DEBUG() function into each class
    sub DEBUG {
	my ($message, @args) = @_;

	return unless $Mock::Apache::DEBUG;
	$message .= "\n" unless $message =~ qr{\n$};
	printf STDERR "DEBUG: $message", @args;
	if ($DEBUG > 1) {
	    my ($package, $file, $line, $subr) = ((caller(1))[0..2], (caller(2))[3]);
	    if ($file eq __FILE__) {
		($package, $file, $line, $subr) = ((caller(2))[0..2], (caller(3))[3]);
	    }
	    print STDERR "       from $subr at line $line of $file\n";
	}

	return;
    }

    sub NYI_DEBUG {
	my ($message, @args) = @_;

	$message .= "\n" unless $message =~ qr{\n$};
	printf STDERR "DEBUG: $message", @args;
	if ($DEBUG > 1) {
	    my ($package, $file, $line, $subr) = ((caller(1))[0..2], (caller(2))[3]);
	    if ($file eq __FILE__) {
		($package, $file, $line, $subr) = ((caller(2))[0..2], (caller(3))[3]);
	    }
	    print STDERR "       from $subr at line $line of $file\n";
	}
	$DB::single = 1;
	croak((caller)[3] . " - NOT YET IMPLEMENTED");
    }

    no strict 'refs';
    *{"${_}::DEBUG"} = \&DEBUG for @APACHE_CLASSES;
    *{"${_}::NYI_DEBUG"} = \&NYI_DEBUG for @APACHE_CLASSES;
}

Readonly our $DEFAULT_HOSTNAME => 'server.example.com';
Readonly our $DEFAULT_ADDR     => '22.22.22.22';
Readonly our $DEFAULT_ADMIN    => 'webmaster';

# Default locations (RedHat-inspired)

Readonly our $DEFAULT_SERVER_ROOT   => '/etc/httpd';
Readonly our $DEFAULT_DOCUMENT_ROOT => '/var/www/html';

# I am still playing with the API to Mock::Apache.
# I envisage having methods to:
#   * set up the mock server
#   * run a request through the server
#   * create an apache request object




# Set up a mock Apache server

sub setup_server {
    my ($class, %params) = @_;

    my $cfg = Apache::ConfigParser->new;

    if (my $config_file = $params{config_file}) {
        $cfg->parse_file($config_file);
    }

    $DEBUG = delete $params{DEBUG};

    $params{document_root}   ||= _get_config_value($cfg, 'DocumentRoot', $DEFAULT_DOCUMENT_ROOT);
    $params{server_root}     ||= _get_config_value($cfg, 'ServerRoot',   $DEFAULT_SERVER_ROOT);
    $params{server_hostname} ||= $DEFAULT_HOSTNAME;
    $params{server_port}     ||= 80;
    $params{server_admin}    ||= _get_config_value($cfg, 'ServerAdmin', 
                                                   $DEFAULT_ADMIN . '@' . $params{server_hostname});
    $params{gid}             ||= getgrnam('apache') || 48;
    $params{uid}             ||= getpwnam('apache') || 48;


    my $self = bless { %params }, $class;

    $self->{server} = $Apache::server = Apache::Server->new($self, %params);

    return $self;
}

sub _get_config_value {
    my ($config, $directive, $default) = @_;

    if ($config and my @dirs = $config->find_down_directive_names($directive)) {
        return $dirs[0]->value;
    }
    return $default;
}

sub mock_client {
    my ($self, %params) = @_;

    return Mock::Apache::RemoteClient->new(%params, mock_apache => $self);
}




# $mock_apache->execute_handler($handler, $request)
# $mock_apache->execute_handler($handler, $client, $request)

sub execute_handler {
    my ($self, $handler, $client) = (shift, shift, shift);

    my $request;
    if (ref $client and $client->isa('Apache')) {
        $request = $client;
        $client  = $client->_mock_client;
    }
    croak "no mock client specified"
        unless ref $client and $client->isa('Mock::Apache::RemoteClient');

    if (!ref $handler) {
        no strict 'refs';
        $handler = \&{$handler};
    }

    $request ||= $client->new_request(@_);

    my $saved_debug = $Mock::Apache::DEBUG;
    local $Mock::Apache::DEBUG = 0;

    local($ENV{REMOTE_ADDR}) = $request->subprocess_env('REMOTE_ADDR');
    local($ENV{REMOTE_HOST}) = $request->subprocess_env('REMOTE_HOST');

    local $Apache::request = $request;

    my $rc = eval {
	local $Mock::Apache::DEBUG = $saved_debug;
	$handler->($request);
    };
    $request->status_line('500 Internal server error')
	if $@;

    my $status  = $request->status;
    (my $message = $request->status_line || '') =~ s/^... //;
    my $headers = HTTP::Headers->new;
    while (my($field, $value) = each %{$request->headers_out}) {
        $headers->push_header($field, $value);
    }
    my $output = $request->_output;

    return HTTP::Response->new( $status, $message, $headers, $output );
}

##############################################################################
#
# Package to model a remote client

package
    Mock::Apache::RemoteClient;

use Readonly;
use Scalar::Util qw(weaken);

use parent qw(Mock::Apache);

Readonly my @PARAMS    => qw(mock_apache REMOTE_ADDR REMOTE_HOST REMOTE_USER);
Readonly my @ACCESSORS => ( map { lc $_ } @PARAMS );

__PACKAGE__->mk_ro_accessors(@ACCESSORS, 'connection');

sub new {
    my ($class, %params) = @_;

    $params{REMOTE_ADDR} ||= '10.0.0.10';
    $params{REMOTE_HOST} ||= 'remote.example.com';

    my $attrs = { map { ( lc $_ => $params{$_} ) } @PARAMS };
    my $self  = $class->SUPER::new($attrs);

    weaken($self->{mock_apache});

    $self->{connection} ||= Apache::Connection->new($self);

    return $self;
}

sub new_request {
    my $self = shift;

    return  Apache->_new_request($self, @_);
}


##############################################################################

package                 # hide from PAUSE indexer
    Apache;

use Carp;
use HTTP::Request;
use Readonly;
use Scalar::Util qw(weaken);
use URI;
use URI::QueryParam;

use parent qw(Class::Accessor);

__PACKAGE__->mk_ro_accessors(qw( log
				 _env
				 _uri
				 _mock_client
				 _output
			      ));

our $server;
our $request;

# Create a new Apache request
# Apache->_new_request($mock_client, @params)

sub _new_request {
    my $class = shift;
    my $mock_client = shift;

    # Set up environment for later - %ENV entries will be localized

    my $env = { GATEWAY_INTERFACE => 'CGI-Perl/1.1',
                MOD_PERL          => '1.3',
                SERVER_SOFTWARE   => 'Apache emulation (Mock::Apache)',
                REMOTE_ADDR       => $mock_client->remote_addr,
                REMOTE_HOST       => $mock_client->remote_host };

    my $r = $class->SUPER::new( { request_time   => time,
                                  is_initial_req => 1,
                                  is_main        => 1,
                                  server         => $mock_client->mock_apache->server,
                                  connection     => $mock_client->connection,
                                  _mock_client   => $mock_client,
                                  _env           => $env,
                                } );

    local $Mock::Apache::DEBUG = 0;

    $r->{log}           ||= $r->{server}->log;
    $r->{notes}           = Apache::Table->new($r);
    $r->{pnotes}          = Apache::Table->new($r, 1);
    $r->{headers_in}      = Apache::Table->new($r);
    $r->{headers_out}     = Apache::Table->new($r);
    $r->{err_headers_out} = Apache::Table->new($r);
    $r->{subprocess_env}  = Apache::Table->new($r);

    $request = $r;
    $server  = $r->{server};

    # Having set up a skeletal request object, see about fleshing out the detail

    my $initializer = (@_ == 1) ? shift : HTTP::Request->new(@_);
    croak('request initializer must be an HTTP:Request object')
        unless $initializer->isa('HTTP::Request');
    $r->_initialize_from_http_request_object($initializer);


    # Expand the environment with information from server object

    $env->{DOCUMENT_ROOT} ||= $r->document_root;
    $env->{SERVER_ADMIN}  ||= $server->server_admin;
    $env->{SERVER_NAME}   ||= $server->server_hostname;
    $env->{SERVER_PORT}   ||= $r->get_server_port;

    # TODO: AUTH_TYPE, CONTENT_LENGTH, CONTENT_TYPE, PATH_INFO,
    # PATH_TRANSLATED, QUERY_STRING, REMOTE_IDENT, REMOTE_USER,
    # REQUEST_METHOD, SCRIPT_NAME, SERVER_PROTOCOL, UNIQUE_ID

    while (my($key, $val) = each %$env) {
        $r->{subprocess_env}->set($key, $val);
    }

    return $r;
}

sub _initialize_from_http_request_object {
    my ($r, $http_req) = @_;

#    $DB::single=1;

    my $uri = $http_req->uri;
    $uri = URI->new($uri) unless ref $uri;

    $r->{method}   = $http_req->method;
    $r->{_uri}     = $uri;
    ($r->{uri}     = $uri->path) =~ s{^/}{};
    $r->{protocol} = 'HTTP/1.1';
    $r->{content}  = $http_req->content;

    $http_req->headers->scan( sub {
                                  my ($key, $value) = @_;
                                  $r->headers_in->set($key, $value);
                                  (my $header_env = "HTTP_$key") =~ s/-/_/g;
                                  $r->{subprocess_env}->set($header_env, $value);
                              } );

    return;
}

################################################################################
#
# The Request Object                                                    MPPR p23
#
# Handlers are called with a reference to the current request object (Apache),
# which by convention is named $r.

# $r = Apache->request([$r])                                            MPPR p23
# Returns a reference to the request object.  Perl handlers are called with a
# reference to the request object as the first argument.
sub request {
    DEBUG('Apache->request => ' . $request);
    return $request
}

# $bool = $r->is_initial_req                                            MPPR p23
# Returns true if the current request is the initial request, and false if it is
# a subrequest or an internal redirect.
sub is_initial_req {
    my ($r) = @_;
    my $bool = $r->{is_initial_req};
    DEBUG('$r->is_initial_req => %s', $bool ? 'true' : 'false');
    return $bool;
}

# $bool = $r->is_main                                                   MPPR p23
# Returns true if the current request is the initial request or an internal
# redirect, and false if it is a subrequest.
sub is_main {
    my ($r) = @_;
    my $bool = $r->{is_main};
    DEBUG('$r->is_main => %s', $bool ? 'true' : 'false');
    return $bool;
}

# $req = $r->last                                                       MPPR p24
# Returns a reference to the last request object in the chain.  When used in a 
# logging handler, this is the request object that generated the final result.
sub last {
    my ($r) = @_;
    my $req = undef;
    DEBUG('$r->last => %s', ref $req ? $req : 'undef');
    return $req;
}

# $req = $r->main                                                       MPPR p24
# Returns a reference to the main (intitial) request object, or undef if $r is
# the main request obeject.
sub main {
    my ($r) = @_;
    my $req = $r->{main};
    DEBUG('$r->main => %s', ref $req ? $req : 'undef');
    return $req;
}

# $req = $r->next                                                       MPPR p24
# Returns a reference to the next request object in the chain.
sub next {
    my ($r) = @_;
    my $req = undef;
    DEBUG('$r->next => %s', ref $req ? $req : 'undef');
    return $req;
}

# $req = $r->prev                                                       MPPR p24
# Returns a reference to the previous request object in the chain.  When used in
# an error handler, this is the request that triggered the error.
sub prev {
    my ($r) = @_;
    my $req = undef;
    DEBUG('$r->prev => %s', ref $req ? $req : 'undef');
    return $req;
}


################################################################################
#
# The Apache::SubRequest Class                                          MPPR p24
#
# The Apache::SubRequest Class is a subclass of Apache and inherits its methods.

# $subr = $r->lookup_file($filename)                                    MPPR p24
# Fetches a subrequest object by filename.
sub lookup_file {
    my ($r, $file) = @_;

    $DB::single=1;
    return $r->new( uri            => $file,
                    is_initial_req => 0 );
}

# $subr = $r->lookup_uri($uri)                                          MPPR p24
# Fetches a subrequest object by URI.
sub lookup_uri {
    my ($r, $uri) = @_;

    $DB::single=1;
    return $r->new( uri            => $uri,
                    is_initial_req => 0 );
}


# $subr->run                                                            MPPR p24
# Invokes the subrequest's content handler and the returns the content handler's
# status code.
{
    package
        Apache::SubRequest;

    our @ISA = qw(Apache);
    sub run {
	my ($r) = @_;
	NYI_DEBUG('$r->run');
    }
}


################################################################################
#
# Client request methods                                                MPPR p24

# {$str|@arr} = $r->args                                                MPPR p24
# FIXME: query_form_hash does not return the right data if keys are repeated
sub args {
    my $r = shift;
    DEBUG('$r->args => %s', wantarray ? '( @list )' : $r->_uri->query);
    return wantarray ? $r->_uri->query_form_hash : $r->_uri->query;
}

# $c = $r->connection                                                   MPPR p25
sub connection {
    my ($r) = @_;
    my $connection = $r->{connection};
    DEBUG('$r->connection => %s', ref $connection ? $connection : 'undef');
    return $connection;
}

# {$str|@arr} = $r->content                                             MPPR p25
sub content {
    my ($r) = @_;
    my $content = $r->{content};
    DEBUG('$r->content => %s',
	  wantarray ? '( \'' . substr($content, 0, 20) . '...\'' : substr($content, 0, 20) . '...');
    return wantarray ? split(qr{\n}, $content) : $content;

}

# $str = $r->filename([$newfilename])                                   MPPR p25
sub filename {
    my ($r, $newfilename) = @_;
    my $filename = $r->{filename};
    DEBUG('$r->filename(%s) => %s', @_ > 1 ? "'$newfilename'" : '', $filename);
    $r->{filename} = $newfilename if @_ > 1;
    return $filename;
}

# $handle = $r->finfo()                                                 MPPR p25
sub finfo {
    my ($r) = @_;
    NYI_DEBUG('$r->finfo');
}

# $str = $r->get_remote_host([$lookup_type])                            MPPR p25
# FIXME: emulate lookups properly
sub get_remote_host {
    my ($r, $type) = @_;
    DEBUG('$r->get_remote_host(%s)', $type);
    if (@_ == 0 or $type == $Apache::Constant::REMOTE_HOST) {
        return $r->_mock_client->remote_host;
    }
    elsif ($type == $Apache::Constant::REMOTE_ADDR) {
        return $r->_mock_client->remote_addr;
    }
    elsif ($type == $Apache::Constant::REMOTE_NOLOOKUP) {
        return $r->_mock_client->remote_addr;
    }
    elsif ($type == $Apache::Constant::REMOTE_DOUBLE_REV) {
        return $r->_mock_client->remote_addr;
    }
    else {
        croak "unknown lookup type";
    }
}

# $str = $r->get_remote_logname                                        MPPR p26
sub get_remote_logname {
    my ($r) = @_;
    NYI_DEBUG('$r->get_remote_logname');
}

# $str = $r->header_in($key[, $value])                                  MPPR p26
# $str = $r->header_out($key[, $value])                                 MPPR p26
# $str = $r->err_header_out($key[, $value])                             MPPR p26
sub header_in       { shift->{headers_in}->_get_or_set(@_); }
sub header_out      { shift->{headers_out}->_get_or_set(@_); }
sub err_header_out  { shift->{err_headers_out}->_get_or_set(@_); }

# {$href|%hash} = $r->headers_in                                        MPPR p26
# {$href|%hash} = $r->headers_out                                       MPPR p26
# {$href|%hash} = $r->err_headers_out                                   MPPR p26
sub headers_in      { shift->{headers_in}->_hash_or_list; }
sub headers_out     { shift->{headers_out}->_hash_or_list; }
sub err_headers_out { shift->{err_headers_out}->_hash_or_list; }


# $bool = $r->header_only                                               MPPR p26
sub header_only {
    my $r = shift;
    my $bool = $r->{method} eq 'HEAD';
    DEBUG('$r->header_only => %s', $bool ? 'true' : 'false');
    return $bool;
}

# $str = $r->method([$newval])                                          MPPR p26
# FIXME: method should be settable
sub method {
    my ($r, $newval) = @_;
    my $val = $r->{method};
    DEBUG('\$r->(\'%s\') => \'%s\'', $newval, $val);
    if (@_ > 1) {
        $r->{method} = $newval;
    }
    return $val;
}

# $num = $r->method_number([$newval])                                   MPPR p26
# FIXME: deal with newval (need to update method)
sub method_number {
    my ($r, $newval) = @_;
    my $method = eval '&Apache::Constants::M_' . $_[0]->{method};
    DEBUG('$r->method_number(%s) => %d', @_ > 1 ? $newval : '', $method);
    return $method;
}

# $str = $r->parsed_uri                                                 MPPR p26
sub parsed_uri {
    my ($r) = @_;
    my $uri = $r->{_uri};
    DEBUG('$r->parsed_uri => %s', ref $uri ? $uri : 'undef');
    return $uri;
}

# $str = $r->path_info([$newval])                                       MPPR p26
sub path_info {
    my ($r) = @_;
    my $str = $r->{_uri}->path_info;
    DEBUG('$r->path_info => \'%s\'', $str);
    return $str;
}

# $str = $r->protocol                                                   MPPR p26
sub protocol {
    my ($r) = @_;
    my $str = $r->{protocol};
    DEBUG('$r->protocol => \'%s\'', $str);
    return $str;
}

# $str = $r->the_request                                                MPPR p26
sub the_request {
    my ($r) = @_;
    my $str = eval {
	local $Mock::Apache::DEBUG = 0;
	sprintf("%s %s %s", $r->method, $r->{_uri}, $r->protocol);
    };
    DEBUG('$r->the_request => \'%s\'', $str);
    return $str;
}

# $str = $r->uri([$newuri])                                             MPPR p27
sub uri {
    my ($r, $newuri) = @_;
    my $uri = $r->{uri};
    DEBUG('$r->uri(%s) => %s', @_ > 1 ? "'$newuri'" : '', $uri);
    $r->{uri} = $newuri if @_ > 1;
    return $uri;
}


################################################################################
#
# Server Response Methods                                              MPPR p27

# $str = $r->cgi_header_out                                            MPPR p28
sub cgi_header_out {
    NYI_DEBUG('$r->cgi_header_out');
}

# $str = $r->content_encoding([$newval])                               MPPR p28
sub content_encoding {
    my ($r, $newval) = @_;
    my $encoding = $r->{content_encoding};
    DEBUG('$r->content_encoding(%s) => \'%s\'', @_ > 1 ? "'$newval'" : '', $encoding);
    $r->{content_encoding} = $newval if @_ > 1;
    return $encoding;
}

sub content_languages {
    NYI_DEBUG('$r->content_languages');
}

# $str = $r->content_type([$newval])                                   MPPR p28
sub content_type {
    my ($r, $newval) = @_;
    my $content_type = $r->{content_type};
    DEBUG('$r->content_type(%s) => \'%s\'', @_ > 1 ? "'$newval'" : '', $content_type);
    $r->{content_type} = $newval if @_ > 1;
    return $content_type;
}


# $num = $r->request_time                                              MPPR p29
# Returns the time at which the request started as a Unix time value.
sub request_time {
    my ($r) = @_;
    my $num = $r->{request_time};
    DEBUG('$r->request_time => %d', $num);
    return $num;
}

# $num = $r->status([$newval])                                         MPPR p29
# Gets or sets the status code of the outgoing response.  Symbolic names for
# all standard status codes are provided by the Apache::Constants module.
sub status   {
    my ($r, $newval) = @_;
    my $status = $r->{status};
    DEBUG('$r->status(%s) => %d', @_ > 1 ? "$newval" : '', $status);
    $r->{status} = $r->{status_line} = $newval if @_ > 1;
    return $status;
}

# $str = $r->status_line([$newstr])                                    MPPR p29
sub status_line   {
    my ($r, $newval) = @_;
    my $status_line = $r->{status_line};
    DEBUG('$r->status_line(%s) => %d', @_ > 1 ? "$newval" : '', $status_line);
    if (@_) {
        if (($r->{status_line} = $status_line) =~ m{^(\d\d\d)}x) {
            $r->status($1);
        }
    }
    return $status_line;
}


# FIXME: need better implementation of print
sub print {
    my ($r, @list) = @_;
    foreach my $item (@list) {
        $r->{content} .= ref $item eq 'SCALAR' ? $$item : $item;
    }
    return;
}

# {$str|$href} = $r->notes([$key[,$val]])                               MPPR p31
# with no arguments returns a reference to the notes table
# otherwise gets or sets the named note
sub notes {
    my $r = shift;
    my $notes = $r->{notes};
    return @_ ? $notes->_get_or_set(@_) : $notes->_hash_or_list;
}

# {$str|$href} = $r->pnotes([$key[,$val]])                              MPPR p31
# with no arguments returns a reference to the pnotes table
# otherwise gets or sets the named pnote
sub pnotes {
    my $r = shift;
    my $pnotes = $r->{pnotes};
    return @_ ? $pnotes->_get_or_set(@_) : $pnotes->_hash_or_list;
}

# $str = $r->document_root                                              MPPR p32
sub document_root {
    my $r = shift;
    my $str = $r->{server}->{document_root};
    DEBUG('$r->document_root => \'%s\'', $str);
    return $str;
}

# $num = $r->server_port                                                MPPR p33
sub get_server_port {
    my $r = shift;
    my $port = $r->{server}->{server_port};
    DEBUG('$r->server_port => \'%d\'', $port);
    return $port;
}

# $s = $r->server                                                       MPPR p38
# $s = Apache->server
sub server  {
    my $self = shift;
    DEBUG('%s->server => ' . $server, ref $self ? '$r' : 'Apache');
    return $server;
}

sub subprocess_env {
    my $r = shift;
    my $subprocess_env = $r->{subprocess_env};

    if (@_) {
        $subprocess_env->_get_or_set(@_);
    }
    elsif (defined wantarray) {
        return $subprocess_env->_hash_or_list;
    }
    else {
        $r->{subprocess_env} = Apache::Table->new($r);

        while (my($key, $val) = each %{$r->{_env}}) {
            $r->{subprocess_env}->set($key, $val);
        }
        return;
    }
}


sub dir_config {
    my ($r) = @_;
    NYI_DEBUG('$r->dir_config');
}





package
    Apache::STDOUT;




################################################################################
#
# The Apache::Server Class                                              MPPR p38

package
    Apache::Server;

use parent 'Class::Accessor';


__PACKAGE__->mk_ro_accessors(qw(_mock_apache uid gid log));

sub new {
    my ($class, $mock_apache, %params) = @_;
    $params{log} = Apache::Log->new();
    $params{_mock_apache} = $mock_apache;
    return $class->SUPER::new(\%params);
}

# $num = $s->gid                                                        MPPR p38
# Returns the numeric group ID under which the server answers requests.  This is
# the value of the Apache "Group" directive.
sub gid {
    my $s = shift;
    my $gid = $s->{gid};
    DEBUG('$s->gid => %d', $gid);
    return $gid;
}

# $num = $s->port                                                       MPPR p39
# Returns the port number on which this server listens.
sub port {
    my $s = shift;
    my $port = $s->{port};
    DEBUG('$s->port => %d', $port);
    return $port;
}

# $str = $s->server_hostname                                            MPPR p39
sub server_hostname {
    my $s = shift;
    my $hostname = $s->{server_hostname};
    DEBUG('$s->server_hostname => \'%s\'', $hostname);
    return $hostname;
}

# $str = $s->server_admin                                               MPPR p39
sub server_admin {
    my $s = shift;
    my $admin = $s->{server_admin};
    DEBUG('$s->server_admin => \'%s\'', $admin);
    return $admin;
}


sub names {
    my $self = shift;
    return @{$self->{names} || []};
}

# $num = $s->uid                                                        MPPR p39
# Returns the numeric user ID under which the server answers requests.  This is
# the value of the Apache "User" directive.
sub uid {
    my $s = shift;
    my $uid = $s->{uid};
    DEBUG('$s->uid => %d', $uid);
    return $uid;
}

# is_virtual
# log
# log_error
# loglevel
# names
# next
# port
# timeout
# warn


################################################################################
#
# The Apache Connection Class                                           MPPR p39

package
    Apache::Connection;

use Scalar::Util qw(weaken);
use parent qw(Class::Accessor);

__PACKAGE__->mk_ro_accessors(qr(_mock_client));

sub new {
    my ($class, $mock_client) = @_;
    my $self = bless { _mock_client => $mock_client }, $class;
    weaken $self->{_mock_client};
    return $self;
}

sub aborted { return $_[0]->{_aborted} }
sub auth_type {
    NYI_DEBUG('$c->auth_type');
}

sub fileno {
    NYI_DEBUG('$c->fileno');
}

sub local_addr {
    NYI_DEBUG('$c->local_addr');
}

sub remote_addr {
    NYI_DEBUG('$c->remote_addr');
}

sub remote_host { $_->_mock_client->remote_host; }
sub remote_ip   { $_->_mock_client->remote_addr; }

sub remote_logname {
    NYI_DEBUG('$c->remote_logname');
    return;
}
sub user {
    NYI_DEBUG('$c->remote_user');
    return;
}

##############################################################################
#
# Logging and the Apache::Log Class                                   MPPR p34

package
    Apache::Log;

use Log::Log4perl;

sub new {
    my ($class, %params) = @_;
    return bless \%params, $class;
}

sub log_error {}
sub log_reason {}

sub warn {
    my $r = shift;
    print STDERR "WARN: ", @_, "\n";
}

sub emerg {
    my $r = shift;
    print STDERR "EMERG: ", @_, "\n";
}

sub alert {
    my $r = shift;
    print STDERR "ALERT: ", @_, "\n";
}

sub error {
    my $r = shift;
    print STDERR "ERROR: ", @_, "\n";
}

sub notice {
    my $r = shift;
    print STDERR "NOTICE: ", @_, "\n";
}

sub info {
    my $r = shift;
    print STDERR "INFO: ", @_, "\n";
}

sub debug {
    my $r = shift;
    print STDERR "DEBUG: ", @_, "\n";
}


##############################################################################
#
# The Apache::Table Class                                             MPPR p40

package
    Apache::Table;

use Apache::FakeTable;
#use Storable qw(freeze thaw);
use YAML::Syck;
use parent 'Apache::FakeTable';

sub new {
    my ($class, $r, $allow_refs) = @_;

    my $self = $class->SUPER::new($r);
    $self->{allow_refs} = !!$allow_refs;
    return $self;
}

sub _hash_or_list {
    my ($self) = @_;

    my $method_name = (caller(1))[3];
    DEBUG("\$r->$method_name(%s) => %s",
	  wantarray ? 'list' : $self);

    if (wantarray) {
        my @values;
        while (my ($key, $value) = each %$self) {
            push @values, $key, $value;
        }
        return @values;
    }
    else {
        return $self;
    }
}


sub _get_or_set {
    my ($self, $key, @new_values) = @_;

    my $method_name = (caller(1))[3];
    my @old_values = $self->get($key);
    if (@old_values and $self->{allow_refs}) {
	local $YAML::Syck::LoadBlessed = 1;

	@old_values = (map { ( Load($_) ) } @old_values);
    }
    DEBUG("\$r->$method_name('%s'%s) => %s", $key,
	  @new_values ? join(',', '', @new_values) : '',
	  @old_values ? join(',', @old_values) : '');
    if (@new_values) {
	if ($self->{allow_refs}) {
	    @new_values = map { ( Dump($_) ) } @new_values;
	}
        $self->set($key, @new_values);
    }
    return unless defined wantarray;
    return wantarray ? @old_values : $old_values[0];
}


##############################################################################
#
# The Apache::URI Class                                               MPPR p41
package
    Apache::URI;

use strict;
use URI;

our @ISA = qw(URI);

sub parse {
    my ($r, $string_uri) = @_;
    DEBUG('$r->parse(%s)', $string_uri);
    $DB::single=1;
    croak("not yet implemented");
    return;
}

##############################################################################
#
# The Apache::Util Class                                              MPPR p43

package
    Apache::Util;

sub escape_html {
    my ($html) = @_;
    my $out = $html;
    $out =~ s/&/&amp;/g;
    $out =~ s/</&lt;/g;
    $out =~ s/>/&gt;/g;
    $out =~ s/"/&quot;/g;
    DEBUG('Apache::Util::escape_html(\'%s\') => \'%s\'', $html, $out);
    return $out;
}

sub escape_uri {
    NYI_DEBUG('escape_uri');
}
sub ht_time {
    NYI_DEBUG('ht_time');
}
sub parsedate {
    NYI_DEBUG('parsedate');
}
sub size_string {
    NYI_DEBUG('size_string');
}
sub unescape_uri {
    NYI_DEBUG('unescape_uri');
}
sub unescape_uri_info {
    NYI_DEBUG('unescape_uri_info');
}
sub validate_password {
    NYI_DEBUG('validate_password');
}


package
    Apache::ModuleConfig;

sub new {
}
sub get {
}


##############################################################################

package
    Apache::Constants;

use parent 'Exporter';

our @COMMON_CONSTS      = qw( OK DECLINED DONE NOT_FOUND FORBIDDEN AUTH_REQUIRED SERVER_ERROR );
our @RESPONSE_CONSTS    = qw( DOCUMENT_FOLLOWS  MOVED  REDIRECT  USE_LOCAL_COPY
                              BAD_REQUEST  BAD_GATEWAY  RESPONSE_CODES  NOT_IMPLEMENTED
                              CONTINUE  NOT_AUTHORITATIVE );
our @METHOD_CONSTS      = qw( METHODS  M_CONNECT  M_DELETE  M_GET  M_INVALID
                              M_OPTIONS  M_POST  M_PUT  M_TRACE  M_PATCH
                              M_PROPFIND  M_PROPPATCH  M_MKCOL  M_COPY
                              M_MOVE  M_LOCK  M_UNLOCK );
our @OPTIONS_CONSTS     = qw( OPT_NONE  OPT_INDEXES  OPT_INCLUDES  OPT_SYM_LINKS
                              OPT_EXECCGI  OPT_UNSET  OPT_INCNOEXEC
                              OPT_SYM_OWNER  OPT_MULTI  OPT_ALL );
our @SATISFY_CONSTS     = qw( SATISFY_ALL SATISFY_ANY SATISFY_NOSPEC );
our @REMOTEHOST_CONSTS  = qw( REMOTE_HOST REMOTE_NAME REMOTE_NOLOOKUP REMOTE_DOUBLE_REV );
our @HTTP_CONSTS        = qw( HTTP_OK  HTTP_MOVED_TEMPORARILY  HTTP_MOVED_PERMANENTLY
                              HTTP_METHOD_NOT_ALLOWED  HTTP_NOT_MODIFIED  HTTP_UNAUTHORIZED
                              HTTP_FORBIDDEN  HTTP_NOT_FOUND  HTTP_BAD_REQUEST
                              HTTP_INTERNAL_SERVER_ERROR  HTTP_NOT_ACCEPTABLE  HTTP_NO_CONTENT
                              HTTP_PRECONDITION_FAILED  HTTP_SERVICE_UNAVAILABLE
                              HTTP_VARIANT_ALSO_VARIES );
our @SERVER_CONSTS      = qw( MODULE_MAGIC_NUMBER  SERVER_VERSION  SERVER_BUILT );
our @CONFIG_CONSTS      = qw( DECLINE_CMD );
our @TYPES_CONSTS       = qw( DIR_MAGIC_TYPE );
our @OVERRIDE_CONSTS    = qw( OR_NONE  OR_LIMIT  OR_OPTIONS  OR_FILEINFO  OR_AUTHCFG
                              OR_INDEXES  OR_UNSET  OR_ALL  ACCESS_CONF  RSRC_CONF );
our @ARGS_HOW_CONSTS    = qw( RAW_ARGS  TAKE1  TAKE2  TAKE12  TAKE3  TAKE23  TAKE123
                              ITERATE  ITERATE2  FLAG  NO_ARGS );


our @EXPORT      = ( @COMMON_CONSTS );
our @EXPORT_OK   = ( @COMMON_CONSTS, @RESPONSE_CONSTS, @METHOD_CONSTS, @OPTIONS_CONSTS, @SATISFY_CONSTS,
                     @REMOTEHOST_CONSTS, @HTTP_CONSTS, @SERVER_CONSTS, @CONFIG_CONSTS, @TYPES_CONSTS,
                     @OVERRIDE_CONSTS, @ARGS_HOW_CONSTS);

our %EXPORT_TAGS = ( common     => \@COMMON_CONSTS,
                     response   => [ @COMMON_CONSTS, @RESPONSE_CONSTS ],
                     methods    => \@METHOD_CONSTS,
                     options    => \@OPTIONS_CONSTS,
                     satisfy    => \@SATISFY_CONSTS,
                     remotehost => \@REMOTEHOST_CONSTS,
                     http       => \@HTTP_CONSTS,
                     server     => \@SERVER_CONSTS,
                     config     => \@CONFIG_CONSTS,
                     types      => \@TYPES_CONSTS,
                     override   => \@OVERRIDE_CONSTS,
                     args_how   => \@ARGS_HOW_CONSTS,   );


sub OK                          {  0 }
sub DECLINED                    { -1 }
sub DONE                        { -2 }

# CONTINUE and NOT_AUTHORITATIVE are aliases for DECLINED.

sub CONTINUE                    { 100 }
sub DOCUMENT_FOLLOWS            { 200 }
sub NOT_AUTHORITATIVE           { 203 }
sub MOVED                       { 301 }
sub REDIRECT                    { 302 }
sub USE_LOCAL_COPY              { 304 }
sub BAD_REQUEST                 { 400 }
sub AUTH_REQUIRED               { 401 }
sub FORBIDDEN                   { 403 }
sub NOT_FOUND                   { 404 }
sub SERVER_ERROR                { 500 }
sub NOT_IMPLEMENTED             { 501 }
sub BAD_GATEWAY                 { 502 }

sub HTTP_OK                     { 200 }
sub HTTP_NO_CONTENT             { 204 }
sub HTTP_MOVED_PERMANENTLY      { 301 }
sub HTTP_MOVED_TEMPORARILY      { 302 }
sub HTTP_NOT_MODIFIED           { 304 }
sub HTTP_BAD_REQUEST            { 400 }
sub HTTP_UNAUTHORIZED           { 401 }
sub HTTP_FORBIDDEN              { 403 }
sub HTTP_NOT_FOUND              { 404 }
sub HTTP_METHOD_NOT_ALLOWED     { 405 }
sub HTTP_NOT_ACCEPTABLE         { 406 }
sub HTTP_LENGTH_REQUIRED        { 411 }
sub HTTP_PRECONDITION_FAILED    { 412 }
sub HTTP_INTERNAL_SERVER_ERROR  { 500 }
sub HTTP_NOT_IMPLEMENTED        { 501 }
sub HTTP_BAD_GATEWAY            { 502 }
sub HTTP_SERVICE_UNAVAILABLE    { 503 }
sub HTTP_VARIANT_ALSO_VARIES    { 506 }

# methods

sub M_GET       { 0 }
sub M_PUT       { 1 }
sub M_POST      { 2 }
sub M_DELETE    { 3 }
sub M_CONNECT   { 4 }
sub M_OPTIONS   { 5 }
sub M_TRACE     { 6 }
sub M_INVALID   { 7 }

# options

sub OPT_NONE      {   0 }
sub OPT_INDEXES   {   1 }
sub OPT_INCLUDES  {   2 }
sub OPT_SYM_LINKS {   4 }
sub OPT_EXECCGI   {   8 }
sub OPT_UNSET     {  16 }
sub OPT_INCNOEXEC {  32 }
sub OPT_SYM_OWNER {  64 }
sub OPT_MULTI     { 128 }
sub OPT_ALL       {  15 }

# satisfy

sub SATISFY_ALL    { 0 }
sub SATISFY_ANY    { 1 }
sub SATISFY_NOSPEC { 2 }

# remotehost

sub REMOTE_HOST       { 0 }
sub REMOTE_NAME       { 1 }
sub REMOTE_NOLOOKUP   { 2 }
sub REMOTE_DOUBLE_REV { 3 }



sub MODULE_MAGIC_NUMBER { "42" }
sub SERVER_VERSION      { "1.x" }
sub SERVER_BUILT        { "199908" }



##############################################################################
#
# Implementation of Apache::Request - a.k.a. libapreq

package
    Apache::Request;

use parent 'Apache';

sub new {
    my ($class, $r, %params) = @_;

    DEBUG('Apache::Request->new(%s) => %s', join(',', map { "$_=>'$params{$_}'" } keys %params ), $r);
    $r->{$_} = $params{$_}
        for qw(POST_MAX DISABLE_UPLOADS TEMP_DIR HOOK_DATA UPLOAD_HOOK);

    return bless $r, $class;
}

sub instance {
    NYI_DEBUG('$apr->instance')
}


sub parse {
    my $apr = shift;
    NYI_DEBUG('$apr->parse')
}


sub param {
    my $apr = shift;
    NYI_DEBUG('$apr->param')
}


sub params {
    my $apr = shift;
    NYI_DEBUG('$apr->params')
}

sub upload {
    my $apr = shift;
    NYI_DEBUG('$apr->upload')
}

###############################################################################

package
    Apache::Upload;

sub name {
    NYI_DEBUG('Apache::Upload->name');
}

sub filename {
    NYI_DEBUG('Apache::Upload->filename');
}

sub fh {
    NYI_DEBUG('Apache::Upload->fh');
}

sub size {
    NYI_DEBUG('Apache::Upload->size');
}

sub info {
    NYI_DEBUG('Apache::Upload->info');
}

sub type {
    NYI_DEBUG('Apache::Upload->type');
}

sub next {
    NYI_DEBUG('Apache::Upload->next');
}

sub tempname {
    NYI_DEBUG('Apache::Upload->tempname');
}

sub link {
    NYI_DEBUG('Apache::Upload->link');
}

################################################################################

package
    Apache::Cookie;

sub new {
    NYI_DEBUG('Apache::Cookie->new');
}

sub bake {
    NYI_DEBUG('$c->bake');
}

sub parse {
    NYI_DEBUG('$c->parse');
}

sub fetch {
    NYI_DEBUG('$c->fetch');
}

sub as_string {
    NYI_DEBUG('$c->as_string');
}

sub name {
    NYI_DEBUG('$c->name');
}

sub value {
    NYI_DEBUG('$c->value');
}

sub domain {
    NYI_DEBUG('$c->domain');
}

sub path {
    NYI_DEBUG('$c->path');
}

sub expires {
    NYI_DEBUG('$c->expires');
}

sub secure {
    NYI_DEBUG('$c->secure');
}


1;

__END__

=head1 NAME

Mock::Apache - mock Apache environment for testing and debugging

=head1 SYNOPSIS

    use Mock::Apache;

    my $server  = Mock::Apache->setup_server(param => 'value', ...);
    my $request = $server->new_request(method_name => 'value', ...);

    $server->

=head1 DESCRIPTION

C<Mock::Apache> is a mock framework for testing and debugging mod_perl
1.x applications.  Although that verson of mod_perl is obsolete, there
is still a lot of legacy code that uses it.  The framework is intended
to assist in understanding such code, by enabling it to be run and
debugged outside of the web server environment.  The framework
provides a tracing facility that prints all methods called, optionally
with caller information.

C<Mock::Apache> is based on C<Apache::FakeRequest> but goes beyond
that module, attempting to provide a relatively comprehensive mocking
of the mod_perl environment.

NOTE: the module is still very much at an alpha stage, with much of
the Apache::* classes missing, and much of the emulation incomplete or
probably just wrong.

I am aiming to provide top-level methods to "process a request", by
giving the mock apache object enough information about the
configuration to identify handlers, etc.  Perhaps passing the
server_setup method the pathname of an Apache configuration file even
and minimally "parsing" it.


=head1 METHODS

=head2 setup_server

=head2 new_request

=head2 execute_handler

localizes elements of the %ENV hash


=head1 SEE ALSO

https://github.com/fordmason/Mock-Apache

I<mod_perl Pocket Reference> by Andrew Ford, O'Reilly & Associates,
Inc, Sebastapol, 2001, ISBN: 0-596-00047-2


=head1 AUTHORS

Andrew Ford <andrew@ford-mason.co.uk>

Based on C<Apache::FakeRequest> by Doug MacEachern, with contributions
from Andrew Ford <andrew@ford-mason.co.uk>.

