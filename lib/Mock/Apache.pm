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

BEGIN {
    our $VERSION = "0.03";

    # Lie about the following modules being loaded

    mark_as_loaded($_)
	for qw( Apache  Apache::Server  Apache::Connection  Apache::Log
                Apache::Table  Apache::URI  Apache::Util  Apache::Constants
                Apache::ModuleConfig  Apache::Symbol
                Apache::Request  Apache::Upload  Apache::Cookie );
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

    $params{document_root}   ||= _get_config_value($cfg, 'DocumentRoot', $DEFAULT_DOCUMENT_ROOT);
    $params{server_root}     ||= _get_config_value($cfg, 'ServerRoot',   $DEFAULT_SERVER_ROOT);
    $params{server_hostname} ||= $DEFAULT_HOSTNAME;
    $params{server_port}     ||= 80;
    $params{server_admin}    ||= _get_config_value($cfg, 'ServerAdmin', 
						   $DEFAULT_ADMIN . '@' . $params{server_hostname});
    $params{gid}             ||= getgrnam('apache') || 48;
    $params{uid}             ||= getpwnam('apache') || 48;

    $Apache::server = Apache::Server->new(%params);

    my $self = bless { server => $Apache::server, %params }, $class;

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


    local($ENV{REMOTE_ADDR}) = $request->subprocess_env('REMOTE_ADDR');
    local($ENV{REMOTE_HOST}) = $request->subprocess_env('REMOTE_HOST');

    local $Apache::request = $request;
    my ($stdout, $rc) = capture_stdout { $handler->($request) };

    my $status  = $request->status;
    (my $message = $request->status_line) =~ s/^... //;
    my $headers = HTTP::Headers->new;
    while (my($field, $value) = each %{$request->headers_out}) {
	$headers->push_header($field, $value);
    }

    return HTTP::Response->new( $status, $message, $headers, $stdout );
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

Readonly our @SCALAR_RO_ACCESSORS => qw( connection
                                         server
                                         is_initial_req
					 is_main
					 _env
					 _uri
					 _mock_client
                                        );
Readonly our @SCALAR_RW_ACCESSORS => ( qw( filename
                                           request_time
                                           uri
					   content
                                          ),

				       # Server response methods
				       qw( content_type
                                           content_encoding
                                           content_languages
                                           status
                                          ),
				     );

Readonly our @UNIMPLEMENTED       => qw( last
					 main
					 next
					 prev
					 lookup_file
					 lookup_uri
					 run
					 filename
					 finfo
					 get_remote_host
					 get_remote_logname );


__PACKAGE__->mk_accessors(@SCALAR_RW_ACCESSORS);
__PACKAGE__->mk_ro_accessors(@SCALAR_RO_ACCESSORS);

{
    no strict 'refs';
    *{"Mock::Apache::$_"} = sub { _unimplemented() }
	for @UNIMPLEMENTED;
}

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
				  _env           => $env  } );

    $r->{log}           ||= $r->{server}->log;
    $r->{notes}           = Apache::Table->new($r);
    $r->{pnotes}          = Apache::Table->new($r);
    $r->{headers_in}      = Apache::Table->new($r);
    $r->{headers_out}     = Apache::Table->new($r);
    $r->{err_headers_out} = Apache::Table->new($r);
    $r->{subprocess_env}  = Apache::Table->new($r);

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

    $DB::single=1;

    my $uri = $http_req->uri;
    $uri = URI->new($uri) unless ref $uri;

    $r->{_uri}    = $uri;
    $r->{method}  = $http_req->method;
    ($r->{uri}    = $uri->path) =~ s{^/}{};
    $r->{content} = $http_req->content;

    $http_req->headers->scan( sub {
				  my ($key, $value) = @_;
				  $r->headers_in->set($key, $value);
				  (my $header_env = "HTTP_$key") =~ s/-/_/g;
				  $r->{subprocess_env}->set($header_env, $value);
			      } );

    return;
}

# $r = Apache->request([$r])                                          # MPPR p23
sub request { $request };

# $s = $r->server                                                     # MPPR p38
# $s = Apache->server
sub server  { $server };

# $str = $r->document_root                                            # MPPR p32
sub document_root   { shift->server->{document_root}; }

# $num = $r->server_port                                              # MPPR p33
sub get_server_port { shift->server->{server_port}; }

# $str = $r->get_remote_host([$lookup_type])                          # MPPR p25
# FIXME: emulate lookups properly
sub get_remote_host {
    my ($r, $type) = @_;
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


# $str = $r->header_in($key[, $value])                                # MPPR p26
sub header_in       { shift->{headers_in}->_get_or_set(@_); }
sub header_out      { shift->{headers_out}->_get_or_set(@_); }
sub err_header_out  { shift->{err_headers_out}->_get_or_set(@_); }

# {$href|%hash} = $r->headers_in                                      # MPPR p26
sub headers_in      { shift->{headers_in}->_hash_or_list; }
sub headers_out     { shift->{headers_out}->_hash_or_list; }
sub err_headers_out { shift->{err_headers_out}->_hash_or_list; }


# $str = $r->method([$newval])                                        # MPPR p26
# FIXME: method should be settable
sub method        { 'GET' }

# $num = $r->method_number([$newval])                                 # MPPR p26
sub method_number { eval '&Apache::Constants::M_' . $_[0]->{method}; }

# {$str|@arr} = $r->args                                              # MPPR p24
# FIXME: query_form_hash does not return the right data if keys are repeated
sub args          { return wantarray ? $self->_uri->query_form_hash : $self->_uri->query }


# $str = $r->status_line([$newstr])
sub status_line   {
    my $r = shift;
    my $status_line = $r->{status_line};
    if (@_) {
	if (($r->{status_line} = shift) =~ m{^(\d\d\d)}x) {
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


# {$str|$href} = $r->notes([$key[,$val]])                             # MPPR p31
# with no arguments returns a reference to the notes table
# otherwise gets or sets the named note
sub notes {
    my $r = shift;
    my $notes = $r->{notes};
    return @_ ? $notes->_get_or_set(@_) : $notes->_hash_or_list;
}

# {$str|$href} = $r->pnotes([$key[,$val]])                            # MPPR p31
# with no arguments returns a reference to the pnotes table
# otherwise gets or sets the named pnote
sub pnotes {
    my $r = shift;
    my $pnotes = $r->{pnotes};
    return @_ ? $pnotes->_get_or_set(@_) : $pnotes->_hash_or_list;
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
}


# Subrequest methods

sub lookup_uri {
    my ($r, $uri) = @_;

    $DB::single=1;
    return $r->new( uri            => $uri,
		    is_initial_req => 0 );
}

sub lookup_file {
    my ($r, $file) = @_;

    $DB::single=1;
    return $r->new( uri            => $file,
		    is_initial_req => 0 );
}


sub _unimplemented {
    my ($r) = @_;

    $DB::single=1;
    my $subname = (caller(0))[3];
    my ($file, $line) = (caller(1))[1..2];
    croak  "$subname not implemented at $file, line $line";
    return;
}

package
    Apache::STDOUT;





##############################################################################
#
# Implementation of Apache::Request - a.k.a. libapreq

package
    Apache::Request;

use parent 'Apache';

sub new {
    my ($class, $r, %params) = @_;

    $r->{$_} = $params{$_}
	for qw(POST_MAX DISABLE_UPLOADS TEMP_DIR HOOK_DATA UPLOAD_HOOK);

    return bless $r, $class;
}

sub instance {
}


sub parse {
    my $apr = shift;
    $DB::single=1;
    return;
}


sub param {
    my $apr = shift;

}


sub params {
    my $apr = shift;
}

sub upload {
}


package
    Apache::Upload;

package
    Apache::Cookie;

sub new {
}

sub bake {
}

sub parse {
}

sub fetch {
}

sub as_string {
}

sub name {
}

sub value {
}

sub domain {
}

sub path {
}

sub expires {
}

sub secure {
}



##############################################################################

package
    Apache::Server;

use Readonly;

use parent 'Class::Accessor';

# gid
# is_virtual
# log
# log_error
# loglevel
# names
# next
# port
# server_hostname
# server_admin
# timeout
# uid
# warn

Readonly our @RW_ACCESSORS => qw();
Readonly our @RO_ACCESSORS => qw(server_admin server_hostname port uid gid log);

__PACKAGE__->mk_accessors(@RW_ACCESSORS);
__PACKAGE__->mk_ro_accessors(@RO_ACCESSORS);

sub new {
    my ($class, %params) = @_;
    $params{log} = Apache::Log->new();
    return $class->SUPER::new(\%params);
}


sub names {
    my $self = shift;
    return @{$self->{names} || []};
}


##############################################################################

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
    $DB::single=1;
    return;
}
sub fileno {
    croak("fileno is not implemented");
    $DB::single=1;
    return;
}
sub local_addr {
    $DB::single=1;
    return;
}
sub remote_addr {
    $DB::single=1;
    return;
}
sub remote_host { $_->_mock_client->remote_host; }
sub remote_ip   { $_->_mock_client->remote_addr; }

sub remote_logname {
    $DB::single=1;
    return;
}
sub user {
    $DB::single=1;
    return;
}

##############################################################################
#

package
    Apache::Log;

use Log::Log4perl;

sub new {
    my ($class, %params) = @_;
    return bless \%params, $class;
}

##############################################################################

package
    Apache::Table;

use Apache::FakeTable;
use parent 'Apache::FakeTable';

sub _hash_or_list {
    my ($self) = @_;

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

    my @old_values = $self->get($key);
    if (@new_values) {
        $self->set($key, @new_values);
    }
    return wantarray ? @old_values : $old_values[0];
}


##############################################################################

package
    Apache::URI;

use strict;
use URI;

our @ISA = qw(URI);

sub parse {
    my ($r, $string_uri) = @_;
    $DB::single=1;
    return;
}

##############################################################################

package
    Apache::Util;

sub escape_html {
    $DB::single=1;
    return;
}
sub escape_uri {
    $DB::single=1;
    return;
}
sub ht_time {
    $DB::single=1;
    return;
}

sub parsedate {
    $DB::single=1;
    return;
}
sub size_string {
    $DB::single=1;
    return;
}
sub unescape_uri {
    $DB::single=1;
    return;
}
sub unescape_uri_info {
    $DB::single=1;
    return;
}
sub validate_password {
    $DB::single=1;
    return;
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
sub HTTP_NO_CONTENT             { 204 }
sub MOVED                       { 301 }
sub REDIRECT                    { 302 }
sub USE_LOCAL_COPY              { 304 }
sub HTTP_NOT_MODIFIED           { 304 }
sub BAD_REQUEST                 { 400 }
sub AUTH_REQUIRED               { 401 }
sub FORBIDDEN                   { 403 }
sub NOT_FOUND                   { 404 }
sub HTTP_METHOD_NOT_ALLOWED     { 405 }
sub HTTP_NOT_ACCEPTABLE         { 406 }
sub HTTP_LENGTH_REQUIRED        { 411 }
sub HTTP_PRECONDITION_FAILED    { 412 }
sub SERVER_ERROR                { 500 }
sub NOT_IMPLEMENTED             { 501 }
sub BAD_GATEWAY                 { 502 }
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
1.x applications.  It is based on C<Apache::FakeRequest> but goes
beyond that module, attempting to provide a relatively comprehensive
mocking of the mod_perl environment.

The module is still very much at an alpha stage, with much of the
Apache::* classes missing.

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

