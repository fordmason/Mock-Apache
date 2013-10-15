package Mock::Apache;

use strict;

use Readonly;

our $VERSION = "0.01";

Readonly our $DEFAULT_HOSTNAME => 'server.example.com';
Readonly our $DEFAULT_ADDR     => '22.22.22.22';
Readonly our $DEFAULT_ADMIN    => 'webmaster';

# Default locations (RedHat-inspired)

Readonly our $DEFAULT_SERVER_ROOT   => '/etc/httpd';
Readonly our $DEFAULT_DOCUMENT_ROOT => '/var/www/html';


# Set up a mock Apache server

sub setup_server {
    my ($class, %params) = @_;

    $params{document_root}   ||= $DEFAULT_DOCUMENT_ROOT;
    $params{server_root}     ||= $DEFAULT_SERVER_ROOT;
    $params{server_hostname} ||= $DEFAULT_HOSTNAME;
    $params{server_port}     ||= 80;
    $params{server_admin}    ||= $DEFAULT_ADMIN . '@' . $params{server_hostname};
    $params{gid}             ||= getgrnam('apache') || 48;
    $params{uid}             ||= getpwnam('apache') || 48;

    $Apache::server = Apache::Server->new(%params);

    my $self = bless { server => $Apache::server, %params }, $class;

    return $self;
}

sub new_request {
    my $self = shift;
    my $req_initializer;
    if ((scalar @_ % 2) == 1 && ref $_[-1]) {
        $req_initializer = pop @_;
        croak('request initializer must be an HTTP:Request object')
            unless $req_initializer->isa('HTTP::Request');
    }

    my %params = @_;
    my $r = Apache->new(server => $self->{server}, @_);
    $r->_initialize_from_http_request_object($req_initializer)
        if $req_initializer;

    return $r;
}


# $mock_apache->execute_handler($handler, $request)

sub execute_handler {
    my ($self, $handler, $request) = @_;

    if (!ref $handler) {
	no strict 'refs';
	$handler = \&{$handler};
    }
    if (ref $request eq 'HASH') {
	$request = $self->new_request(%$request); 
    }
    
    local($ENV{REMOTE_ADDR}) = $request->subprocess_env('REMOTE_ADDR');
    local($ENV{REMOTE_HOST}) = $request->subprocess_env('REMOTE_HOST');

    return $handler->($request);
}



##############################################################################

package Apache;

use Readonly;
use URI;

use parent qw(Class::Accessor);

Readonly our @SCALAR_RO_ACCESSORS => qw( connection
                                         server
                                         is_initial_req
					 is_main
                                        );
Readonly our @SCALAR_RW_ACCESSORS => ( qw( filename request_time uri ),
				       # Server response methods
				       qw( content_type
                                           content_encoding
                                           content_languages ) );

Readonly our @UNIMPLEMENTED       => qw( last
					 main
					 next
					 prev
					 lookup_file
					 lookup_uri
					 run
					 args
					 content
					 filenam
					 finfo
					 get_remote_host
					 get_remote_logname );


__PACKAGE__->mk_accessors(@SCALAR_RW_ACCESSORS);
__PACKAGE__->mk_ro_accessors(@SCALAR_RO_ACCESSORS);

{
    no strict 'refs';
    *{"Mock::Apache::$_"} = \&_unimplemented
	for @UNIMPLEMENTED;
}

our $server;
our $request;

sub new {
    my ($class, %params) = @_;

    my $env = { GATEWAY_INTERFACE => delete $params{GATEWAY_INTERFACE} || 'CGI-Perl/1.1',
		MOD_PERL          => '1.3',
		REMOTE_ADDR       => delete $params{REMOTE_ADDR} || '42.42.42.42',
		REMOTE_HOST       => delete $params{REMOTE_HOST} || 'remote.example.com' };

    my $r = $class->SUPER::new( { request_time   => time,
				  is_initial_req => 1,
				  is_main        => 1,
				  %params,
				  _env           => $env  } );

    $r->{notes}           = Apache::Table->new($r);
    $r->{pnotes}          = Apache::Table->new($r);
    $r->{headers_in}      = Apache::Table->new($r);
    $r->{headers_out}     = Apache::Table->new($r);
    $r->{err_headers_out} = Apache::Table->new($r);
    $r->{subprocess_env}  = Apache::Table->new($r);

    while (my($key, $val) = each %{$params{headers} || {}}) {
	$r->{headers_in}->set($key, $val);
    }

    while (my($key, $val) = each %$env) {
	$r->{subprocess_env}->set($key, $val);
    }

    $r->{server}     ||= Apache::Server->new();
    $r->{connection} ||= Apache::Connection->new();
    $r->{log}        ||= $r->server->log;

    return $r;
}

sub request { $request };
sub server  { $server };

sub document_root { shift->server->{document_root}; }

sub header_in       { shift->{headers_in}->_get_or_set(@_); }
sub header_out      { shift->{headers_out}->_get_or_set(@_); }
sub err_header_out  { shift->{err_headers_out}->_get_or_set(@_); }
sub headers_in      { shift->{headers_in}->_hash_or_list; }
sub headers_out     { shift->{headers_out}->_hash_or_list; }
sub err_headers_out { shift->{err_headers_out}->_hash_or_list; }

sub notes {
    my $r = shift;
    my $notes = $r->{notes};
    return @_ ? $notes->_get_or_set(@_) : $notes->_hash_or_list;
}

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




sub _initialize_from_http_request_object {
    my ($r, $http_req) = @_;

    $DB::single=1;

    my $uri = $http_req->uri;
    $uri = URI->new($uri) unless ref $uri;

    $r->{uri} = $uri->path;
    return;
}


sub _unimplemented {
    my ($r) = @_;
    $DB::single=1;
    return;
}

##############################################################################

package Apache::Server;

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

package Apache::Connection;

sub new {
    my ($class, %params) = @_;
    return bless \%params, $class;
}

##############################################################################

package Apache::Log;

use Log::Log4perl;

sub new {
    my ($class, %params) = @_;
    return bless \%params, $class;
}

##############################################################################

package Apache::Table;

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

package Apache::URI;

use strict;
use URI;

our @ISA = qw(URI);

sub parse {
    my ($r, $string_uri) = @_;
    $DB::single=1;
    return;
}

##############################################################################

package Apache::Util;

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




##############################################################################

package Apache::Constants;

use parent 'Exporter';

our @COMMON_TAGS = qw( OK DECLINED DONE NOT_FOUND FORBIDDEN AUTH_REQUIRED SERVER_ERROR );
our %EXPORT_TAGS = ( common     => [ @COMMON_TAGS ],
                     response   => [ @COMMON_TAGS,
				     qw( DOCUMENT_FOLLOWS
                                         MOVED
                                         REDIRECT
                                         USE_LOCAL_COPY
                                         BAD_REQUEST
                                         BAD_GATEWAY
                                         RESPONSE_CODES
                                         NOT_IMPLEMENTED
                                         CONTINUE
                                         NOT_AUTHORITATIVE ) ],

                     methods    => [ qw( METHODS
                                         M_CONNECT
                                         M_DELETE
                                         M_GET
                                         M_INVALID
                                         M_OPTIONS
                                         M_POST
                                         M_PUT
                                         M_TRACE
                                         M_PATCH
                                         M_PROPFIND
                                         M_PROPPATCH
                                         M_MKCOL
                                         M_COPY
                                         M_MOVE
                                         M_LOCK
                                         M_UNLOCK ) ],

                     options    => [ qw( OPT_NONE
                                         OPT_INDEXES
                                         OPT_INCLUDES
                                         OPT_SYM_LINKS
                                         OPT_EXECCGI
                                         OPT_UNSET
                                         OPT_INCNOEXEC
                                         OPT_SYM_OWNER
                                         OPT_MULTI
                                         OPT_ALL ) ],

		     satisfy    => [ qw( SATISFY_ALL SATISFY_ANY SATISFY_NOSPEC ) ],

		     remotehost => [ qw( REMOTE_HOST REMOTE_NAME REMOTE_NOLOOKUP REMOTE_DOUBLE_REV ) ],

		     http       => [ qw( HTTP_OK
                                         HTTP_MOVED_TEMPORARILY
                                         HTTP_MOVED_PERMANENTLY
                                         HTTP_METHOD_NOT_ALLOWED
                                         HTTP_NOT_MODIFIED
                                         HTTP_UNAUTHORIZED
                                         HTTP_FORBIDDEN
                                         HTTP_NOT_FOUND
                                         HTTP_BAD_REQUEST
                                         HTTP_INTERNAL_SERVER_ERROR
                                         HTTP_NOT_ACCEPTABLE
                                         HTTP_NO_CONTENT
                                         HTTP_PRECONDITION_FAILED
                                         HTTP_SERVICE_UNAVAILABLE
                                         HTTP_VARIANT_ALSO_VARIES ) ],

		     server     => [ qw( MODULE_MAGIC_NUMBER SERVER_VERSION SERVER_BUILT ) ],
		     config     => [ qw( DECLINE_CMD ) ],
		     types      => [ qw( DIR_MAGIC_TYPE ) ],
		     override   => [ qw( OR_NONE
                                         OR_LIMIT
                                         OR_OPTIONS
                                         OR_FILEINFO
                                         OR_AUTHCFG
                                         OR_INDEXES
                                         OR_UNSET
                                         OR_ALL
                                         ACCESS_CONF
                                         RSRC_CONF ) ],

                    args_how    => [ qw( RAW_ARGS
                                         TAKE1
                                         TAKE2
                                         TAKE12
                                         TAKE3
                                         TAKE23
                                         TAKE123
                                         ITERATE
                                         ITERATE2
                                         FLAG
                                         NO_ARGS ) ],
    );


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


=head1 AUTHORS

Andrew Ford <andrew@ford-mason.co.uk>

Based on C<Apache::FakeRequest> by Doug MacEachern, with contributions
from Andrew Ford <andrew@ford-mason.co.uk>.

