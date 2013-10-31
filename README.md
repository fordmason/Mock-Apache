Mock-Apache
===========

"Mock::Apache" is a mock framework for testing and debugging mod_perl
1.x applications. Although that version of mod_perl is obsolete, there
is still a lot of legacy code that uses it. The framework is intended to
assist in understanding such code, by enabling it to be run and debugged
outside of the web server environment. The framework provides a tracing
facility that prints all methods called, optionally with caller
information.

The package is inspired by Apache::FakeRequest (which I contributed to) but more
comprehensive than that module in its mocking of the environment.

The module is still very much at an alpha stage, with much of the
Apache::* classes missing.

I am aiming to provide top-level methods to "process a request", by
giving the mock apache object enough information about the
configuration to identify handlers, etc.  Perhaps passing the
server_setup method the pathname of an Apache configuration file even
and minimally "parsing" it.

Author
------

Andrew Ford 
