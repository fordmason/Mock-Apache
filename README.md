Mock-Apache
===========

Mocked Apache 1.3 environment for testing and debugging mod_perl
handlers.  Inspired by Apache::FakeRequest (which I contributed to)
but more comprehensive than that module in its mocking of the
environment.

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
