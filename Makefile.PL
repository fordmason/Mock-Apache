use ExtUtils::MakeMaker;

WriteMakefile( NAME          => 'Mock::Apache',
               VERSION_FROM  => 'lib/Mock/Apache.pm',
               ABSTRACT      => 'Mock Apache environment',
               AUTHOR        => 'Andrew Ford <andrew[at]ford-mason.co.uk>',
               LICENSE       => 'perl',
               PREREQ_PM     => {
                   'Apache::FakeTable'     => 0,
                   'Apache::ConfigParser'  => 0,
                   'Module::Loaded'        => 0,
                   'parent'                => 0,
                   'Readonly'              => 0,
                   'URI'                   => 0,
               },
               META_ADD      => {

                   # Mock::Apache provides emulated implementations of
                   # the mod_perl modules, but these should not be
                   # indexed.

                   no_index => {
                       package   => [ qw( Apache
                                          Apache::Connection
                                          Apache::Constants
                                          Apache::Log
                                          Apache::Server
                                          Apache::Table
                                          Apache::URI
                                          Apache::Util ) ],
                   },
                   repository  => {
                       url  => 'git://github.com/fordmason/Mock-Apache.git',
                       web  => 'https://github.com/fordmason/Mock-Apache',
                       type => 'git',
                   },                                     
               },
            );
