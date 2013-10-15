use ExtUtils::MakeMaker;

WriteMakefile( NAME          => 'Mock::Apache',
	       VERSION_FROM  => 'lib/Mock/Apache.pm',
	       AUTHOR        => 'Andrew Ford <ANDREWF@cpan.org>',
	       PREREQ_PM     => {
		   'Apache::FakeTable' => 0,
		   'parent'            => 0,
		   'Readonly'          => 0,
		   'URI'               => 0,
	       },
    );
