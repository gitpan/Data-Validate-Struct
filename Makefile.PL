#
# Makefile.PL - build file for Date::Validate::Struct
#
# Copyright (c) 2007 Thomas Linden <tom |AT| cpan.org>.
# All Rights Reserved. Std. disclaimer applies.
# Artificial License, same as perl itself. Have fun.
#

use ExtUtils::MakeMaker;

WriteMakefile(
	      NAME	   => 'Data::Validate::Struct',
	      VERSION_FROM => 'Struct.pm',
	      clean        => { FILES => '*~ */*~' },
	      PREREQ_PM    => { 'Regexp::Common' },
	      dist         => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
	      test         => { TESTS => 't/*.t' }
);

