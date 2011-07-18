use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Mojolicious::Plugin::Bcrypt',
    AUTHOR              => q{minimalist <minimalist@lavabit.com>},
    VERSION_FROM        => 'lib/Mojolicious/Plugin/Bcrypt.pm',
    ABSTRACT_FROM       => 'lib/Mojolicious/Plugin/Bcrypt.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.3002
      ? ('LICENSE'=> 'perl')
      : ()),
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
        'Mojolicious' => 0,
        'Crypt::Eksblowfish::Bcrypt' => 0.009,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Mojolicious-Plugin-Bcrypt-*' },
);
