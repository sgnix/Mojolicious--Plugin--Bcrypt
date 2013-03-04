package Mojolicious::Plugin::Bcrypt;

use warnings;
use strict;

our $VERSION = '0.04';

use Mojo::Base 'Mojolicious::Plugin';
use Crypt::Eksblowfish::Bcrypt qw(bcrypt en_base64);
use Crypt::Random::Source qw(get_strong get_weak);

sub register {
    my $self   = shift;
    my $app    = shift;
    my $config = shift || {};

    $app->helper(
        bcrypt => sub {
            my $c = shift;
            my ( $password, $settings ) = @_;
            unless ( defined $settings && $settings =~ /^\$2a\$/ ) {
                $settings = sprintf(
                    '$2a$%02d$%s',
                    $config->{cost} || 6,
                    _salt($config->{strong})
                );
            }
            return bcrypt( $password, $settings );
        }
    );

    $app->helper(
        bcrypt_validate => sub {
            my $c = shift;
            my ( $plain, $crypted ) = @_;
            return $c->bcrypt( $plain, $crypted ) eq $crypted;
        }
    );
}

sub _salt {
    return en_base64((shift) ? get_strong(16) : get_weak(16));
}

1;

__END__

=head1 NAME

Mojolicious::Plugin::Bcrypt - bcrypt your passwords!

=head1 VERSION

Version 0.04

=head1 SYNOPSIS

Provides a helper for crypting and validating passwords via bcrypt.

    use Mojolicious::Plugin::Bcrypt;

    sub startup {
        my $self = shift;
        $self->plugin('bcrypt', { cost => 4, strong => 0 });
    }

    ...

Optional parameter C<cost> is a non-negative integer controlling the
cost of the hash function. The number of operations is proportional to 2^cost.
The current default value is 6.

Optional parameter C<strong> define random data sources type for salt: weak (0)
or strong (1) random source. Default value is 0.

=head1 HELPERS

=head2 bcrypt

Crypts a password via the bcrypt algorithm.

    $self->bcrypt( $password, $settings );

C<$settings> is an optional string which encodes the algorithm parameters, as
described in L<Crypt::Eksblowfish::Bcrypt>.

    sub signup {
        my $self = shift;
        my $crypted_pass = $self->bcrypt( $self->param('password') );
        ...
    }

=head2 bcrypt_validate

Validates a password against a crypted copy (for example from your database).

    sub login {
        my $self = shift;
        my $entered_pass = $self->param('password');
        my $crypted_pass = $self->get_password_from_db();
        if ( $self->bcrypt_validate( $entered_pass, $crypted_pass ) ) {

            # Authenticated
            ...;
        }
        else {

            # Wrong password
            ...;
        }
    }

=head1 DEVELOPMENT AND REPOSITORY

Clone it on GitHub at https://github.com/naturalist/Mojolicious--Plugin--Bcrypt

=head1 SEE ALSO

L<Crypt::Eksblowfish::Bcrypt>, L<Mojolicious>, L<Mojolicious::Plugin>

=head1 AUTHOR

minimalist, C<< <minimalist at lavabit.com> >>

=head1 LICENSE AND COPYRIGHT

Copyright 2011 minimalist.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut

