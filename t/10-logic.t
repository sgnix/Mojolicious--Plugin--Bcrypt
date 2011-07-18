#!/usr/bin/perl

use strict;
use warnings;

use Test::More tests => 17;
use Test::Mojo;
use Mojolicious::Lite;
use Mojolicious::Plugin::Bcrypt;

plugin bcrypt => { cost => 6 };

get '/bc' => sub {
    my $self = shift;
    my ( $p, $s ) = map { $self->param($_) } qw/p s/;
    $self->render_text( $self->bcrypt( $p, $s ) );
};

get '/bv' => sub {
    my $self = shift;
    my ( $p, $c ) = map { $self->param($_) } qw/p c/;
    my $ok = $self->bcrypt_validate( $p, $c );
    $self->render_text( $ok ? 'Pass' : 'Fail' );
};

my $t = Test::Mojo->new();
my @A = <DATA>;

for (@A) {
    chomp;
    s/([^ ]+) ([^ ]+) *//;
    my ( $settings, $hash ) = ( $1, $2 );
    $t->get_ok("/bc?p=$_&s=$settings")->content_is( $settings . $hash );
    $t->get_ok( "/bv?p=$_&c=" . $settings . $hash, $_ );
}

my $password = 'big secret';
my $bcrypted = app->bcrypt($password);
ok( app->bcrypt_validate( $password, $bcrypted ), 'accept ok' );
ok( !app->bcrypt_validate( 'meow!', $bcrypted ), 'deny ok' );

__DATA__
$2a$06$cDTyXCPyZ0npLBTSbVTSTe 7GWMx9.3G/fpj8oDiyuQdsa2iqpFGmO 
$2a$06$OxDCTUayLyPtLRWxbhPoPe r8io68QbDErcImQ1oQKuFgO5Vkawfuu password
$2a$06$LULFY1a3ZyXTLhLqRDb/Qe kyfCo7Mcdq3yim3Qvkcwt3j6WkGkotu 0
$2a$06$YDDSKEnPLDi0MRDxTU3zKu iGlbH4EazT7YiiSSbAGONYfPYZLfm3m short skirt and long jacket
$2a$06$TRTxb0bYKRbxLB/2SiX0PO NmMUp3S1PE0XxrPCOIyF9Y01irLMmgi нова загора
