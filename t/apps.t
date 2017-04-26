#!/usr/bin/env perl

# Copyright (C) 2017 Alex Schroeder <alex@gnu.org>

# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <http://www.gnu.org/licenses/>.

use Test::More;
use Test::Mojo;
use Mojo::JSON qw(decode_json);
use FindBin;
use strict;
use warnings;

diag("Removing database.db file");
unlink("database.db") if -f "database.db";

require "$FindBin::Bin/../gomphotherium.pl";

my $t = Test::Mojo->new;

# curl -X POST -d "client_name=Oddmuse&redirect_uris=urn:ietf:wg:oauth:2.0:oob&scopes=read" -Ss http://localhost:3000/api/v1/apps

# register client
$t->post_ok('/api/v1/apps' => form => {
  client_name => 'Oddmuse',
  redirect_uris => 'urn:ietf:wg:oauth:2.0:oob',
  scopes => 'read'})
    ->status_is(200)
    ->json_has('/id')
    ->json_has('/client_id')
    ->json_has('/client_secret');

# remember client stuff
my $hash	  = decode_json $t->tx->res->body;
my $client_id	  = $hash->{client_id};
my $client_secret = $hash->{client_secret};

# curl -X POST -d "username=alex&email=kensanata@gmail.com&password=*secret*" -Ss http://localhost:3000/auth

# create user
$t->post_ok('/auth' => form => {
  username => 'alex',
  password => '*secret*',
  email => 'alex@gnu.org',
  scopes => 'read'})
    ->status_is(200);

# FIXME: make sure we can't register twice
$t->post_ok('/auth' => form => {
  username => 'alex',
  email => 'alex@gnu.org',
  password => '*secret*',
  scopes => 'read'})
    ->status_is(500);

is($t->tx->res->body, 'User already exists');

# curl -X POST -d "client_id=CLIENT_ID_HERE&client_secret=CLIENT_SECRET_HERE&grant_type=password&username=YOUR_EMAIL&password=YOUR_PASSWORD" -Ss http://localhost:3000/oauth/token
# curl -X POST -d "client_id=456106006&client_secret=1234&grant_type=password&username=kensanata@gmail.com&password=*secret*" -Ss http://localhost:3000/oauth/token

# authenticate using password
$t->post_ok('/oauth/token' => form => {
  client_id => $client_id,
  client_secret => $client_secret,
  grant_type => 'password',
  username => 'alex@gnu.org',
  password => '*secret*'})
    ->status_is(200)
    ->json_has('/access_token')
    ->json_has('/refresh_token')
    ->json_has('/token_type', 'Bearer');

$hash		 = decode_json $t->tx->res->body;
my $access_token = $hash->{access_token};

# curl --header "Authorization: Bearer MTQ5MjgxNDQ5NS0zNTI5OTQtMC45OTMxODYwMDk5MzA0OTctSlBRanVqVDdzZzQzZ2dKS1MzcWo1WHp3MkFKUEs4" -sS http://localhost:3000/api/v1/accounts/verify_credentials

$t->ua->on(start => sub {
  my ($ua, $tx) = @_;
  $tx->req->headers->authorization("Bearer $access_token");
});

$t->get_ok('/api/v1/accounts/verify_credentials')
    ->status_is(200)
    ->json_has('/id')
    ->json_has('/username');

done_testing();
