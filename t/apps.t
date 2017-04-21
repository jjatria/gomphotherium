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
use FindBin;
use strict;
use warnings;

diag("Removing database.db file");
unlink("database.db") if -f "database.db";

require "$FindBin::Bin/../gomphotherium.pl";

my $t = Test::Mojo->new;

# curl -X POST -d "client_name=Oddmuse&redirect_uris=urn:ietf:wg:oauth:2.0:oob&scopes=read" -Ss http://localhost:3000/api/v1/apps

$t->post_ok('/api/v1/apps' => form => {
  client_name => 'Oddmuse',
  redirect_uris => 'urn:ietf:wg:oauth:2.0:oob',
  scopes => 'read'})
    ->status_is(200)
    ->json_has('/id')
    ->json_has('/client_id')
    ->json_has('/client_secret');

done_testing();
