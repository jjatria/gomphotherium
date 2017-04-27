package Gomphotherium::Schema::ResultSet::UserAccount;

use Moose;
use MooseX::MarkAsMethods autoclean => 1;

extends 'Gomphotherium::Schema::ResultSet';


#   followers_count => ( is => 'ro', isa => Int );
#   following_count => ( is => 'ro', isa => Int );
#   statuses_count  => ( is => 'ro', isa => Int );


__PACKAGE__->meta->make_immutable;

1;
