package Gomphotherium::Schema::Result::UserAccount;

use Moose;
use MooseX::MarkAsMethods autoclean => 1;

extends 'Gomphotherium::Schema::Result';

__PACKAGE__->table("user_account");

__PACKAGE__->add_columns(
  id => {
    data_type => "integer",
    size => 10,
    is_auto_increment => 1,
    extra => {
      unsigned => 1,
    },
  },

  username => {
    data_type => "varchar",
    size => 50,
  },

  acct => {
    data_type => "varchar",
    size => 50,
  },


  display_name => {
    data_type => "varchar",
    size => 255,
    is_nullable => 1,
  },

  avatar => {
    data_type => "varchar",
    size => 250,
  },

  header => {
    data_type => "varchar",
    size => 250,
  },

  url => {
    data_type => "varchar",
    size => 255,
  },

  note => {
    data_type => "varchar",
    size => 160,
    is_nullable => 1,
  },

  locked => {
    data_type => "bool",
    default => 0,
  },


  created_at => {
    data_type => "datetime",
    set_on_create => 1,
  },
);

__PACKAGE__->set_primary_key("id");

__PACKAGE__->has_many(
  statuses => 'Gomphotherium::Schema::Result::Status', 'author',
);

__PACKAGE__->has_many(
  relationships => 'CloudCAST::Schema::Result::Relationship', 'id',
);

sub render {
  my ($self) = @_;

  my %payload = map { $_ => $self->{$_} } qw(
    id acct avatar created_at display_name header locked note url username
  );

  # Not yet implemented
  # $payload{avatar_static} = ...;
  # $payload{header_static} = ...;

#   $payload{followers_count} = ...;
#   $payload{statuses_count}  = ...;

  return \%payload;
}

__PACKAGE__->add_unique_constraint([ qw/ username / ]);

__PACKAGE__->meta->make_immutable;

1;
