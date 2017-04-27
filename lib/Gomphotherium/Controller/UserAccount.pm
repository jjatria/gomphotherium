package Gomphotherium::Controller::UserAccount;

use Mojo::Base 'Mojolicious::Controller';

sub fetch {
  my $self = shift->openapi->valid_input or return;

  my $user = $self->get_user;
  return $self->render( openapi => $user->render ) if defined $user;

  return $self->render(
    status => 404,
    openapi => { error => 'User not found' },
  );
}

sub _get_user {
  my ($self) = @_;
  return (defined $self->validation->param('id'))
    ? $self->app->schema->resultset('UserAccount')
      ->search( { id => $self->validation->param('id') } )
      ->first
    : undef;
}

1;
