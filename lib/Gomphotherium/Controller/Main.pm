package Gomphotherium::Controller::Main;
use Mojo::Base 'Mojolicious::Controller';

sub instance {
  my $self = shift->openapi->valid_input or return;
  return $self->render( openapi => $self->app->config->{instance} );
}

1;
