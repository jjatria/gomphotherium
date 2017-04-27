package Gomphotherium;

use Mojo::Base 'Mojolicious';
use Encode;

has schema => (
  is => 'rw',
  isa => 'Gomphotherium::Schema',
  lazy => 1,
  default => sub {
    use Gomphotherium::Schema;
    Gomphotherium::Schema->connect({
      dsn => $_[0]->config->{database}{dsn},
    });
  },
);

# This method will run once at server start
sub startup {
  my $self = shift;

  # Load configuration from hash returned by "my_app.conf"
  my $config = $self->plugin('Config');

  # Documentation browser under "/perldoc"
  $self->plugin('PODRenderer') if $config->{perldoc};

  # Load possibly many versions of the API
  foreach my $v (keys %{$config->{api_spec}}) {
    $self->plugin( OpenAPI => {
      route => $self->routes->under("/api/v$v"),
      url   => $config->{api_spec}{$v},
    });
  }

#   $self->plugin( OAuth2::Server => {
#     authorize_route              => '/oauth/authorize',
#     access_token_route           => '/oauth/token',
#     login_resource_owner_cb      => $resource_owner_logged_in_sub,
#     confirm_by_resource_owner_cb => $resource_owner_confirm_scopes_sub,
#     verify_client_cb             => $verify_client_sub,
#     store_auth_code_cb           => $store_auth_code_sub,
#     verify_auth_code_cb          => $verify_auth_code_sub,
#     store_access_token_cb        => $store_access_token_sub,
#     verify_access_token_cb       => $verify_access_token_sub,
#     verify_user_password_cb      => $verify_user_password_sub,
#   };
}

1;
