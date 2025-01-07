package KeycloakAuth

import (
	keyimpl "github.com/YATAHAKI/KeycloakAuth/impl"
	"github.com/YATAHAKI/KeycloakAuth/provider"
	"go.uber.org/fx"
)

var KeycloakModule = fx.Module(
	"auth_keycloak",
	fx.Provide(
		keyimpl.LoadConfig,
		fx.Annotate(
			keyimpl.NewProvider,
			fx.As(new(provider.AuthProvider)),
		),
	),
)
