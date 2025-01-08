package keyimpl

import (
	"github.com/ilyakaznacheev/cleanenv"
	"time"
)

// Config contains the configuration for the authentication provider,
// including the URI for the public JWK, the timeout for updating the JWK, and the client ID.
type Config struct {
	// PublicJWKUri - URI to get the public JWK.
	// Must be set in the configuration (environment variables or file).
	PublicJWKUri string `env:"PUBLIC_JWK_URI" json:"public_jwk_uri" yaml:"public_jwk_uri" validate:"required"`

	// RefreshJWKTimeout - timeout for JWK refresh.
	// If not specified, the default value of 3 hours is used.
	RefreshJWKTimeout time.Duration `env:"REFRESH_JWK_TIMEOUT" json:"refresh_jwk_timeout" yaml:"refresh_jwk_timeout" env-default:"3h"`

	// ClientID - client identifier for authentication.
	// Must be specified in the configuration (environment variables or file).
	ClientID string `env:"CLIENT_ID" json:"client_id" yaml:"client_id" validate:"required"`
}

// LoadConfig loads the configuration from the “config.yaml” file or from environment variables.
// Load priority: first from the file, then from environment variables.
// The configuration must match the Config structure and use the “KEYCLOAK_” prefix for environment variables.
func LoadConfig() (*Config, error) {
	var cfg struct {
		Config Config `env-prefix:"KEYCLOAK_" yaml:"keycloak" json:"keycloak"`
	}
	if err := cleanenv.ReadConfig("config.yaml", &cfg); err != nil {
		if err = cleanenv.ReadEnv(&cfg); err != nil {
			return nil, err
		}
	}

	return &cfg.Config, nil
}
