package keyimpl

import (
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
