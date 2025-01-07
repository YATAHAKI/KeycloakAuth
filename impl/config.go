package keyimpl

import (
	"github.com/ilyakaznacheev/cleanenv"
	"time"
)

type Config struct {
	PublicJWKUri      string        `env:"PUBLIC_JWK_URI" json:"public_jwk_uri" yaml:"public_jwk_uri" validate:"required"`
	RefreshJWKTimeout time.Duration `env:"REFRESH_JWK_TIMEOUT" json:"refresh_jwk_timeout" yaml:"refresh_jwk_timeout" env-default:"3h"`
	ClientID          string        `env:"CLIENT_ID" json:"client_id" yaml:"client_id" validate:"required"`
}

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
