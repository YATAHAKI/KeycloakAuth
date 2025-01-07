package keyimpl

import (
	"encoding/json"
	"github.com/lestrrat-go/jwx/jwk"
	"log/slog"
)

func (p *Provider) SerializeJwkSet(key jwk.Set) (string, error) {
	serializedKey, err := json.Marshal(key)
	if err != nil {
		p.logger.Error("Failed to serialize JWK set", slog.String("err", err.Error()))
		return "", err
	}

	return string(serializedKey), nil
}

func (p *Provider) DeserializeJwkSet(serializedJwkSet string) (jwk.Set, error) {
	keySet, err := jwk.Parse([]byte(serializedJwkSet))
	if err != nil {
		p.logger.Error("Failed to deserialize JWK set", slog.String("err", err.Error()))
		return nil, err
	}

	return keySet, nil
}
