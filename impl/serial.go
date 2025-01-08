package keyimpl

import (
	"encoding/json"
	"github.com/lestrrat-go/jwx/jwk"
	"log/slog"
)

// SerializeJwkSet serializes a JWK Set into a JSON string.
func (p *Provider) SerializeJwkSet(key jwk.Set) (string, error) {
	serializedKey, err := json.Marshal(key)
	if err != nil {
		p.logger.Error("Failed to serialize JWK set", slog.String("err", err.Error()))
		return "", err
	}

	return string(serializedKey), nil
}

// DeserializeJwkSet deserializes a JSON string back to a JWK Set.
// In case of an error, returns nil and an error.
func (p *Provider) DeserializeJwkSet(serializedJwkSet string) (jwk.Set, error) {
	keySet, err := jwk.Parse([]byte(serializedJwkSet))
	if err != nil {
		p.logger.Error("Failed to deserialize JWK set", slog.String("err", err.Error()))
		return nil, err
	}

	return keySet, nil
}
