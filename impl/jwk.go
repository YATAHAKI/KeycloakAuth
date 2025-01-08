package keyimpl

import (
	"context"
	"github.com/lestrrat-go/jwx/jwk"
)

// Redis key
const _jwkSet = "jwk-set"

// FetchJWKSet retrieves the JWK (JSON Web Key) set from the Redis cache or requests it from a remote server.
// If the JWK is already in the cache, it is deserialized and returned. If the JWK is not in the cache, it is loaded
// from the remote server and then stored in the cache for future requests.
func (p *Provider) FetchJWKSet(ctx context.Context) (jwk.Set, error) {
	result, err := p.redis.Get(ctx, _jwkSet).Result()
	if err == nil {
		p.logger.Info("Getting Jwk from cache")
		resultSet, err := p.DeserializeJwkSet(result)
		if err != nil {
			return nil, err
		}
		return resultSet, nil
	}

	resultSet, err := jwk.Fetch(ctx, p.config.PublicJWKUri)
	if err != nil {
		return nil, err
	}

	p.logger.Info("Fetching Jwk from remote")
	serializedKeySet, err := p.SerializeJwkSet(resultSet)
	if err != nil {
		return nil, err
	}

	if err = p.redis.Set(ctx, _jwkSet, serializedKeySet, p.config.RefreshJWKTimeout).Err(); err != nil {
		return nil, err
	}

	return resultSet, nil
}
