package keyimpl

import (
	"context"
	"github.com/lestrrat-go/jwx/jwk"
)

const _jwkSet = "jwk-set"

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
