package keyimpl

import (
	"context"
	"crypto/rsa"
	"github.com/YATAHAKI/KeycloakAuth/models"
	"github.com/golang-jwt/jwt/v5"
	"log/slog"
)

func (p *Provider) VerifyToken(ctx context.Context, tokenString string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &models.Claims{ResourceAccess: models.ResourceAccess{
		ClientID: p.config.ClientID,
	}}, p.KeyFunc(ctx))
	if err != nil {
		p.logger.Error("Failed to parse token", slog.String("error", err.Error()))
		return nil, models.ErrInvalidToken
	}

	return token, nil
}

func (p *Provider) KeyFunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		var rawKey *rsa.PublicKey

		keySet, err := p.FetchJWKSet(ctx)
		if err != nil {
			p.logger.Error("Failed to fetch JWK Set", slog.String("err", err.Error()))
			return nil, err
		}

		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, models.ErrUnexpectedSigningMethod
		}

		keyID, ok := token.Header["kid"].(string)
		if !ok {
			return nil, models.ErrValidationToken
		}

		key, found := keySet.LookupKeyID(keyID)
		if !found {
			return nil, models.ErrInvalidToken
		}

		if err = key.Raw(rawKey); err != nil {
			p.logger.Error("Failed to get raw key", slog.String("err", err.Error()))
			return nil, models.ErrInvalidToken
		}

		return &rawKey, nil
	}
}
