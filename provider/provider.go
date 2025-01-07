package provider

import (
	"context"
	"github.com/YATAHAKI/KeycloakAuth/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/jwk"
)

const UserDetailsKey = "UserDetails"

type AuthProvider interface {
	VerifyToken(ctx context.Context, tokenString string) (*jwt.Token, error)
	KeyFunc(ctx context.Context) jwt.Keyfunc
	FetchJWKSet(ctx context.Context) (jwk.Set, error)
	IsUserHaveRoles(roles []string, userRoles []string) bool
	SerializeJwkSet(key jwk.Set) (string, error)
	DeserializeJwkSet(serializedJwkSet string) (jwk.Set, error)
	Authorize(ctx context.Context, path string, tokenString string) (models.User, error)
	IsSecureEndpoint(endpoint string) bool
	AddSecureEndpoint(endpoint string, roles ...string)
}
