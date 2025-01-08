package provider

import (
	"context"
	"github.com/YATAHAKI/KeycloakAuth/models"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/jwk"
)

// UserDetailsKey is the key used for storing user details in the context.
const UserDetailsKey = "UserDetails"

// AuthProvider defines the methods required for authentication and authorization.
type AuthProvider interface {
	// VerifyToken validates a JWT token string and returns the parsed token or an error.
	// ctx - The context for the operation.
	// tokenString - The JWT token string to verify.
	// Returns the parsed JWT token or an error if verification fails.
	VerifyToken(ctx context.Context, tokenString string) (*jwt.Token, error)

	// KeyFunc returns the key function used for verifying JWT tokens.
	// ctx - The context for the operation.
	// Returns a JWT key function.
	KeyFunc(ctx context.Context) jwt.Keyfunc

	// FetchJWKSet fetches the JSON Web Key Set (JWK Set) used for JWT verification.
	// ctx - The context for the operation.
	// Returns the JWK Set or an error if fetching fails.
	FetchJWKSet(ctx context.Context) (jwk.Set, error)

	// IsUserHaveRoles checks whether the user has the required roles.
	// roles - The required roles for the user.
	// userRoles - The roles assigned to the user.
	// Returns true if the user has the required roles, false otherwise.
	IsUserHaveRoles(roles []string, userRoles []string) bool

	// SerializeJwkSet serializes the JWK Set to a string.
	// key - The JWK Set to serialize.
	// Returns the serialized JWK Set string or an error.
	SerializeJwkSet(key jwk.Set) (string, error)

	// DeserializeJwkSet deserializes a JWK Set from a string.
	// serializedJwkSet - The serialized JWK Set string.
	// Returns the deserialized JWK Set or an error.
	DeserializeJwkSet(serializedJwkSet string) (jwk.Set, error)

	// Authorize checks if a user is authorized to access a given path with the provided JWT token.
	// ctx - The context for the operation.
	// path - The path the user is trying to access.
	// tokenString - The JWT token string for the user.
	// Returns the user details if authorized, or an error if not authorized.
	Authorize(ctx context.Context, path string, tokenString string) (models.User, error)

	// IsSecureEndpoint checks if an endpoint requires security and authentication.
	// endpoint - The endpoint to check.
	// Returns true if the endpoint requires security, false otherwise.
	IsSecureEndpoint(endpoint string) bool

	// AddSecureEndpoint adds an endpoint to the list of secure endpoints and associates it with specified roles.
	// endpoint - The endpoint to secure.
	// roles - The roles required to access the endpoint.
	AddSecureEndpoint(endpoint string, roles ...string)
}
