package provider

import (
	"context"
	"github.com/YATAHAKI/KeycloakAuth/models"
)

// UserDetailsKey is the key used for storing user details in the context.
const UserDetailsKey = "UserDetails"

// AuthProvider defines the methods required for authentication and authorization.
type AuthProvider interface {
	// AuthorizeGRPC checks if a user is authorized to access a given path with the provided JWT token.
	// ctx - The context for the operation.
	// path - The path the user is trying to access.
	// tokenString - The JWT token string for the user.
	// Returns the user details if authorized, or an error if not authorized.
	AuthorizeGRPC(ctx context.Context, path, tokenString string) (models.User, error)

	// AuthorizeHTTP checks if a user is authorized to access a given path with the provided JWT token.
	// ctx - The context for the operation.
	// method - The HTTP method (GET, POST, etc.) for the request.
	// path - The path the user is trying to access.
	// tokenString - The JWT token string for the user.
	// Returns the user details if authorized, or an error if not authorized.
	AuthorizeHTTP(ctx context.Context, method, path, tokenString string) (models.User, error)

	// IsSecureEndpoint checks if an endpoint requires security and authentication.
	// endpoint - The endpoint to check.
	// Returns true if the endpoint requires security, false otherwise.
	IsSecureEndpoint(rule models.SecureEndpoint) bool

	// RegisterEndpoint registers a new protected endpoint with its associated roles.
	// The endpoint registration behavior differs based on the provider type:
	//   - For HTTP: uses both Method and Path to create the endpoint key
	//   - For gRPC: uses only the Path (full method name) as the endpoint key
	//
	// Parameters:
	//   - endpoint: EndpointRule containing the endpoint information and allowed roles
	//
	// Returns:
	//   - error: nil if registration is successful, error otherwise
	//
	// Example for HTTP:
	//
	//	err := provider.RegisterEndpoint(EndpointRule{
	//	    Method: "GET",
	//	    Path:   "/api/users",
	//	    Roles:  []string{"admin"},
	//	})
	//
	// Example for gRPC:
	//
	//	err := provider.RegisterEndpoint(EndpointRule{
	//	    Path:  "/package.service/Method",
	//	    Roles: []string{"admin"},
	//	})
	RegisterEndpoint(rule ...models.EndpointInfo) error
}
