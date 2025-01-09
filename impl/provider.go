// Package keyimpl Package auth provides authentication and authorization mechanisms for both HTTP and gRPC services.
package keyimpl

import (
	"context"
	"fmt"
	"github.com/YATAHAKI/KeycloakAuth/models"
	"github.com/YATAHAKI/KeycloakAuth/provider"
	"github.com/go-playground/validator/v10"
	"github.com/redis/go-redis/v9"
	"log/slog"
	"os"
)

var _ provider.AuthProvider = (*Provider)(nil)

// Provider implements the AuthProvider interface and manages authentication and authorization
// for both HTTP and gRPC services. It supports role-based access control and maintains
// a registry of protected endpoints.
type Provider struct {
	// Config
	config *Config

	// Redis client
	redis *redis.Client

	// Validator
	validate *validator.Validate

	// Map of protected endpoints with their associated roles
	secureEndpoints map[string][]string

	// Type of the provider (HTTP or gRPC)
	providerType models.ProviderType

	// Logger
	logger *slog.Logger
}

// NewGRPCProvider creates and initializes a new Provider instance configured for gRPC endpoints.
// It sets up the necessary components for gRPC-specific authentication and authorization.
//
// Parameters:
//   - config: Configuration settings for the provider
//   - redis: Redis client for token management
//
// Returns:
//   - *Provider: A new Provider instance configured for gRPC
//
// Example:
//
//	provider := NewGRPCProvider(config, redisClient)
//	provider.RegisterEndpoint(EndpointRule{
//	    Path:  "/package.service/Method",
//	    Roles: []string{"admin"},
//	})
func NewGRPCProvider(config *Config, redis *redis.Client) *Provider {
	return &Provider{
		config:          config,
		redis:           redis,
		validate:        validator.New(),
		secureEndpoints: make(map[string][]string),
		providerType:    models.GRPCProvider,
		logger:          slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}
}

// NewHTTPProvider creates and initializes a new Provider instance configured for HTTP endpoints.
// It sets up the necessary components for HTTP-specific authentication and authorization.
//
// Parameters:
//   - config: Configuration settings for the provider
//   - redis: Redis client for token management
//
// Returns:
//   - *Provider: A new Provider instance configured for HTTP
//
// Example:
//
//	provider := NewHTTPProvider(config, redisClient)
//	provider.RegisterEndpoint(EndpointRule{
//	    Method: "GET",
//	    Path:   "/api/users",
//	    Roles:  []string{"admin"},
//	})
func NewHTTPProvider(config *Config, redis *redis.Client) *Provider {
	return &Provider{
		config:          config,
		redis:           redis,
		validate:        validator.New(),
		secureEndpoints: make(map[string][]string),
		providerType:    models.HTTPProvider,
		logger:          slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}
}

// RegisterEndpoint registers a secure endpoint with associated roles
func (p *Provider) RegisterEndpoint(rules ...models.EndpointInfo) error {
	for _, rule := range rules {
		switch p.providerType {
		case models.HTTPProvider:
			key := fmt.Sprintf("%s:%s", rule.Method, rule.Path)
			p.secureEndpoints[key] = rule.Roles
			return nil
		case models.GRPCProvider:
			p.secureEndpoints[rule.Path] = rule.Roles
			return nil
		default:
			return fmt.Errorf("unknown provider type")
		}
	}
	return nil
}

// IsSecureEndpoint checks if the provided endpoint (path and method) is registered as a secure endpoint.
// It verifies if the endpoint is present in the secureEndpoints map depending on the provider type (HTTP or gRPC).
// For HTTP providers, it checks using a combination of path and method as the key.
// For gRPC providers, it checks using only the path as the key.
// Parameters:
// - rule: models.EndpointInfo containing the path, method (for HTTP), and associated roles for the endpoint.
// Returns:
// - true if the endpoint is registered as secure, false otherwise.
func (p *Provider) IsSecureEndpoint(rule models.SecureEndpoint) bool {
	switch p.providerType {
	case models.HTTPProvider:
		key := fmt.Sprintf("%s:%s", rule.Method, rule.Path)
		_, ok := p.secureEndpoints[key]
		return ok
	case models.GRPCProvider:
		_, ok := p.secureEndpoints[rule.Path]
		return ok
	default:
		return false
	}
}

// AuthorizeGRPC authorizes the user based on the passed token and endpoint path.
// Checks the validity of the token and whether the user has the necessary roles for access.
// Parameters:
// - path: path of the protected endpoint
// - tokenString: string with user's JWT token
// Returns user and error (if any).
func (p *Provider) AuthorizeGRPC(ctx context.Context, path, tokenString string) (models.User, error) {
	token, err := p.VerifyToken(ctx, tokenString)
	if err != nil {
		p.logger.Error("Failed to verify token", slog.String("err", err.Error()))
		return models.User{}, models.ErrInvalidToken
	}

	claims, ok := token.Claims.(*models.Claims)
	if !(ok && token.Valid) {
		p.logger.Error("Failed to get claims from token")
		return models.User{}, models.ErrInvalidToken
	}

	if claims.Subject == "" {
		p.logger.Error("Failed to get sub claims from token")
		return models.User{}, models.ErrInvalidToken
	}

	if err = p.validate.Var(claims.Subject, "uuid4"); err != nil {
		p.logger.Error("Failed to validate sub claim", slog.String("err", err.Error()))
		return models.User{}, models.ErrInvalidToken
	}

	user := models.User{
		Roles:      claims.ResourceAccess.Client.Roles,
		UserID:     claims.Subject,
		Email:      claims.Email,
		Username:   claims.PreferredUsername,
		Name:       claims.Name,
		FamilyName: claims.FamilyName,
	}

	neededRoles := p.secureEndpoints[path]
	if len(neededRoles) == 0 {
		neededRoles = []string{}
	}
	if !p.IsUserHaveRoles(neededRoles, claims.ResourceAccess.Client.Roles) {
		p.logger.Error("User data", slog.Any("User", user))
		p.logger.Error(
			"User doesn't have needed roles",
			slog.Any("User roles", claims.ResourceAccess.Client.Roles),
			slog.Any("Needed Roles", neededRoles),
		)
		return user, models.ErrAccessDenied
	}

	return user, nil
}

// AuthorizeHTTP authorizes the user based on the passed token, HTTP method, and endpoint path.
// Checks the validity of the token and whether the user has the necessary roles for access.
// Parameters:
// - method: HTTP method (e.g., "GET", "POST", "PUT", "DELETE").
// - path: path of the protected endpoint (e.g., "/api/v1/user").
// - tokenString: string with the user's JWT token.
// Returns user and error (if any).
func (p *Provider) AuthorizeHTTP(ctx context.Context, method, path, tokenString string) (models.User, error) {
	token, err := p.VerifyToken(ctx, tokenString)
	if err != nil {
		p.logger.Error("Failed to verify token", slog.String("err", err.Error()))
		return models.User{}, models.ErrInvalidToken
	}

	claims, ok := token.Claims.(*models.Claims)
	if !(ok && token.Valid) {
		p.logger.Error("Failed to get claims from token")
		return models.User{}, models.ErrInvalidToken
	}

	if claims.Subject == "" {
		p.logger.Error("Failed to get sub claims from token")
		return models.User{}, models.ErrInvalidToken
	}

	if err = p.validate.Var(claims.Subject, "uuid4"); err != nil {
		p.logger.Error("Failed to validate sub claim", slog.String("err", err.Error()))
		return models.User{}, models.ErrInvalidToken
	}

	user := models.User{
		Roles:      claims.ResourceAccess.Client.Roles,
		UserID:     claims.Subject,
		Email:      claims.Email,
		Username:   claims.PreferredUsername,
		Name:       claims.Name,
		FamilyName: claims.FamilyName,
	}

	key := fmt.Sprintf("%s:%s", method, path)
	neededRoles := p.secureEndpoints[key]
	if len(neededRoles) == 0 {
		neededRoles = []string{}
	}
	if !p.IsUserHaveRoles(neededRoles, claims.ResourceAccess.Client.Roles) {
		p.logger.Error("User data", slog.Any("User", user))
		p.logger.Error(
			"User doesn't have needed roles",
			slog.Any("User roles", claims.ResourceAccess.Client.Roles),
			slog.Any("Needed Roles", neededRoles),
		)
		return user, models.ErrAccessDenied
	}

	return user, nil
}
