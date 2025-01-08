package keyimpl

import (
	"context"
	"github.com/YATAHAKI/KeycloakAuth/models"
	"github.com/YATAHAKI/KeycloakAuth/provider"
	"github.com/go-playground/validator/v10"
	"github.com/redis/go-redis/v9"
	"log/slog"
)

var _ provider.AuthProvider = (*Provider)(nil)

// Provider implements the AuthProvider interface and provides methods to authenticate, authorize, and manage secure endpoints.
type Provider struct {
	// Config
	config *Config

	// Redis client
	redis *redis.Client

	// Validator
	validate *validator.Validate

	// Map of protected endpoints with roles
	secureEndpoints map[string][]string

	// Logger
	logger *slog.Logger
}

func NewProvider(config *Config, redis *redis.Client, validate *validator.Validate, logger *slog.Logger) *Provider {
	return &Provider{
		config:          config,
		redis:           redis,
		validate:        validate,
		secureEndpoints: make(map[string][]string),
		logger:          logger,
	}
}

// AddSecureEndpoint adds a secure endpoint with the required roles to the secureEndpoints map.
// Parameters:
// - endpoint: the path of the endpoint
// - roles: list of roles required for access
func (p *Provider) AddSecureEndpoint(endpoint string, roles ...string) {
	p.secureEndpoints[endpoint] = roles
}

// IsSecureEndpoint checks if the specified endpoint is protected.
// Returns true if the endpoint is secured, otherwise false.
// Parameters:
// - endpoint: endpoint path.
func (p *Provider) IsSecureEndpoint(endpoint string) bool {
	_, ok := p.secureEndpoints[endpoint]
	return ok
}

// Authorize authorizes the user based on the passed token and endpoint path.
// Checks the validity of the token and whether the user has the necessary roles for access.
// Parameters:
// - path: path of the protected endpoint
// - tokenString: string with user's JWT token
// Returns user and error (if any).
func (p *Provider) Authorize(ctx context.Context, path string, tokenString string) (models.User, error) {
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
		Roles:      claims.ResourceAccess.RealmManagement.Roles,
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
	if !p.IsUserHaveRoles(neededRoles, claims.ResourceAccess.RealmManagement.Roles) {
		p.logger.Error("User data", slog.Any("User", user))
		p.logger.Error(
			"User doesn't have needed roles",
			slog.Any("User roles", claims.ResourceAccess.RealmManagement.Roles),
			slog.Any("Needed Roles", neededRoles),
		)
		return user, models.ErrAccessDenied
	}

	return user, nil
}
