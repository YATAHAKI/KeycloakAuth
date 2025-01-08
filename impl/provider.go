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

type Provider struct {
	config          *Config
	redis           *redis.Client
	validate        *validator.Validate
	secureEndpoints map[string][]string
	logger          *slog.Logger
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

func (p *Provider) AddSecureEndpoint(endpoint string, roles ...string) {
	p.secureEndpoints[endpoint] = roles
}

func (p *Provider) IsSecureEndpoint(endpoint string) bool {
	_, ok := p.secureEndpoints[endpoint]
	return ok
}

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
