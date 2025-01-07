package keyimpl

import (
	"context"
	"github.com/YATAHAKI/KeycloakAuth/models"
	"github.com/YATAHAKI/KeycloakAuth/provider"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
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

	claims, ok := token.Claims.(jwt.MapClaims)
	if !(ok && token.Valid) {
		p.logger.Error("Failed to get claims from token")
		return models.User{}, models.ErrInvalidToken
	}

	if claims["sub"] == "" || claims["sub"] == nil {
		p.logger.Error("Failed to get sub claims from token")
		return models.User{}, models.ErrInvalidToken
	}

	if err = p.validate.Var(claims["sub"], "uuid4"); err != nil {
		p.logger.Error("Failed to validate sub claim", slog.String("err", err.Error()))
		return models.User{}, models.ErrInvalidToken
	}

	userRoles := make([]string, 0)
	if resourceAccess, ok := claims["resource_access"].(map[string]interface{}); ok {
		if authClient, ok := resourceAccess[p.config.ClientID].(map[string]interface{}); ok {
			if roles, ok := authClient["roles"].([]interface{}); ok {
				for i := range roles {
					if roleStr, ok := roles[i].(string); ok {
						userRoles = append(userRoles, roleStr)
					}
				}
			}
		}
	}

	userEmail, ok := claims["email"].(string)
	if !ok {
		userEmail = ""
	}

	us := models.User{
		Roles:      userRoles,
		UserID:     claims["sub"].(string),
		Email:      userEmail,
		Username:   claims["preferred_username"].(string),
		Name:       claims["name"].(string),
		FamilyName: claims["family_name"].(string),
	}

	neededRoles := p.secureEndpoints[path]
	if len(neededRoles) == 0 {
		neededRoles = []string{}
	}
	if !p.IsUserHaveRoles(neededRoles, userRoles) {
		p.logger.Error("User data", slog.Any("User", us))
		p.logger.Error("User doesn't have needed roles", slog.Any("User roles", userRoles), slog.Any("Needed Roles", neededRoles))
		return us, models.ErrAccessDenied
	}

	return us, nil
}
