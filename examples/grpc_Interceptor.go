package examples

import (
	"context"
	"github.com/YATAHAKI/KeycloakAuth/models"
	"github.com/YATAHAKI/KeycloakAuth/provider"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"log/slog"
	"strings"
)

func NewAuthInterceptor(auth provider.AuthProvider, logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if !auth.IsSecureEndpoint(models.SecureEndpoint{
			Path: info.FullMethod,
		}) {
			logger.Info("Endpoint not protected", slog.String("method", info.FullMethod))
			return handler(ctx, req)
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			logger.Error("Failed to get metadata", slog.String("method", info.FullMethod))
			return nil, status.Error(codes.Unauthenticated, "Failed to get metadata")
		}

		authHeader, ok := md["authorization"]
		if !ok || len(authHeader) == 0 {
			logger.Error("Failed to get authorization header", slog.String("method", info.FullMethod))
			return nil, status.Error(codes.Unauthenticated, "Failed to get authorization header")
		}

		token := strings.TrimPrefix(authHeader[0], "Bearer ")
		if token == authHeader[0] {
			logger.Error("Incorrect authorization token", slog.String("method", info.FullMethod))
			return nil, status.Error(codes.Unauthenticated, "Incorrect authorization token")
		}

		user, err := auth.AuthorizeGRPC(ctx, info.FullMethod, token)
		if err != nil {
			logger.Error("Authorization failed", "method", info.FullMethod, "error", err)
			return nil, status.Error(codes.PermissionDenied, "Authorization failed")
		}

		logger.Info("Authorization succeeded", "method", info.FullMethod, "user", user.Username)

		ctx = context.WithValue(ctx, provider.UserDetailsKey, user)
		resp, err := handler(ctx, req)
		if err != nil {
			logger.Error("Failed to call handler", "method", info.FullMethod, "error", err)
			return nil, err
		}

		logger.Info("Call success", "method", info.FullMethod, "user", user.Username)
		return resp, nil
	}
}
