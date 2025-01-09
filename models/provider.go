package models

// ProviderType represents the type of service the Provider will authenticate.
type ProviderType int

const (
	// HTTPProvider indicates the Provider is configured for HTTP service authentication.
	HTTPProvider ProviderType = iota + 1

	// GRPCProvider indicates the Provider is configured for gRPC service authentication.
	GRPCProvider
)

// EndpointInfo defines the structure for protecting specific endpoints with role-based access control.
// It contains the necessary information to identify and secure an endpoint.
type EndpointInfo struct {
	// Path represents the endpoint path for HTTP routes or the full method name for gRPC services.
	Path string

	// Method specifies the HTTP method (GET, POST, etc.). This field is only used for HTTP endpoints
	// and should be left empty for gRPC endpoints.
	Method string

	// Roles is a list of role names that are allowed to access this endpoint.
	// Users must have at least one of these roles to be granted access.
	Roles []string
}

// SecureEndpoint represents the endpoint details for secure access control.
// It is used to describe both HTTP routes and gRPC services, with different usage depending on the provider type.
//
// Fields:
//
//   - Path: The endpoint path for HTTP routes or the full method name for gRPC services.
//     For HTTP endpoints, this is the URL path (e.g., "/api/users").
//     For gRPC services, this is the full method name (e.g., "/package.service/Method").
//
//   - Method: The HTTP method (GET, POST, etc.) for the request. This field is only used for HTTP endpoints.
//     For gRPC services, this field should be left empty.
type SecureEndpoint struct {
	// Path represents the endpoint path for HTTP routes or the full method name for gRPC services.
	Path string

	// Method specifies the HTTP method (GET, POST, etc.). This field is only used for HTTP endpoints
	// and should be left empty for gRPC endpoints.
	Method string
}
