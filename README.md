# Keycloak Auth Library

A library for integrating with Keycloak, providing functionalities for authentication and authorization.

---

## Features

- Verify JWT tokens.
- Fetch and manage JWK (JSON Web Key) sets.
- Role-based access control.
- Serialize and deserialize JWK sets.
- Define and check secure endpoints.

---

## Installation

Install the library using `go get`:

```bash
go get github.com/YATAHAKI/KeycloakAuth
```

---

## Usage

### Simple config
```yaml
keycloak:
  public_jwk_uri: http://localhost:8180/realms/example-client/protocol/openid-connect/certs
  client_id: example-client
  refresh_jwk_timeout: 12h # optional/default 3h
```

### Verify a Token

```go
ctx := context.Background()g
token, err := authProvider.VerifyToken(ctx, "your-jwt-token")
if err != nil {
    log.Fatalf("Token verification failed: %v", err)
}
fmt.Println("Verified token:", token)
```

### Add and Check Secure Endpoints

```go
authProvider.AddSecureEndpoint("/admin", "admin", "superuser")
if authProvider.IsSecureEndpoint("/admin") {
    fmt.Println("/admin is a secure endpoint")
}
```

### Authorize a User

```go
ctx := context.Background()
user, err := authProvider.Authorize(ctx, "/profile", "your-jwt-token")
if err != nil {
    log.Fatalf("Authorization failed: %v", err)
}
fmt.Println("Authorized user:", user)
```

### Example: gRPC Interceptor

You can use the library to integrate with gRPC by implementing an interceptor for authentication and authorization. Check out the example in the [Examples](./examples) directory for more details.

---

## API Reference

### `AuthProvider`

#### `VerifyToken`
```go
VerifyToken(ctx context.Context, tokenString string) (*jwt.Token, error)
```
Verifies the provided JWT token.

---

#### `KeyFunc`
```go
KeyFunc(ctx context.Context) jwt.Keyfunc
```
Returns a key function used for JWT token parsing and verification.

---

#### `FetchJWKSet`
```go
FetchJWKSet(ctx context.Context) (jwk.Set, error)
```
Fetches the JWK (JSON Web Key) set from a Keycloak server.

---

#### `IsUserHaveRoles`
```go
IsUserHaveRoles(roles []string, userRoles []string) bool
```
Checks if the user has at least one of the specified roles.

---

#### `SerializeJwkSet`
```go
SerializeJwkSet(key jwk.Set) (string, error)
```
Serializes a JWK set into a string.

---

#### `DeserializeJwkSet`
```go
DeserializeJwkSet(serializedJwkSet string) (jwk.Set, error)
```
Deserializes a JWK set from a string.

---

#### `Authorize`
```go
Authorize(ctx context.Context, path string, tokenString string) (models.User, error)
```
Authorizes a user based on the provided token and endpoint path.

---

#### `IsSecureEndpoint`
```go
IsSecureEndpoint(endpoint string) bool
```
Checks if an endpoint is secure.

---

#### `AddSecureEndpoint`
```go
AddSecureEndpoint(endpoint string, roles ...string)
```
Adds a secure endpoint with specified roles.

---

## License

This library is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.

---

## Contributing

Contributions are welcome! Please open an issue or submit a pull request to contribute.

