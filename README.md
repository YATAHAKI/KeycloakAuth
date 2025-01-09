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

There's also official documentation - [docs](https://pkg.go.dev/github.com/YATAHAKI/KeycloakAuth)

### Simple config
```yaml
keycloak:
  public_jwk_uri: http://localhost:8180/realms/example-client/protocol/openid-connect/certs
  client_id: example-client
  refresh_jwk_timeout: 12h # optional/default 3h
```






### Example: gRPC Interceptor

You can use the library to integrate with gRPC by implementing an interceptor for authentication and authorization. Check out the example in the [Examples](./examples) directory for more details.

---

## License

This library is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.

---

## Contributing

Contributions are welcome! Please open an issue or submit a pull request to contribute.

