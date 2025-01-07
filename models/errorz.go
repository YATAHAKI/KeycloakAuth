package models

import "errors"

var (
	ErrInvalidToken            = errors.New("invalid token")
	ErrAccessDenied            = errors.New("access denied")
	ErrValidationToken         = errors.New("token validation failed")
	ErrJwkNotFound             = errors.New("jwk not found")
	ErrUnexpectedSigningMethod = errors.New("unexpected signing method")
)
