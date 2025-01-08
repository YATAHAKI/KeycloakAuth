package models

import "errors"

var (
	// ErrInvalidToken represents the error that occurs when a token is invalid.
	ErrInvalidToken = errors.New("invalid token")

	// ErrAccessDenied represents the error that occurs when access is denied.
	ErrAccessDenied = errors.New("access denied")

	// ErrValidationToken represents the error that occurs when token validation fails.
	ErrValidationToken = errors.New("token validation failed")

	// ErrUnexpectedSigningMethod represents an error that occurs when the token signing method is unexpected.
	ErrUnexpectedSigningMethod = errors.New("unexpected signing method")
)
