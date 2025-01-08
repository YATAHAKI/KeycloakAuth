// Package models contains structures and methods for working with JWT claims and their deserialization.
package models

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
)

// Claims represents the standard and additional fields that may be present in a JWT token.
type Claims struct {
	// RegisteredClaims contains standard JWT fields (e.g., exp, iss, sub, etc.).
	jwt.RegisteredClaims

	// Typ is the type of the token.
	Typ string `json:"typ,omitempty"`

	// Azp is the authorized party for the token.
	Azp string `json:"azp,omitempty"`

	// AuthTime is the time of authentication in UNIX format.
	AuthTime int `json:"auth_time,omitempty"`

	// Acr is the authentication context class reference.
	Acr string `json:"acr,omitempty"`

	// AllowedOrigins is a list of allowed origins for requests.
	AllowedOrigins []string `json:"allowed-origins,omitempty"`

	// RealmAccess represents access to resources related to the realm.
	RealmAccess RealmAccess `json:"realm_access,omitempty"`

	// ResourceAccess represents access to resources.
	ResourceAccess ResourceAccess `json:"resource_access,omitempty"`

	// Scope is the scope of the token.
	Scope string `json:"scope,omitempty"`

	// EmailVerified indicates if the email is verified.
	EmailVerified bool `json:"email_verified,omitempty"`

	// Name is the user's full name.
	Name string `json:"name,omitempty"`

	// PreferredUsername is the preferred username of the user.
	PreferredUsername string `json:"preferred_username,omitempty"`

	// GivenName is the user's given name.
	GivenName string `json:"given_name,omitempty"`

	// FamilyName is the user's family name.
	FamilyName string `json:"family_name,omitempty"`

	// Email is the user's email address.
	Email string `json:"email,omitempty"`
}

// RealmAccess represents the roles available in the realm.
type RealmAccess struct {
	Roles []string `json:"roles,omitempty"`
}

// ResourceAccess represents access to specific resources.
type ResourceAccess struct {
	// RealmManagement represents the roles for realm management.
	RealmManagement RealmManagement `json:"realm-management,omitempty"`

	// Account represents the roles for the account resource.
	Account Account `json:"account,omitempty"`

	// Client represents the roles for the client resource.
	Client Client `json:"omitempty"`

	// ClientID is the ID of the client.
	ClientID string `json:"-"`
}

// UnmarshalJSON implements custom JSON deserialization for ResourceAccess.
func (r *ResourceAccess) UnmarshalJSON(bytes []byte) error {
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(bytes, &rawMap); err != nil {
		return fmt.Errorf("cannot unmarshal json object: %w", err)
	}

	for key, value := range rawMap {
		switch key {
		case "realm-management":
			if err := json.Unmarshal(value, &r.RealmManagement); err != nil {
				return fmt.Errorf("cannot unmarshal realm-management object: %w", err)
			}
		case "account":
			if err := json.Unmarshal(value, &r.Account); err != nil {
				return fmt.Errorf("cannot unmarshal account object: %w", err)
			}
		case r.ClientID:
			if err := json.Unmarshal(value, &r.Client); err != nil {
				return fmt.Errorf("cannot unmarshal client object: %w", err)
			}
		}
	}

	return nil
}

// RealmManagement represents the roles for realm management.
type RealmManagement struct {
	// Roles is a list of roles for realm management.
	Roles []string `json:"roles,omitempty"`
}

// Account represents the roles for the account resource.
type Account struct {
	// Roles is a list of roles for the account resource.
	Roles []string `json:"roles,omitempty"`
}

// Client represents the roles for a specific client.
type Client struct {
	// Roles is a list of roles for the client resource.
	Roles []string `json:"roles,omitempty"`
}
