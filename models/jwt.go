package models

import "github.com/golang-jwt/jwt/v5"

type Claims struct {
	jwt.RegisteredClaims
	Typ               string         `json:"typ,omitempty"`
	Azp               string         `json:"azp,omitempty"`
	AuthTime          int            `json:"auth_time,omitempty"`
	Acr               string         `json:"acr,omitempty"`
	AllowedOrigins    []string       `json:"allowed-origins,omitempty"`
	RealmAccess       RealmAccess    `json:"realm_access,omitempty"`
	ResourceAccess    ResourceAccess `json:"resource_access,omitempty"`
	Scope             string         `json:"scope,omitempty"`
	EmailVerified     bool           `json:"email_verified,omitempty"`
	Name              string         `json:"name,omitempty"`
	PreferredUsername string         `json:"preferred_username,omitempty"`
	GivenName         string         `json:"given_name,omitempty"`
	FamilyName        string         `json:"family_name,omitempty"`
	Email             string         `json:"email,omitempty"`
}

type RealmAccess struct {
	Roles []string `json:"roles,omitempty"`
}

type ResourceAccess struct {
	RealmManagement RealmManagement `json:"realm-management,omitempty"`
	Account         Account         `json:"account,omitempty"`
}

type RealmManagement struct {
	Roles []string `json:"roles,omitempty"`
}

type Account struct {
	Roles []string `json:"roles,omitempty"`
}
