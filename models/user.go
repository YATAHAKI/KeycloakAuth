package models

// User represents the user of the system with their roles and personal information.
type User struct {
	// Roles contains a list of roles assigned to the user.
	Roles []string

	// UserID - unique user identifier.
	UserID string

	// Email - the user's email.
	Email string

	// Username - the username used to log in.
	Username string

	// Name - user name.
	Name string

	// FamilyName - user's last name.
	FamilyName string
}
