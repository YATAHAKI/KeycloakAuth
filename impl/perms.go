package keyimpl

import "slices"

// IsUserHaveRoles checks if the user has at least one of the required roles.
func (p *Provider) IsUserHaveRoles(roles []string, userRoles []string) bool {
	if len(roles) == 0 {
		return true
	}

	for _, role := range roles {
		if slices.Contains(userRoles, role) {
			return true
		}
	}

	return false
}
