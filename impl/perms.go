package keyimpl

import "slices"

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
