package models

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestResourceAccess_MarshalJSON(t *testing.T) {
	test := []struct {
		name     string
		input    []byte
		expected *ResourceAccess
		isFail   bool
	}{
		{
			name: "Valid JSON with dynamic key",
			input: []byte(`{
				"realm-management": {"roles": ["view-users"]},
				"account": {"roles": ["manage-account"]},
				"aibolit-api": {"roles": ["user"]}
			}`),
			expected: &ResourceAccess{
				RealmManagement: RealmManagement{Roles: []string{"view-users"}},
				Account:         Account{Roles: []string{"manage-account"}},
				Client:          Client{Roles: []string{"user"}},
				ClientID:        "aibolit-api",
			},
			isFail: false,
		},
		{
			name: "Valid JSON with missing dynamic key",
			input: []byte(`{
				"realm-management": {"roles": ["view-users"]},
				"account": {"roles": ["manage-account"]}
			}`),
			expected: &ResourceAccess{
				RealmManagement: RealmManagement{Roles: []string{"view-users"}},
				Account:         Account{Roles: []string{"manage-account"}},
				Client:          Client{},
				ClientID:        "",
			},
			isFail: false,
		},
		{
			name:  "Empty JSON",
			input: []byte(`{}`),
			expected: &ResourceAccess{
				RealmManagement: RealmManagement{},
				Account:         Account{},
				Client:          Client{},
				ClientID:        "",
			},
			isFail: false,
		},
	}

	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			ra := ResourceAccess{
				ClientID: tt.expected.ClientID,
			}
			err := json.Unmarshal(tt.input, &ra)

			if tt.isFail {
				require.Error(t, err, "Expected error but got nil")
			}

			require.NoError(t, err)

			assert.Equal(t, tt.expected, &ra, "error")
		})
	}
}
