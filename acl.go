package redis_acl

type ACLUser struct {
	Name               string   `json:"name"`
	Cluster            string   `json:"cluster"`
	Enabled            bool     `json:"enabled"`
	Passwords          []string `json:"passwords"`
	AllowedKeys        []string `json:"allowed_keys"`
	AllowedChannels    []string `json:"allowed_channels"`
	AllowedCommands    []string `json:"allowed_commands"`
	DisallowedKeys     []string `json:"disallowed_keys"`
	DisallowedChannels []string `json:"disallowed_channels"`
	DisallowedCommands []string `json:"disallowed_commands"`
}

func parseACLUser(s string) (*ACLUser, error) {
	// "user default on nopass ~* &* +@all"
	return nil, nil
}
