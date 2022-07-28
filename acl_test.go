package redis_acl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseACLListUser(t *testing.T) {
	user, err := parseACLListUser("user default on nopass ~* &* +@all")
	assert.NoError(t, err)
	assert.Equal(t, ACLUser{
		Cluster:                  "",
		Name:                     "default",
		Flags:                    []string{"on", "allkeys", "allchannels"},
		Enabled:                  true,
		NoPass:                   true,
		Passwords:                nil,
		PasswordHash:             nil,
		Commands:                 "",
		Keys:                     []string{"*"},
		Channels:                 []string{"*"},
		AllowedCommands:          nil,
		AllowedCommandCategories: []string{"@all"},
		DisallowedCommands:       nil,
		DisallowedCategories:     nil,
	}, *user)
}

func TestParseACLGetUser(t *testing.T) {
	result := []interface{}{
		"flags",
		[]interface{}{
			"on",
			"allkeys",
			"allchannels",
		},

		"passwords",
		[]interface{}{
			"8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",
		},
		"commands",
		"-@all +@admin",
		"keys",
		[]interface{}{
			"*",
		},
		"channels",
		[]interface{}{
			"*",
		},
	}

	user, err := parseACLGetUser(result)
	assert.NoError(t, err)
	assert.Equal(t, ACLUser{
		Cluster: "",
		Name:    "",
		Flags: []string{
			"on",
			"allkeys",
			"allchannels",
		},
		Enabled:   true,
		NoPass:    false,
		Passwords: nil,
		PasswordHash: []string{
			"8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",
		},
		Commands:                 "-@all +@admin",
		Keys:                     []string{"*"},
		Channels:                 []string{"*"},
		AllowedCommands:          nil,
		AllowedCommandCategories: nil,
		DisallowedCommands:       nil,
		DisallowedCategories:     nil,
	}, *user)
}

func TestACLUserString(t *testing.T) {
	user := ACLUser{
		Cluster:                  "",
		Name:                     "easton",
		Flags:                    []string{"on", "allchannels"},
		Enabled:                  true,
		NoPass:                   false,
		Passwords:                []string{"pass1"},
		PasswordHash:             nil,
		Commands:                 "+@all",
		Keys:                     []string{"key1"},
		Channels:                 nil,
		AllowedCommands:          nil,
		AllowedCommandCategories: nil,
		DisallowedCommands:       nil,
		DisallowedCategories:     nil,
	}
	assert.Equal(t, []string{"easton", "on", ">pass1", "~key1", "&*", "+@all"},
		user.String())

	user = ACLUser{
		Cluster:                  "",
		Name:                     "easton",
		Flags:                    []string{"off", "allkeys", "allcommands"},
		Enabled:                  false,
		NoPass:                   true,
		Passwords:                []string{"pass1"},
		PasswordHash:             nil,
		Commands:                 "-@keys",
		Keys:                     []string{"key1"},
		Channels:                 []string{"channel1"},
		AllowedCommands:          nil,
		AllowedCommandCategories: nil,
		DisallowedCommands:       nil,
		DisallowedCategories:     nil,
	}
	assert.Equal(t, []string{"easton", "off", "nopass", "~*", "resetchannels", "&channel1", "+@all"},
		user.String())
}
