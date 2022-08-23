package redis_acl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseACLListUser(t *testing.T) {
	user, err := ParseACLListUser("user default on nopass ~* &* +@all")
	assert.NoError(t, err)
	assert.Equal(t, ACLUser{
		Cluster:              "",
		Name:                 "default",
		Flags:                []string{"allchannels", "allcommands", "allkeys", "on"},
		Enabled:              true,
		NoPass:               true,
		Passwords:            nil,
		PasswordHashes:       nil,
		Commands:             "",
		Keys:                 []string{"*"},
		Channels:             []string{"*"},
		AllowedCommands:      nil,
		AllowedCategories:    []string{"@all"},
		DisallowedCommands:   nil,
		DisallowedCategories: nil,
	}, *user)

	user, err = ParseACLListUser("user easton off >p@ssw0rd ~sensitive-keys:* resetchannels &eventchannels* +@admin")
	assert.NoError(t, err)
	assert.Equal(t, ACLUser{
		Cluster:              "",
		Name:                 "easton",
		Flags:                []string{"off"},
		Enabled:              false,
		NoPass:               false,
		Passwords:            []string{"p@ssw0rd"},
		PasswordHashes:       []string{"a075d17f3d453073853f813838c15b8023b8c487038436354fe599c3942e1f95"},
		Commands:             "",
		Keys:                 []string{"~sensitive-keys:*"},
		Channels:             []string{"eventchannels*"},
		AllowedCommands:      nil,
		AllowedCategories:    []string{"@admin"},
		DisallowedCommands:   nil,
		DisallowedCategories: []string{"@all"},
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
		PasswordHashes: []string{
			"8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",
		},
		Commands:             "-@all +@admin",
		Keys:                 []string{"*"},
		Channels:             []string{"*"},
		AllowedCommands:      nil,
		AllowedCategories:    nil,
		DisallowedCommands:   nil,
		DisallowedCategories: nil,
	}, *user)
}

func TestACLUserString(t *testing.T) {
	user := ACLUser{
		Cluster:              "",
		Name:                 "easton",
		Flags:                []string{"on", "allchannels"},
		Enabled:              true,
		NoPass:               false,
		Passwords:            []string{"pass1"},
		PasswordHashes:       nil,
		Commands:             "+@all",
		Keys:                 []string{"key1"},
		Channels:             nil,
		AllowedCommands:      nil,
		AllowedCategories:    nil,
		DisallowedCommands:   nil,
		DisallowedCategories: nil,
	}
	assert.Equal(t, "easton on >pass1 ~key1 &* +@all",
		user.String(true))

	user = ACLUser{
		Cluster:              "",
		Name:                 "easton",
		Flags:                []string{"off", "allkeys", "allcommands"},
		Enabled:              false,
		NoPass:               true,
		Passwords:            []string{"pass1"},
		PasswordHashes:       nil,
		Commands:             "-@keys",
		Keys:                 []string{"key1"},
		Channels:             []string{"channel1"},
		AllowedCommands:      nil,
		AllowedCategories:    nil,
		DisallowedCommands:   nil,
		DisallowedCategories: nil,
	}
	assert.Equal(t, "easton off nopass ~* resetchannels &channel1 +@all",
		user.String(true))
}
