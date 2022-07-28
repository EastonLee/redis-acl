package redis_acl

import (
	"context"
	"sort"
	"strings"

	"github.com/go-redis/redis/v8"
	"github.com/juju/errors"
	"github.com/thoas/go-funk"
)

/*
 * Selectors are supported from Redis 7
 * https://redis.io/topics/acl#acl-selectors
 * this library does NOT support selectors yet
 */

type ACLUser struct {
	Cluster string `json:"cluster"`

	Name                 string   `json:"name"`
	Flags                []string `json:"flags"`
	Enabled              bool     `json:"enabled"`
	NoPass               bool     `json:"nopass"`
	Passwords            []string `json:"passwords"`
	PasswordHash         []string `json:"password_hash"`
	PasswordsToRemove    []string `json:"passwords_to_remove"`
	PasswordHashToRemove []string `json:"password_hash_to_remove"`
	// Commands in form of "+@all -keys"
	Commands string `json:"commands"`

	Keys     []string `json:"keys"`
	Channels []string `json:"channels"`

	// TODO: maybe unnecessary
	AllowedCommands          []string `json:"allowed_commands"`
	AllowedCommandCategories []string `json:"allowed_categories"`

	DisallowedCommands   []string `json:"disallowed_commands"`
	DisallowedCategories []string `json:"disallowed_categories"`
}

func (u *ACLUser) Consolidate() {
	// TODO: form `Commands` from `Flags`, `AllowedCommands` and `DisallowedCommands`
	u.Commands = ""
}

func (u *ACLUser) String() (rules []string) {
	genRulesWithPrefix := func(ruleList []string, prefix string) []string {
		return funk.Map(ruleList, func(r string) string {
			return prefix + r
		}).([]string)
	}

	rules = append(rules, u.Name)

	if u.Enabled {
		rules = append(rules, "on")
	} else {
		rules = append(rules, "off")
	}

	if u.NoPass {
		rules = append(rules, "nopass")
	} else {
		rules = append(rules, genRulesWithPrefix(u.Passwords, ">")...)
		rules = append(rules, genRulesWithPrefix(u.PasswordHash, "#")...)
		rules = append(rules, genRulesWithPrefix(u.PasswordsToRemove, "<")...)
		rules = append(rules, genRulesWithPrefix(u.PasswordHashToRemove, "!")...)
	}

	if funk.InStrings(u.Flags, "allkeys") {
		rules = append(rules, "~*")
	} else {
		rules = append(rules, genRulesWithPrefix(u.Keys, "~")...)
	}

	if funk.InStrings(u.Flags, "allchannels") {
		rules = append(rules, "&*")
	} else {
		rules = append(rules, "resetchannels")
		rules = append(rules, genRulesWithPrefix(u.Channels, "&")...)
	}

	if funk.InStrings(u.Flags, "allcommands") {
		rules = append(rules, "+@all")
	} else if len(u.Commands) > 0 {
		rules = append(rules, u.Commands)
	}

	// TODO: allowed and disallowed commands and categories
	return rules
}

func parseACLListUser(s string) (*ACLUser, error) {
	// https://redis.io/docs/manual/security/acl/#acl-rules
	// example: "user default on nopass ~* &* +@all"
	user := &ACLUser{}
	segments := strings.Split(s, " ")
	if len(segments) < 7 {
		return nil, errors.Errorf("expected that `ACL LIST` command result contains "+
			"at least 7 segments, but got %v", segments)
	}

	user.Name = segments[1]
	for _, s := range segments {
		switch {
		// enabled
		case s == "on":
			user.Enabled = true
			user.Flags = append(user.Flags, "on")
		case s == "off":
			user.Enabled = false
			user.Flags = append(user.Flags, "off")

		// commands
		case s == "allcommands", s == "+*":
			user.AllowedCommands = append(user.AllowedCommands, "@all")
			user.Flags = append(user.Flags, "allcommands")
		case s == "nocommands":
			user.DisallowedCommands = append(user.DisallowedCommands, "@all")
		case strings.HasPrefix(s, "+@"):
			user.AllowedCommandCategories = append(user.AllowedCommandCategories, s[1:])
		case strings.HasPrefix(s, "-@"):
			user.AllowedCommandCategories = append(user.DisallowedCategories, s[1:])
		case strings.HasPrefix(s, "+"):
			user.AllowedCommands = append(user.AllowedCommands, s[1:])
		case strings.HasPrefix(s, "-"):
			user.DisallowedCommands = append(user.DisallowedCommands, s[1:])

		// keys
		case s == "allkeys", s == "~*":
			user.Keys = append(user.Keys, "*")
			user.Flags = append(user.Flags, "allkeys")
		case s == "resetkeys":
			user.Keys = nil
		case strings.HasPrefix(s, "~"),
			strings.HasPrefix(s, "%R~"),
			strings.HasPrefix(s, "%W~"),
			strings.HasPrefix(s, "%RW~"):
			user.Keys = append(user.Keys, s)

		// channels
		case s == "allchannels", s == "&*":
			user.Channels = append(user.Channels, "*")
			user.Flags = append(user.Flags, "allchannels")
		case s == "resetchannels":
			user.Channels = nil
		case strings.HasPrefix(s, "&"):
			user.Channels = append(user.Channels, s[1:])

		// passwords
		case strings.HasPrefix(s, "nopass"):
			user.Passwords = nil
			user.NoPass = true
		case strings.HasPrefix(s, "resetpass"):
			user.Passwords = nil
		case strings.HasPrefix(s, ">"):
			user.Passwords = append(user.Passwords, s[1:])
		case strings.HasPrefix(s, "<"):
			user.Passwords = funk.FilterString(user.Passwords, func(p string) bool {
				return p != s[1:]
			})
		case strings.HasPrefix(s, "#"):
			user.PasswordHash = append(user.PasswordHash, s[1:])
		case strings.HasPrefix(s, "!"):
			user.PasswordHash = funk.FilterString(user.PasswordHash, func(p string) bool {
				return p != s[1:]
			})
		}
	}
	user.Consolidate()
	return user, nil
}

func parseACLGetUser(result interface{}) (*ACLUser, error) {
	lines := result.([]interface{})
	if lines == nil {
		return nil, errors.Errorf("expected that `ACL GETUSER` command result is an array, "+
			"but got %v", result)
	}

	user := &ACLUser{}
	for i, line := range lines {
		switch i {
		case 1:
			lineI := line.([]interface{})
			flags := funk.Map(lineI, func(i interface{}) string {
				return i.(string)
			}).([]string)
			user.Flags = flags
			for _, flag := range flags {
				switch flag {
				case "on":
					user.Enabled = true
				case "off":
					user.Enabled = false
				case "allcommands":
					user.AllowedCommands = append(user.AllowedCommands, "@all")
				case "allkeys":
					user.Keys = append(user.Keys, "*")
				case "allchannels":
					user.Channels = append(user.Channels, "*")
				case "nopass":
					user.NoPass = true
				}
			}
		case 3:
			lineI := line.([]interface{})
			passwds := funk.Map(lineI, func(i interface{}) string {
				return i.(string)
			}).([]string)
			user.PasswordHash = passwds
		case 5:
			commands := line.(string)
			user.Commands = commands
		case 7:
			lineI := line.([]interface{})
			keys := funk.Map(lineI, func(i interface{}) string {
				return i.(string)
			}).([]string)
			user.Keys = keys
		case 9:
			lineI := line.([]interface{})
			channels := funk.Map(lineI, func(i interface{}) string {
				return i.(string)
			}).([]string)
			user.Channels = channels
		}
	}
	return user, nil
}

func ACLList(ctx context.Context, client redis.UniversalClient) ([]*ACLUser, error) {
	result, err := client.Do(ctx, "ACL", "LIST").Result()
	if err != nil {
		return nil, errors.Trace(err)
	}

	var users []*ACLUser
	for _, i := range result.([]interface{}) {
		s := i.(string)
		user, err := parseACLListUser(s)
		if err != nil {
			return nil, errors.Trace(err)
		}
		users = append(users, user)
	}
	sort.Slice(users, func(i, j int) bool {
		return users[i].Name < users[j].Name
	})
	return users, nil
}

func ACLGetUser(ctx context.Context, client redis.UniversalClient, name string) (*ACLUser, error) {
	result, err := client.Do(ctx, "ACL", "GETUSER", name).Result()
	if err != nil {
		return nil, errors.Trace(err)
	}

	user, err := parseACLGetUser(result)
	if err != nil {
		return nil, errors.Trace(err)
	}
	user.Name = name
	return user, nil
}

func ACLSetUser(ctx context.Context, client redis.UniversalClient, user *ACLUser) error {
	rules := user.String()
	command := append([]interface{}{"ACL", "SETUSER"},
		funk.Map(rules, func(i interface{}) interface{} { return i }).([]interface{})...)
	_, err := client.Do(ctx, command...).Result()
	return errors.Trace(err)
}

func ACLDelUser(ctx context.Context, client redis.UniversalClient, name string) error {
	_, err := client.Do(ctx, "ACL", "DELUSER", name).Result()
	return errors.Trace(err)
}
