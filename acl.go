package redis_acl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

	Name                   string   `json:"name"`
	Flags                  []string `json:"flags"`
	Enabled                bool     `json:"enabled"`
	NoPass                 bool     `json:"nopass"`
	Passwords              []string `json:"passwords"`
	PasswordHashes         []string `json:"password_hashes"`
	PasswordsToRemove      []string `json:"passwords_to_remove"`
	PasswordHashesToRemove []string `json:"password_hashes_to_remove"`
	// Commands in form of "+@all -keys"
	Commands string `json:"commands"`

	Keys     []string `json:"keys"`
	Channels []string `json:"channels"`

	// TODO: maybe unnecessary
	AllowedCommands   []string `json:"allowed_commands"`
	AllowedCategories []string `json:"allowed_categories"`

	DisallowedCommands   []string `json:"disallowed_commands"`
	DisallowedCategories []string `json:"disallowed_categories"`
}

func (u *ACLUser) Consolidate() {
	// TODO: form `Commands` from `Flags`, `AllowedCommands` and `DisallowedCommands`
	u.Commands = ""
}

func (u *ACLUser) String() string {
	genRulesWithPrefix := func(ruleList []string, prefix string) []string {
		return funk.Map(ruleList, func(r string) string {
			return prefix + r
		}).([]string)
	}

	var rules []string
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
		rules = append(rules, genRulesWithPrefix(u.PasswordHashes, "#")...)
		rules = append(rules, genRulesWithPrefix(u.PasswordsToRemove, "<")...)
		rules = append(rules, genRulesWithPrefix(u.PasswordHashesToRemove, "!")...)
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
	return strings.Join(rules, " ")
}

// func (u ACLUser) MarshalJSON() ([]byte, error) {
// 	text := fmt.Sprintf(`"%s"`, u.String())
// 	return []byte(text), nil
// }

// func (u *ACLUser) UnmarshalJSON(data []byte) error {
// 	if u == nil {
// 		u = &ACLUser{}
// 	}
// 	newUser, err := ParseACLListUser(string(data))
// 	if err != nil {
// 		return errors.Trace(err)
// 	}
//
// 	if u.Name == "" {
// 		u.Name = newUser.Name
// 	}
// 	if len(u.Passwords) == 0 {
// 		u.Passwords = newUser.Passwords
// 	}
// 	if len(u.PasswordHashes) == 0 {
// 		u.PasswordHashes = newUser.PasswordHashes
// 	}
// 	if len(u.PasswordsToRemove) == 0 {
// 		u.PasswordsToRemove = newUser.PasswordsToRemove
// 	}
// 	if len(u.PasswordHashToRemove) == 0 {
// 		u.PasswordHashToRemove = newUser.PasswordHashToRemove
// 	}
// 	if len(u.Keys) == 0 {
// 		u.Keys = newUser.Keys
// 	}
// 	if len(u.Channels) == 0 {
// 		u.Channels = newUser.Channels
// 	}
// 	if len(u.Flags) == 0 {
// 		u.Flags = newUser.Flags
// 	}
// 	if len(u.Commands) == 0 {
// 		u.Commands = newUser.Commands
// 	}
// 	if len(u.AllowedCommands) == 0 {
// 		u.AllowedCommands = newUser.AllowedCommands
// 	}
// 	if len(u.AllowedCategories) == 0 {
// 		u.AllowedCategories = newUser.AllowedCategories
// 	}
// 	if len(u.DisallowedCommands) == 0 {
// 		u.DisallowedCommands = newUser.DisallowedCommands
// 	}
// 	if len(u.DisallowedCategories) == 0 {
// 		u.DisallowedCategories = newUser.DisallowedCategories
// 	}
//
// 	return nil
// }

func Sha256(pass string) string {
	h := sha256.New()
	h.Write([]byte(pass))
	return hex.EncodeToString(h.Sum(nil))
}
func ParseACLListUser(s string) (*ACLUser, error) {
	// https://redis.io/docs/manual/security/acl/#acl-rules
	// example: "user default on nopass ~* &* +@all"
	user := &ACLUser{}
	segments := strings.Split(s, " ")
	minimumSegments := 5
	if len(segments) < minimumSegments {
		return nil, errors.Errorf("expected that `ACL LIST` command result contains "+
			"at least %d segments, but got %v", minimumSegments, segments)
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
		case s == "allcommands", s == "+*", s == "+@all":
			user.AllowedCategories = append(user.AllowedCategories, "@all")
			user.Flags = append(user.Flags, "allcommands")
		case s == "nocommands", s == "-*", s == "-@all":
			user.DisallowedCategories = append(user.DisallowedCategories, "@all")
			user.Flags = append(user.Flags, "nocommands")
		case strings.HasPrefix(s, "+@"):
			user.AllowedCategories = append(user.AllowedCategories, s[1:])
		case strings.HasPrefix(s, "-@"):
			user.AllowedCategories = append(user.DisallowedCategories, s[1:])
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
			user.PasswordHashes = nil
			user.NoPass = true
		case strings.HasPrefix(s, "resetpass"):
			user.Passwords = nil
			user.PasswordHashes = nil
		case strings.HasPrefix(s, ">"):
			user.Passwords = append(user.Passwords, s[1:])
			// automatically convert plaintext password to sha256 hash
			hash := Sha256(s[1:])
			if funk.InStrings(user.PasswordHashes, hash) {
				user.PasswordHashes = append(user.PasswordHashes, hash)
			}
		case strings.HasPrefix(s, "<"):
			user.Passwords = funk.FilterString(user.Passwords, func(p string) bool {
				return p != s[1:]
			})
			hash := Sha256(s[1:])
			user.PasswordHashes = funk.FilterString(user.PasswordHashes, func(p string) bool {
				return p != hash
			})
		case strings.HasPrefix(s, "#"):
			user.PasswordHashes = append(user.PasswordHashes, s[1:])
		case strings.HasPrefix(s, "!"):
			user.Passwords = funk.FilterString(user.Passwords, func(p string) bool {
				return Sha256(p) != s[1:]
			})
			user.PasswordHashes = funk.FilterString(user.PasswordHashes, func(p string) bool {
				return p != s[1:]
			})
		}
	}
	user.Consolidate()
	sort.Strings(user.Flags)
	sort.Strings(user.Passwords)
	sort.Strings(user.PasswordHashes)
	sort.Strings(user.PasswordsToRemove)
	sort.Strings(user.PasswordHashesToRemove)
	sort.Strings(user.Keys)
	sort.Strings(user.Channels)
	sort.Strings(user.AllowedCommands)
	sort.Strings(user.AllowedCategories)
	sort.Strings(user.DisallowedCommands)
	sort.Strings(user.DisallowedCategories)

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
			user.PasswordHashes = passwds
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
		user, err := ParseACLListUser(s)
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
	segs := strings.Split(user.String(), " ")
	command := append([]interface{}{"ACL", "SETUSER"},
		funk.Map(segs, func(i string) interface{} { return i }).([]interface{})...)
	_, err := client.Do(ctx, command...).Result()
	return errors.Trace(err)
}

func ACLDelUser(ctx context.Context, client redis.UniversalClient, name string) error {
	_, err := client.Do(ctx, "ACL", "DELUSER", name).Result()
	return errors.Trace(err)
}
