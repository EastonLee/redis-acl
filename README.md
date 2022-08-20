# redis-acl

Redis starts supporting ACL from version 6. This repository contains an equivalent golang struct, and gives you the ability to parse ACL rules and stringify the `ACLUser` struct.

## Installation

```bash
go get github.com/easton.lee/redis-acl
```

## Usage

```go
package main

import (
	"encoding/json"
	"fmt"

	acl "github.com/eastonlee/redis-acl"
)

func main() {
	user := &acl.ACLUser{
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
	fmt.Println(user.String())
	// Output:
	// "easton off nopass ~* resetchannels &channel1 +@all"

	user, err := acl.ParseACLListUser("user easton off >p@ssw0rd ~sensitive-keys:* resetchannels &eventchannels* +@admin")
	if err != nil {
		fmt.Println(err)
	}
	bs, err := json.MarshalIndent(user, "", "  ")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(bs))
	// Output:
	/*
	** {
	**   "cluster": "",
	**   "name": "easton",
	**   "flags": [
	**     "off"
	**   ],
	**   "enabled": false,
	**   "nopass": false,
	**   "passwords": [
	**     "p@ssw0rd"
	**   ],
	**   "password_hashes": [
	**     "a075d17f3d453073853f813838c15b8023b8c487038436354fe599c3942e1f95"
	**   ],
	**   "passwords_to_remove": null,
	**   "password_hashes_to_remove": null,
	**   "commands": "",
	**   "keys": [
	**     "~sensitive-keys:*"
	**   ],
	**   "channels": [
	**     "eventchannels*"
	**   ],
	**   "allowed_commands": null,
	**   "allowed_categories": [
	**     "@admin"
	**   ],
	**   "disallowed_commands": null,
	**   "disallowed_categories": [
	**     "@all"
	**   ]
	** }
	 */
}
```

## License

MIT License