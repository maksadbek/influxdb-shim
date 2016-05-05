package ldap

import "github.com/gogits/gogs/modules/auth/ldap"

func NewSource(name, host, port, email, userBase, filter, userDN string) *ldap.Source {
	return &ldap.Source{
		Name:          name,
		Host:          host,
		Port:          port,
		AttributeMail: email,
		UserBase:      userBase,
		UserFilter:    filter,
		UserDN:        userDN,
	}
}
