package auth

import (
	"github.com/gogits/gogs/modules/auth/ldap"
	"github.com/spf13/viper"
)

func NewSource(c *viper.Viper) *ldap.Source {
	return &ldap.Source{
		Name:          c.GetString("auth.ldap.name"),
		Host:          c.GetString("auth.ldap.host"),
		Port:          c.GetInt("auth.ldap.port"),
		AttributeMail: c.GetString("auth.ldap.email"),
		UserBase:      c.GetString("auth.ldap.userBase"),
		Filter:        c.GetString("auth.ldap.filter"),
		UserDN:        c.GetString("auth.ldap.userDN"),
	}
}
