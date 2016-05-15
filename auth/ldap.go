package auth

import (
	"github.com/gogits/gogs/modules/auth/ldap"
	"github.com/spf13/viper"
)

// Source is the proxy for ldap.Source
type Source struct {
	s         *ldap.Source
	UseBindDN bool
}

// Login can be used to check user id and password,
// returns full user info if succeded
func (source *Source) Login(uid, password string) (User, bool) {
	name, un, sn, mail, admin, logged := source.s.SearchEntry(uid, password, source.UseBindDN)
	if !logged {
		return User{}, logged
	}
	u := User{
		Email:    mail,
		Name:     name,
		Username: un,
		Surname:  sn,
		IsAdmin:  admin,
	}
	return u, logged
}

// User contains the user information
type User struct {
	Email      string
	Name       string
	Username   string
	Surname    string
	IsAdmin    bool
	GroupNames []string
}

// NewSource can be used to create new Source object with the given params
func NewSource(c *viper.Viper) *Source {
	return &Source{
		s: &ldap.Source{
			Name:              c.GetString("auth.ldap.name"),
			Host:              c.GetString("auth.ldap.host"),
			Port:              c.GetInt("auth.ldap.port"),
			UserBase:          c.GetString("auth.ldap.userBase"),
			Filter:            c.GetString("auth.ldap.userFilter"),
			UserDN:            c.GetString("auth.ldap.userDN"),
			AttributeUsername: c.GetString("auth.ldap.attrUsername"),
			AttributeName:     c.GetString("auth.ldap.attrName"),
			AttributeSurname:  c.GetString("auth.ldap.attrSurname"),
			AttributeMail:     c.GetString("auth.ldap.attrMail"),
		},
		UseBindDN: c.GetBool("auth.ldap.useBindDN"),
	}
}
