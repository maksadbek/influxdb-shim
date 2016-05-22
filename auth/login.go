package auth

import (
	"github.com/golang/glog"
	"github.com/spf13/viper"
)

// User contains the user information
type User struct {
	Email      string
	Name       string
	Username   string
	Surname    string
	IsAdmin    bool
	GroupNames []string
}

// Login can be used to check user id and password,
// returns full user info if succeded
func (source *Source) Login(uid, password string) (User, bool) {
	name, un, sn, mail, admin, logged := source.SearchEntry(uid, password, source.UseDBind)
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

	groups, err := source.Search(source.UserBase, source.Filter, []string{"memberOf"})
	if err != nil {
		glog.Errorf("Unable to get user's groups: %s", err.Error())
		return u, logged
	}

	if len(groups) > 0 {
		for _, dn := range groups[0].Attrs {
			u.GroupNames = dn.Values
		}
	}

	return u, logged
}

// NewSource can be used to create new Source object with the given params
func NewSource(c viper.Viper) *Source {
	return &Source{
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
		UseDBind:          c.GetBool("auth.ldap.useDirectBind"),
	}
}
