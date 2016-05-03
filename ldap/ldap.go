package ldap

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/golang/glog"

	"gopkg.in/ldap.v2"
)

type Source struct {
	Name string // name
	Host string // LDAP host
	Port int    // port number

	UseSSL     bool // use SSL
	SkipVerify bool

	BindDN       string // DN to bind with
	BindPassword string // Bind DN password

	UserBase string // base search path for users
	UserDN   string // template for the DN of the user for simple auth

	AttrUsername string // username attribute
	AttrName     string // first name attribute
	AttrSurname  string // surname attribute
	AttrMail     string // e-mail attribute
	AttrInBind   bool   // fetch attributes in bind context (not user)

	Filter      string // query filter to validate entry
	AdminFilter string // query filter to check if user is admin

	Enabled bool // if this source is disabled
}

type User struct {
	Username string
	Name     string
	Surname  string
	Mail     string
	IsAdmin  bool
}

const (
	queryBadChars  = "\x00()*\\"            // See http://tools.ietf.org/search/rfc4515
	userDNBadChars = "\x00()*\\,='\"#+;<> " // See http://tools.ietf.org/search/rfc4514: "special characters"
)

func (s *Source) clearQuery(username string) (string, bool) {
	if strings.ContainsAny(username, queryBadChars) {
		return "", false
	}
	return fmt.Sprintf(s.Filter, username), true
}

func (s *Source) clearDN(username string) (string, bool) {
	if strings.ContainsAny(username, userDNBadChars) {
		return "", false
	}
	return fmt.Sprintf(s.UserDN, username), true
}

func (s *Source) findUserDN(l *ldap.Conn, name string) (string, bool) {
	if s.BindDN != "" && s.BindPassword != "" {
		err := l.Bind(s.BindDN, s.BindPassword)
		if err != nil {
			glog.Info("Failed to bind as BindDN: ", s.BindDN, err)
			return "", false
		}
		glog.Info("Bound as BindDN ", s.BindDN)
	} else {
		glog.Info("proceeding with anonymous LDAP search")
	}
	userFilter, ok := s.clearQuery(name)
	if !ok {
		return "", false
	}
	searchReq := ldap.NewSearchRequest(
		s.UserBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		userFilter,
		[]string{},
		nil,
	)

	sr, err := l.Search(searchReq)
	if err != nil || len(sr.Entries) < 1 {
		return "", false
	} else if len(sr.Entries) > 1 {
		return "", false
	}
	userDN := sr.Entries[0].DN
	if userDN == "" {
		return "", false
	}
	return userDN, true
}

func (s *Source) SearchEntry(name, passwd string, directBind bool) (User, bool) {
	var user User
	l, err := dial(s)
	if err != nil {
		s.Enabled = false
		return user, false
	}
	defer l.Close()

	var userDN string
	if directBind {
		var ok bool
		userDN, ok = s.clearDN(name)
		if !ok {
			return user, false
		}
	} else {
		var found bool
		userDN, found = s.findUserDN(l, name)
		if !found {
			return user, false
		}
	}
	if directBind || !s.AttrInBind {
		err = bindUser(l, userDN, passwd)
		if err != nil {
			return user, false
		}
	}

	userFilter, ok := s.clearQuery(name)
	if !ok {
		return user, false
	}
	search := ldap.NewSearchRequest(
		userDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		userFilter,
		[]string{s.AttrUsername, s.AttrName, s.AttrSurname, s.AttrMail},
		nil,
	)
	sr, err := l.Search(search)
	if err != nil {
		return user, false
	} else if len(sr.Entries) < 1 {
		if directBind {
			glog.Error("user filter inhibited user login")
		} else {
			glog.Error("LDAP search filter failed, no entries")
		}
		return user, false
	}

	user.Username = sr.Entries[0].GetAttributeValue(s.AttrUsername)
	user.Name = sr.Entries[0].GetAttributeValue(s.AttrUsername)
	user.Surname = sr.Entries[0].GetAttributeValue(s.AttrSurname)
	user.Mail = sr.Entries[0].GetAttributeValue(s.AttrMail)

	if len(s.AdminFilter) > 0 {
		search = ldap.NewSearchRequest(
			userDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			s.AdminFilter,
			[]string{s.Name},
			nil,
		)
		sr, err = l.Search(search)
		if err != nil {
			glog.Error("LDAP admin search failed with error: %v", err)
		} else if len(sr.Entries) < 1 {
			glog.Error("LDAP admin search falied, no entries")
		} else {
			user.IsAdmin = true
		}
	}

	if !directBind && s.AttrInBind {
		err = bindUser(l, userDN, passwd)
		if err != nil {
			return User{}, false
		}
	}
	return user, true
}

func bindUser(l *ldap.Conn, userDN, passwd string) error {
	glog.Info("Binding with userDN: %s", userDN)
	err := l.Bind(userDN, passwd)
	if err != nil {
		glog.Error("LDAP auth failed for user %s, error: %v", userDN, err)
		return err
	}
	glog.Info("Successfully bound userDN: %s", userDN)
	return nil
}

func dial(s *Source) (*ldap.Conn, error) {
	if s.UseSSL {
		return ldap.DialTLS(
			"tcp",
			fmt.Sprintf("%s:%d", s.Host, s.Port),
			&tls.Config{InsecureSkipVerify: s.SkipVerify},
		)
	} else {
		return ldap.Dial("tcp", fmt.Sprintf("%s:%d", s.Host, s.Port))
	}
}
