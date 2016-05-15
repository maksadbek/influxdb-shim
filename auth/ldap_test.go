package auth

import (
	"testing"
	"time"

	"github.com/gogits/gogs/modules/auth/ldap"
)

func TestLogin(t *testing.T) {
	s := ldap.Source{
		Name:          "forumsys",
		Host:          "ldap.forumsys.com",
		Port:          389,
		BindDN:        "uid=tesla,dc=example,dc=com",
		BindPassword:  "password",
		UserBase:      "dc=example,dc=com",
		Filter:        "(&(uid=%s))",
		AttributeMail: "mail",
	}

	go func() {
		a, b, c, d, e, logged := s.SearchEntry("tesla", "password", false)
		t.Log(a, b, c, d, e, logged)
	}()

	time.Sleep(20 * time.Second)
}
