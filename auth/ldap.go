// Copyright 2014 The Gogs Authors. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

// Package ldap provide functions & structure to query a LDAP ldap directory
// For now, it's mainly tested again an MS Active Directory service, see README.md for more information
package auth

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/golang/glog"
	"gopkg.in/ldap.v2"
)

// Basic LDAP authentication service
type Source struct {
	Name              string // canonical name (ie. corporate.ad)
	Host              string // LDAP host
	Port              int    // port number
	UseSSL            bool   // Use SSL
	SkipVerify        bool
	BindDN            string // DN to bind with
	BindPassword      string // Bind DN password
	UserBase          string // Base search path for users
	UserDN            string // Template for the DN of the user for simple auth
	AttributeUsername string // Username attribute
	AttributeName     string // First name attribute
	AttributeSurname  string // Surname attribute
	AttributeMail     string // E-mail attribute
	AttributesInBind  bool   // fetch attributes in bind context (not user)
	Filter            string // Query filter to validate entry
	AdminFilter       string // Query filter to check if user is admin
	Enabled           bool   // if this source is disabled
	UseDBind          bool   // Use Direct Bind to glogin
}

// Attr is the attributes of the search result
type Attr struct {
	Name   string
	Values []string
}

// Result is the search result
type Result struct {
	DN    string
	Attrs []Attr
}

func (ls *Source) sanitizedUserQuery(username string) (string, bool) {
	// See http://tools.ietf.org/search/rfc4515
	badCharacters := "\x00()*\\"
	if strings.ContainsAny(username, badCharacters) {
		glog.Infof("'%s' contains invalid query characters. Aborting.", username)
		return "", false
	}

	return fmt.Sprintf(ls.Filter, username), true
}

func (ls *Source) sanitizedUserDN(username string) (string, bool) {
	// See http://tools.ietf.org/search/rfc4514: "special characters"
	badCharacters := "\x00()*\\,='\"#+;<> "
	if strings.ContainsAny(username, badCharacters) {
		glog.Errorf("'%s' contains invalid DN characters. Aborting.", username)
		return "", false
	}

	return fmt.Sprintf(ls.UserDN, username), true
}

func (ls *Source) findUserDN(l *ldap.Conn, name string) (string, bool) {
	glog.Errorf("Search for LDAP user: %s", name)
	if ls.BindDN != "" && ls.BindPassword != "" {
		err := l.Bind(ls.BindDN, ls.BindPassword)
		if err != nil {
			glog.Errorf("Failed to bind as BindDN[%s]: %v", ls.BindDN, err)
			return "", false
		}
		glog.Errorf("Bound as BindDN %s", ls.BindDN)
	} else {
		glog.Errorf("Proceeding with anonymous LDAP search.")
	}

	// A search for the user.
	userFilter, ok := ls.sanitizedUserQuery(name)
	if !ok {
		return "", false
	}

	glog.Errorf("Searching for DN using filter %s and base %s", userFilter, ls.UserBase)
	search := ldap.NewSearchRequest(
		ls.UserBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0,
		false, userFilter, []string{}, nil)

	// Ensure we found a user
	sr, err := l.Search(search)
	if err != nil || len(sr.Entries) < 1 {
		glog.Errorf("Failed search using filter[%s]: %v", userFilter, err)
		return "", false
	} else if len(sr.Entries) > 1 {
		glog.Errorf("Filter '%s' returned more than one user.", userFilter)
		return "", false
	}

	userDN := sr.Entries[0].DN
	if userDN == "" {
		glog.Error("LDAP search was successful, but found no DN!")
		return "", false
	}

	return userDN, true
}

// Search provides searching functionality by given filters and attributes
func (ls *Source) Search(baseDN string, filter string, attrs []string) ([]Result, error) {
	l, err := ldapDial(ls)
	if err != nil {
		glog.Error("LDAP Connect error, %s:%v", ls.Host, err)
		ls.Enabled = false
		return nil, err
	}
	defer l.Close()
	glog.Errorf("Fetching attributes '%+v', with filter %s and base %s", attrs, filter, baseDN)
	search := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		attrs,
		nil,
	)

	sr, err := l.Search(search)
	if err != nil {
		glog.Errorf("LDAP Search failed unexpectedly! (%v)", err)
		return nil, err
	} else if len(sr.Entries) < 1 {
		glog.Errorf("LDAP Search failed unexpectedly! (0 entries)")
		return nil, err
	}
	r := make([]Result, len(sr.Entries))
	for entryIndex, entry := range sr.Entries {
		ri := &r[entryIndex]
		ri.DN = entry.DN
		ri.Attrs = make([]Attr, len(entry.Attributes))
		for attrIndex, attr := range entry.Attributes {
			ri.Attrs[attrIndex] = Attr{attr.Name, attr.Values}
		}
	}
	return r, nil
}

// SearchEntry : search an LDAP source if an entry (name, passwd) is valid and in the specific filter
func (ls *Source) SearchEntry(name, passwd string, directBind bool) (string, string, string, string, bool, bool) {
	l, err := ldapDial(ls)
	if err != nil {
		glog.Error("LDAP Connect error, %s:%v", ls.Host, err)
		ls.Enabled = false
		return "", "", "", "", false, false
	}
	defer l.Close()

	var userDN string
	if directBind {
		glog.Errorf("LDAP will bind directly via UserDN template: %s", ls.UserDN)

		var ok bool
		userDN, ok = ls.sanitizedUserDN(name)
		if !ok {
			return "", "", "", "", false, false
		}
	} else {
		glog.Errorf("LDAP will use BindDN.")

		var found bool
		userDN, found = ls.findUserDN(l, name)
		if !found {
			return "", "", "", "", false, false
		}
	}

	if directBind || !ls.AttributesInBind {
		// binds user (checking password) before looking-up attributes in user context
		err = bindUser(l, userDN, passwd)
		if err != nil {
			return "", "", "", "", false, false
		}
	}

	userFilter, ok := ls.sanitizedUserQuery(name)
	if !ok {
		return "", "", "", "", false, false
	}

	glog.Infof("Fetching attributes '%v', '%v', '%v', '%v' with filter %s and base %s", ls.AttributeUsername, ls.AttributeName, ls.AttributeSurname, ls.AttributeMail, userFilter, userDN)
	search := ldap.NewSearchRequest(
		userDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, userFilter,
		[]string{ls.AttributeUsername, ls.AttributeName, ls.AttributeSurname, ls.AttributeMail},
		nil)
	sr, err := l.Search(search)
	if err != nil {
		glog.Errorf("LDAP Search failed unexpectedly! (%v)", err)
		return "", "", "", "", false, false
	} else if len(sr.Entries) < 1 {
		if directBind {
			glog.Error("User filter inhibited user login.")
		} else {
			glog.Error("LDAP Search failed unexpectedly! (0 entries)")
		}

		return "", "", "", "", false, false
	}

	username_attr := sr.Entries[0].GetAttributeValue(ls.AttributeUsername)
	name_attr := sr.Entries[0].GetAttributeValue(ls.AttributeName)
	sn_attr := sr.Entries[0].GetAttributeValue(ls.AttributeSurname)
	mail_attr := sr.Entries[0].GetAttributeValue(ls.AttributeMail)

	admin_attr := false
	if len(ls.AdminFilter) > 0 {
		glog.Errorf("Checking admin with filter %s and base %s", ls.AdminFilter, userDN)
		search = ldap.NewSearchRequest(
			userDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, ls.AdminFilter,
			[]string{ls.AttributeName},
			nil)

		sr, err = l.Search(search)
		if err != nil {
			glog.Errorf("LDAP Admin Search failed unexpectedly! (%v)", err)
		} else if len(sr.Entries) < 1 {
			glog.Errorf("LDAP Admin Search failed")
		} else {
			admin_attr = true
		}
	}

	if !directBind && ls.AttributesInBind {
		// binds user (checking password) after looking-up attributes in BindDN context
		err = bindUser(l, userDN, passwd)
		if err != nil {
			return "", "", "", "", false, false
		}
	}

	return username_attr, name_attr, sn_attr, mail_attr, admin_attr, true
}

func bindUser(l *ldap.Conn, userDN, passwd string) error {
	glog.Errorf("Binding with userDN: %s", userDN)
	err := l.Bind(userDN, passwd)
	if err != nil {
		glog.Errorf("LDAP auth. failed for %s, reason: %v", userDN, err)
		return err
	}
	glog.Errorf("Bound successfully with userDN: %s", userDN)
	return err
}

func ldapDial(ls *Source) (*ldap.Conn, error) {
	if ls.UseSSL {
		glog.Errorf("Using TLS for LDAP without verifying: %v", ls.SkipVerify)
		return ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", ls.Host, ls.Port), &tls.Config{
			InsecureSkipVerify: ls.SkipVerify,
		})
	} else {
		return ldap.Dial("tcp", fmt.Sprintf("%s:%d", ls.Host, ls.Port))
	}
}
