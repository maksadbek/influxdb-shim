package conf

import (
	"fmt"

	"github.com/Maksadbek/influxdb-shim/util"
	"github.com/golang/glog"
	"github.com/spf13/viper"
)

// Groups type is the slice of Group
type Groups map[string]Group

// Group contains the group infos, include CN(common name) and OU(org unit)
type Group struct {
	OU      string   `toml:"ou"`
	DC      string   `soml:"dc"`
	CN      string   `toml:"cn"`
	Queries []string `toml:"queries"`
}

// GetFullname receives domain component and retuns full LDAP name of the group,
// e.g: CN=Global group,OU:Linux Foundation,DC=awk,DC=sed,DC=com
func (g Group) GetFullname() string {
	return fmt.Sprintf("CN=%s,OU=%s,%s", g.CN, g.OU, g.DC)
}

// HasQuery search for given query in Queries slice of Group
// returns boolean value wheater it is found or not
func (g Group) HasQuery(query string) bool {
	glog.Infof("Searching for query: %s", query)
	for _, q := range g.Queries {
		if util.CleanQuery(q) == util.CleanQuery(query) {
			glog.Info("Query found")
			return true
		}
	}
	glog.Info("Query not found")
	return false
}

// NewGroups creates Groups by given configs in viper.Viper instance
// returns pointer to created groups instance
func NewGroups(c viper.Viper) (*Groups, error) {
	glog.Info("Creating new group from configurations")
	groups := Groups{}
	g := []Group{}

	// unmarshal the config into slice of groups
	err := c.UnmarshalKey("groups", &g)
	if err != nil {
		glog.Error("cannot unmarshal groups")
		return nil, err
	}
	// range over groups from configuration
	// fill groups map with fullname(DN) as a key and group as a value
	for _, group := range g {
		groups[group.GetFullname()] = group
	}
	return &groups, nil
}

// Get searchs group by group name in g.groups slice
// example group name: 'CN=Wizards,OU=Gryfinndor,DC=White,DC=com'
func (g Groups) get(groupName string) (Group, bool) {
	group, ok := g[groupName]
	if !ok {
		return Group{}, ok
	}
	return group, ok
}

// Search receives groupNames(DN) and searchs in the map
func (g Groups) Search(groupNames ...string) (Group, bool) {
	var (
		group Group
		found bool
	)
	// range over given group names
	for _, name := range groupNames {
		glog.Infof("Searching for a group %s", name)
		group, found = g.get(name)
		if !found {
			continue
		}
	}
	if !found {
		glog.Infof("Such group does not exist")
	}
	return group, found
}
