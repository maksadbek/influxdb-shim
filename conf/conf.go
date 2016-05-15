package conf

import (
	"fmt"
	"sync"

	"github.com/golang/glog"
	"github.com/spf13/viper"
)

// Group contains the group infos, include CN(common name) and OU(org unit)
type Group struct {
	OU            string   `toml:"ou"`
	DC            string   `soml:"dc"`
	CN            string   `toml:"cn"`
	DeniedQueries []string `toml:"deniedQueries"`
}

// GetFullname receives domain component and retuns full LDAP name of the group,
// e.g: CN=Global group,OU:Linux Foundation,DC=awk,DC=sed,DC=com
func (g Group) GetFullname() string {
	return fmt.Sprintf("CN=%s,OU=%s,%s", g.CN, g.OU, g.DC)
}

// Groups type is the slice of Group
type Groups struct {
	sync.RWMutex
	groups []Group `toml:"groups"`
}

// NewGroups can be used to
func NewGroups(c viper.Viper) (*Groups, error) {
	glog.Info("Creating new group from configurations")
	g := Groups{}

	err := c.UnmarshalKey("groups", &g.groups)
	if err != nil {
		glog.Error("cannot unmarshal groups")
		return nil, err
	}
	return &g, nil
}

// Add can be used to insert group data to groups
func (g *Groups) Add(group ...Group) {
	glog.Info("Adding a group into list: %+v", group)
	g.Lock()
	g.groups = append(g.groups, group...)
	g.Unlock()
}

// Get searchs group by group name in g.groups slice
func (g *Groups) Get(groupName string) (Group, bool) {
	glog.Infof("Searching for a group %s", groupName)
	g.RLock()
	for _, group := range g.groups {
		if group.GetFullname() == groupName {
			glog.Infof("Found the group: %+v", group)
			g.RUnlock()
			return group, true
		}
	}
	g.RUnlock()
	glog.Infof("Such group does not exist")
	return Group{}, false
}
