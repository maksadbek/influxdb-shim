package conf

import (
	"bytes"
	"testing"

	"github.com/spf13/viper"
)

func TestNewGroup(t *testing.T) {
	testConf := []byte(`
    [blacklist]
        queries     = [""]
        adminGroup  = "Admin"
    [[groups]]
        ou = "Gryfinndor"
        cn = "Wizards"
        dc = "DC=White,DC=com"
        deniedQueries = [
            "Bombardo maxima",
            "Avada kedavra"
        ]
    [[groups]]
        ou = "Slizeren"
        dc = "DC=Black,DC=com"
        cn = "Witchs"
        deniedQueries = [
            "Crucio",
            "Imperio"
        ]`)

	c := viper.Viper{}
	c.SetConfigType("toml")
	err := c.ReadConfig(bytes.NewBuffer(testConf))
	if err != nil {
		t.Fatal(err)
	}

	group, err := NewGroups(c)
	if err != nil {
		t.Fatal(err)
	}

	testData := []struct {
		name string
		cn   string
		q    []string
	}{
		{
			name: "CN=Witchs,OU=Slizeren,DC=Black,DC=com",
			cn:   "Witchs",
			q: []string{
				"Crucio",
				"Imperio",
			},
		},
		{
			name: "CN=Wizards,OU=Gryfinndor,DC=White,DC=com",
			cn:   "Wizards",
			q: []string{
				"Bombardo maxima",
				"Avada kedavra",
			},
		},
	}

	for _, d := range testData {
		if g, ok := group.Get(d.name); ok {
			if g.CN != d.cn {
				t.Errorf("want %s, got %s", d.cn, g.CN)
			}
			if len(g.DeniedQueries) != len(d.q) {
				t.Fatalf("group queries are invalid")
			}
			for i := range d.q {
				if g.DeniedQueries[i] != d.q[i] {
					t.Errorf("want %+v, got %+v", d.q[i], g.DeniedQueries[i])
				}
			}
		} else {
			t.Fatal("groups does not contain pushed group")
		}
	}
}
