package httpd

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"gopkg.in/fatih/set.v0"

	"github.com/Maksadbek/influxdb-shim/auth"
	"github.com/Maksadbek/influxdb-shim/conf"
	"github.com/golang/glog"
	"github.com/influxdata/influxdb/client/v2"
	"github.com/spf13/viper"

	"io/ioutil"
)

// service
type service struct {
	ln      net.Listener
	addr    string
	err     chan error
	Handler *handler
}

func NewService(c *viper.Viper) (*service, error) {
	influxConfig := client.HTTPConfig{
		Addr:      c.GetString("influxdb.addr"),
		Username:  c.GetString("influxdb.username"),
		Password:  c.GetString("influxdb.password"),
		UserAgent: c.GetString("influxdb.userAgent"),
	}
	// blacklist of queries
	blacklist := set.New()
	for _, v := range c.GetStringSlice("blacklist.queries") {
		blacklist.Add(strings.ToLower(strings.Replace(v, " ", "", -1)))
	}
	// new LDAP source
	source := auth.NewSource(c)
	// get public & priv keys for token signing
	pubKey, err := ioutil.ReadFile(c.GetString("auth.token.pubKeyPath"))
	if err != nil {
		glog.Errorf("Unable to get public key path from config: %s", err.Error())
		return nil, err
	}

	privKey, err := ioutil.ReadFile(c.GetString("auth.token.privKeyPath"))
	if err != nil {
		glog.Errorf("Unable to get private key path from config: %s", err.Error())
		return nil, err
	}
	// create new token signer
	signer := auth.NewSigner(
		privKey,
		pubKey,
		c.GetString("auth.token.method"),
		c.GetInt("auth.token.ttl"),
	)
	// get groups list from config
	groups, err := conf.NewGroups(*c)
	if err != nil {
		glog.Errorf("Unable to unmarshal list of groups: %s", err.Error())
		return nil, err
	}
	// create a new web service
	s := &service{
		addr:    c.GetString("web.addr"),
		Handler: NewHandler(influxConfig, blacklist, source, signer, *groups),
		err:     make(chan error),
	}

	return s, nil
}

func (s *service) Open() error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	glog.Info("listening on HTTP:", listener.Addr().String())
	s.ln = listener
	s.serve()
	return nil
}

func (s *service) serve() {
	err := http.Serve(s.ln, s.Handler)
	if err != nil && !strings.Contains(err.Error(), "closed") {
		s.err <- fmt.Errorf("listener failed: addr=%s, err=%s", s.addr, err)
	}
}

func (s *service) Close() error {
	if s.ln != nil {
		return s.ln.Close()
	}
	return nil
}

func (s *service) Err() <-chan error {
	return s.err
}
