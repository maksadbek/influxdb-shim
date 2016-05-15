package httpd

import (
	"fmt"
        "net"
        "net/http"
        "strings"

        "gopkg.in/fatih/set.v0"

        "github.com/Maksadbek/influxdb-shim/auth"
        "github.com/golang/glog"
        "github.com/influxdata/influxdb/client/v2"
        "github.com/spf13/viper"

        "io/ioutil"
)

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
        blacklist := set.New()
        for _, v := range c.GetStringSlice("blacklist.queries") {
                blacklist.Add(strings.ToLower(strings.Replace(v, " ", "", -1)))
        }

        source := auth.NewSource(c)

        pubKey, err := ioutil.ReadFile(c.GetString("auth.token.pubKeyPath"))
        if err != nil {
                return nil, err
        }

        privKey, err := ioutil.ReadFile(c.GetString("auth.token.privKeyPath"))
        if err != nil {
                return nil, err
        }

        signer := auth.NewSigner(
                privKey,
                pubKey,
                c.GetString("auth.token.method"),
                c.GetInt("auth.token.ttl"),
        )               
        s := &service{
                addr:    c.GetString("web.addr"),
                Handler: NewHandler(influxConfig, blacklist, source, signer),
                err:     make(chan error),
        }

        return s,nil
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
