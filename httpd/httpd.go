package httpd

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/golang/glog"
	"github.com/spf13/viper"
)

// service
type service struct {
	ln      net.Listener
	addr    string
	err     chan error
	Handler *handler
}

func NewService(c viper.Viper) (*service, error) {
	// create a new web service
	s := &service{
		addr:    c.GetString("web.addr"),
		Handler: NewHandler(c),
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
