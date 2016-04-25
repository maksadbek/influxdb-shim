package httpd

import (
	"net"

	"github.com/golang/glog"
	"github.com/spf13/viper"
)

type service struct {
	ln           net.Listener
	addr         string
	influxdbAddr string
	Handler      *handler
}

func NewService(c viper.Viper) *Service {
	s := &Service{
		addr:    c.GetString("web.bindAddress"),
		Handler: NewHandler(c),
	}
	return s
}

func (s *service) OpenDBConn() error {

}

func (s *service) Open() error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	glog.Info("listening on HTTP:", listener.Addr().String())
	s.ln = listener
}
