package main

import (
	"flag"

	"github.com/Maksadbek/influxdb-shim/httpd"
	"github.com/golang/glog"
	"github.com/spf13/viper"
)

// config file type must be toml
const configType string = "toml"

// flags
var (
	config     = flag.String("config", "conf", "config file name without extension")
	configPath = flag.String("configPath", ".", "config file path")
)

func main() {
	flag.Parse()
	glog.Info("starting...")
	// setup config
	v := viper.New()
	v.SetConfigType(configType)
	v.SetConfigName(*config)
	v.AddConfigPath(*configPath)
	if err := v.ReadInConfig(); err != nil {
		glog.Fatal(err)
	}

	webService, err := httpd.NewService(v)
	if err != nil {
		glog.Fatal(err)
	}
	
	go func() {
		for err := range webService.Err() {
			glog.Fatal(err)
		}
	}()
	glog.Fatal(webService.Open())
}
