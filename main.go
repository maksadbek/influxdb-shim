package main

import (
	"flag"

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
	viper.SetConfigType(configType)
	viper.SetConfigName(*config)
	viper.AddConfigPath(*configPath)
	if err := viper.ReadInConfig(); err != nil {
		glog.Fatal(err)
	}
	glog.Info(viper.GetString("auth.ldap.login"))
	glog.Info(viper.GetString("auth.ldap.secret"))
}
