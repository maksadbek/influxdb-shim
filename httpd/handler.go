package httpd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"gopkg.in/fatih/set.v0"

	"github.com/Maksadbek/influxdb-shim/auth"
	"github.com/Maksadbek/influxdb-shim/conf"
	"github.com/Maksadbek/influxdb-shim/util"
	"github.com/bmizerany/pat"
	"github.com/golang/glog"
	"github.com/influxdata/influxdb/client/v2"
	"github.com/spf13/viper"
)

var (
	errProhibitedQuery = errors.New("This query is prohibited")
	errUserNotFound    = errors.New("User with such uid and password not found")
	errNoSuchGroup     = errors.New("This group is not configured")
)

type route struct {
	name       string
	method     string
	pattern    string
	handleFunc interface{}
}

// HTTP handler to InfluxDB
type handler struct {
	mux            *pat.PatternServeMux
	influxConf     client.HTTPConfig
	blacklist      *set.Set
	source         *auth.Source
	signer         *auth.Signer
	groups         conf.Groups
	useBindDN      bool
	adminGroupName string
}

// NewHandler create new handler object
func NewHandler(c viper.Viper) *handler {
	//	client.HTTPConfig, b *set.Set, source *auth.Source, signer *auth.Signer, groups conf.Groups
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
		return nil
	}

	privKey, err := ioutil.ReadFile(c.GetString("auth.token.privKeyPath"))
	if err != nil {
		glog.Errorf("Unable to get private key path from config: %s", err.Error())
		return nil
	}
	// create new token signer
	signer := auth.NewSigner(
		privKey,
		pubKey,
		c.GetString("auth.token.method"),
		c.GetInt("auth.token.ttl"),
	)
	// get groups list from config
	groups, err := conf.NewGroups(c)
	if err != nil {
		glog.Errorf("Unable to unmarshal list of groups: %s", err.Error())
		return nil
	}
	h := &handler{
		mux:            pat.New(),
		influxConf:     influxConfig,
		blacklist:      blacklist,
		source:         source,
		signer:         signer,
		groups:         *groups,
		adminGroupName: c.GetString("blacklist.adminGroup"),
	}

	h.SetRoutes([]route{
		route{
			"query",
			"GET", "/query", h.serveQuery,
		},
		route{
			"auth",
			"POST", "/auth", h.serveAuth,
		},
	})
	return h
}

func (h *handler) SetRoutes(routes []route) {
	for _, r := range routes {
		var handler http.Handler
		if hf, ok := r.handleFunc.(func(http.ResponseWriter, *http.Request)); ok {
			handler = http.HandlerFunc(hf)
		}
		h.mux.Add(r.method, r.pattern, handler)
	}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *handler) serveAuth(w http.ResponseWriter, r *http.Request) {
	glog.Info("auth")
	err := r.ParseForm()
	if err != nil {
		glog.Errorf("Unable to parse form: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	uid, p := r.Form.Get("uid"), r.Form.Get("p")
	user, logged := h.source.Login(uid, p)
	if !logged {
		glog.Errorf("Invalid user credentials: uid: '%s', password: '%s'", uid, p)
		http.Error(w, errUserNotFound.Error(), http.StatusUnauthorized)
		return
	}

	tokenString, err := h.signer.Sign(user)
	if err != nil {
		glog.Errorf("Unable to sign the token: %s", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// send token back
	fmt.Fprintf(w, tokenString)
}

// serveQuery is the query handler that receives InfluxDB queries and send results back
// it checks access through access token that is passed on query header
func (h *handler) serveQuery(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		glog.Errorf("Unable to parse form: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	q := r.Form.Get("q")   // user
	db := r.Form.Get("db") // database

	if q == "" || db == "" {
		glog.Errorf("Query does not contain query string or database")
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// get access token and verify
	tokenString := r.Header.Get("AccessToken")
	if tokenString == "" {
		glog.Errorf("Query does not contain access token")
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	user, err := h.signer.Parse(tokenString)
	if err != nil {
		glog.Errorf("Invalid access token")
		http.Error(w, "Invalid access token", http.StatusBadRequest)
		return
	}

	// search for group names
	group, found := h.groups.Search(user.GroupNames...)
	// if groups was not found, then fail
	if !found {
		http.Error(w, errNoSuchGroup.Error(), http.StatusBadRequest)
		return
	}

	cleanedQuery := util.CleanQuery(q)
	// check if the query in global blacklist or denied for user's group
	if (h.blacklist.Has(cleanedQuery) || group.HasQuery(q)) && group.GetFullname() != h.adminGroupName {
		glog.Infof("The query('%s') in blacklist", q)
		http.Error(w, errProhibitedQuery.Error(), http.StatusForbidden)
		return
	}

	glog.Infof("Query '%s' to database: '%s'", q, db)

	// create new InfluxDB client
	c, err := client.NewHTTPClient(h.influxConf)
	if err != nil {
		glog.Errorf("Unable to open connection to InfluxDB: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// send query to InfluxDB
	query := client.NewQuery(q, db, "ns")
	response, err := c.Query(query)
	if err != nil {
		glog.Errorf("Unable to run query to InfluxDB: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	encoder := json.NewEncoder(w)
	if err := encoder.Encode(response); err != nil {
		glog.Errorf("unable to encode json: %s", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
