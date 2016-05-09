package httpd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"gopkg.in/fatih/set.v0"

	"github.com/bmizerany/pat"
	"github.com/gogits/gogs/modules/auth/ldap"
	"github.com/golang/glog"
	"github.com/influxdata/influxdb/client/v2"
)

var (
	ErrProhibitedQuery = errors.New("This query is prohibited")
	ErrUserNotFound    = errors.New("User with such uid and password not found")
)

type route struct {
	name       string
	method     string
	pattern    string
	handleFunc interface{}
}

// HTTP handler to InfluxDB
type handler struct {
	mux        *pat.PatternServeMux
	influxConf client.HTTPConfig
	blacklist  *set.Set
	source     *ldap.Source
	useBindDN  bool
}

func NewHandler(c client.HTTPConfig, b *set.Set, source *ldap.Source, bdn bool) *handler {
	h := &handler{
		mux:        pat.New(),
		influxConf: c,
		blacklist:  b,
		source:     source,
		useBindDN:  bdn,
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
	name, _, _, mail, admin, logged := h.source.SearchEntry(uid, p, h.useBindDN)
	if !logged {
		glog.Errorf("Invalid user credentials: uid: '%s', password: '%s'", uid, p)
		http.Error(w, ErrUserNotFound.Error(), http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(w, mail, name, admin)
}

func (h *handler) serveQuery(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		glog.Errorf("Unable to parse form: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	u := r.Form.Get("u")   // user
	db := r.Form.Get("db") // database
	q := r.Form.Get("q")   // query
	p := r.Form.Get("p")   // password

	cleanedQuery := strings.Replace(strings.ToLower(strings.TrimSpace(q)), " ", "", -1)
	// check if user in blacklist
	if h.blacklist.Has(cleanedQuery) {
		glog.Infof("Blocked query('%s') was denied", q)
		http.Error(w, ErrProhibitedQuery.Error(), http.StatusForbidden)
		return
	}

	glog.Infof("Query '%s' from user: '%s' with password '%s' to database: '%s'", q, u, p, db)

	c, err := client.NewHTTPClient(h.influxConf)
	if err != nil {
		glog.Errorf("Unable to open connection to InfluxDB: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	query := client.NewQuery(q, db, "ns")
	response, err := c.Query(query)
	if err != nil {
		glog.Errorf("Unable to run query to InfluxDB: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	encoder := json.NewEncoder(w)
	encoder.Encode(response)
}
