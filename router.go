package web

// router manages the routes of our server. This can get a lot more complicated but allows us to create arbitrarily
// complex middleware and handlers (for example if either a middleware or handler needed a 3rd party connection to a database
// or complex configuration)

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Endpoint ...
type Endpoint struct {
	Prefix  bool
	Path    string
	Method  string
	Queries map[string]string
	Handler http.HandlerFunc
}

// router is a router for registering different requests for different endpoints
type router struct {
	authed []Endpoint
	public []Endpoint
}

// newRouter creates a new mux router with all our handlers configured
func newRouter(
	landing string,
	authed []Endpoint,
	public []Endpoint,
	allMiddleware []mux.MiddlewareFunc,
	publicMiddleware []mux.MiddlewareFunc,
	authedMiddleware []mux.MiddlewareFunc,
) (r *mux.Router, err error) {

	r = mux.NewRouter()

	// Apply the middleware that is applied to all requests first
	for _, f := range allMiddleware {
		r.Use(f)
	}

	// Protected Paths
	// Create a subrouter for our authed routes. Add in the auth middleware
	authedRouter := r.PathPrefix("/").Subrouter()
	for _, f := range authedMiddleware {
		authedRouter.Use(f)
	}

	for _, endpoint := range authed {
		r := authedRouter.NewRoute().
			Methods(endpoint.Method).
			HandlerFunc(endpoint.Handler)

		if endpoint.Prefix {
			r.PathPrefix(endpoint.Path)
		} else {
			r.Path(endpoint.Path)
		}

		for k, v := range endpoint.Queries {
			r.Queries(k, v)
		}
	}

	// Public paths
	// Create a subrouter for our public paths
	publicRouter := r.PathPrefix("/").Subrouter()
	for _, f := range publicMiddleware {
		publicRouter.Use(f)
	}

	for _, endpoint := range public {

		r := publicRouter.NewRoute().
			Methods(endpoint.Method).
			HandlerFunc(endpoint.Handler)

		if endpoint.Prefix {
			r.PathPrefix(endpoint.Path)
		} else {
			r.Path(endpoint.Path)
		}

		for k, v := range endpoint.Queries {
			r.Queries(k, v)
		}
	}

	// Metrics endpoint for prometheus
	r.NewRoute().
		Methods(http.MethodGet).
		Path("/metrics").
		Handler(promhttp.Handler())

	if landing != "" {
		// Bare Response redirect to whatever URL we want
		r.NewRoute().
			Path("/").
			Handler(http.RedirectHandler(fmt.Sprintf("/%s", landing), http.StatusMovedPermanently))
	}

	// This is required because the default NotFoundHandler will bypass all the middleware but we don't want that.
	// Note that this needs to go last in our router so we don't wildcard over the rest of our routes.
	// See https://stackoverflow.com/questions/43613311/make-a-custom-404-with-golang-and-mux
	r.NotFoundHandler = r.NewRoute().HandlerFunc(notFound).GetHandler()

	return r, nil
}

// notFound handles requests where the route was not found
func notFound(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("page not found"))
}
