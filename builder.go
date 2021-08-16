package web

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/grindlemire/web/middleware"
	"github.com/pcman312/errutils"
	"github.com/pkg/errors"
	"github.com/rs/cors"
	"github.com/vrecan/life"
	"go.uber.org/multierr"
)

// serverBuilder handles the functional configuration of the rest server. This adds some boilerplate but
// allows us to have complex configuration with the ability to default and allows us to have a clean
// struct in the actual server (for example we don't need to store the httpPort and httpsPort in the server struct)
type serverBuilder struct {
	log         Logger
	httpPort    int
	httpsPort   int
	tlsCertPath string
	tlsKeyPath  string

	jwtSigningKeyPath string
	jwtPublicKeyPath  string
	jwtPassphrase     string
	jwtSigningKey     *rsa.PrivateKey

	httpTimeout time.Duration
	corsOptions cors.Options
	apiVersion  string
	landing     string

	handler http.Handler

	authed                   []Endpoint
	public                   []Endpoint
	disableDefaultMiddleware bool
	publicMiddleware         []mux.MiddlewareFunc
	authedMiddleware         []mux.MiddlewareFunc
	allMiddleware            []mux.MiddlewareFunc
}

// validate validates that all the required arguments are set
func (b serverBuilder) validate() error {
	merr := errutils.NewMultiError()
	if b.handler != nil {
		if b.publicMiddleware != nil {
			multierr.Append(merr, errors.New("cannot specify public middleware as well as an external handler"))
		}

		if b.authedMiddleware != nil {
			multierr.Append(merr, errors.New("cannot specify authed middleware as well as an external handler"))
		}

		if b.allMiddleware != nil {
			multierr.Append(merr, errors.New("cannot specify any middleware as well as an external handler"))
		}

		if b.disableDefaultMiddleware {
			multierr.Append(merr, errors.New("Disabling deafult middleware does nothing when using an external handler"))
		}

		if b.authed != nil {
			multierr.Append(merr, errors.New("cannot specify authed endpoints as well as an external handler"))
		}

		if b.public != nil {
			multierr.Append(merr, errors.New("cannot specify public endpoints as well as an external handler"))
		}
	}

	if b.jwtSigningKey != nil && (b.jwtSigningKeyPath != "" || b.jwtPublicKeyPath != "") {
		multierr.Append(merr, errors.New("cannot specify a jwt signing key as well as a path to a file for it"))
	}

	return merr.ErrorOrNil()
}

// Opt is an option for configuring the rest server
type Opt func(s *serverBuilder) error

// HTTPPort configures the port the http redirect is served over
func HTTPPort(port int) Opt {
	return func(b *serverBuilder) error {
		b.httpPort = port
		return nil
	}
}

// HTTPSPort configures the port the https server serves on
func HTTPSPort(port int) Opt {
	return func(b *serverBuilder) error {
		b.httpsPort = port
		return nil
	}
}

// TLSCertPath configures the path to the tls certificate
func TLSCertPath(path string) Opt {
	return func(b *serverBuilder) error {
		b.tlsCertPath = path
		return nil
	}
}

// TLSKeyPath configures the path to the tls private key
func TLSKeyPath(path string) Opt {
	return func(b *serverBuilder) error {
		b.tlsKeyPath = path
		return nil
	}
}

// JWTSigningCertPath configures the path to the public key that will be used
// to validate jwts. Defaults to the tls cert.
func JWTSigningCertPath(path string) Opt {
	return func(b *serverBuilder) error {
		b.jwtPublicKeyPath = path
		return nil
	}
}

// JWTSigningKeyPath configures the path to the private  key that will be used
// to validate the jwts. Defaults to the tls private key.
func JWTSigningKeyPath(path string) Opt {
	return func(b *serverBuilder) error {
		b.jwtSigningKeyPath = path
		return nil
	}
}

// JWTSingingKeyPassphrase configures the passphrase that is required to use the signing key (if there is one).
func JWTSingingKeyPassphrase(passphrase string) Opt {
	return func(b *serverBuilder) error {
		b.jwtSigningKeyPath = passphrase
		return nil
	}
}

// JWTSigningKey configures the path to the private  key that will be used
// to validate the jwts. Defaults to the tls private key.
func JWTSigningKey(key *rsa.PrivateKey) Opt {
	return func(b *serverBuilder) error {
		b.jwtSigningKey = key
		return nil
	}
}

// CORSOptions configures cors options for the server
func CORSOptions(c cors.Options) Opt {
	return func(b *serverBuilder) error {
		b.corsOptions = c
		return nil
	}
}

// AddAuthedEndpoint adds some authed endpoints to the server
func AddAuthedEndpoint(authed ...Endpoint) Opt {
	return func(b *serverBuilder) error {
		b.authed = append(b.authed, authed...)
		return nil
	}
}

// AddEndpoint adds some public endpoints to the server
func AddEndpoint(public ...Endpoint) Opt {
	return func(b *serverBuilder) error {
		b.public = append(b.public, public...)
		return nil
	}
}

// DisableDefaultMiddleware will disable the server from adding request fingerprinting
// prometheus metrics for all routes, and jwt auth for authed routes
func DisableDefaultMiddleware(disable bool) Opt {
	return func(b *serverBuilder) error {
		b.disableDefaultMiddleware = disable
		return nil
	}
}

// AddAuthedMiddleware adds a set of middleware to the server. Order matters
// here as first will be encountered first in a request.
func AddAuthedMiddleware(authedMiddleware ...mux.MiddlewareFunc) Opt {
	return func(b *serverBuilder) error {
		b.authedMiddleware = append(b.authedMiddleware, authedMiddleware...)
		return nil
	}
}

// AddPublicMiddleware adds a set of middleware to the server. Order matters
// here as first will be encountered first in a request.
func AddPublicMiddleware(publicMiddleware ...mux.MiddlewareFunc) Opt {
	return func(b *serverBuilder) error {
		b.publicMiddleware = append(b.publicMiddleware, publicMiddleware...)
		return nil
	}
}

// AddAllMiddleware adds a set of middleware to the server. Order matters
// here as first will be encountered first in a request.
func AddAllMiddleware(allMiddleware ...mux.MiddlewareFunc) Opt {
	return func(b *serverBuilder) error {
		b.allMiddleware = append(b.allMiddleware, allMiddleware...)
		return nil
	}
}

// SetLogger sets a logger if you want one
func SetLogger(logger Logger) Opt {
	return func(b *serverBuilder) error {
		b.log = logger
		return nil
	}
}

// SetTimeout sets the http timeout for requests and responses. Defaults to
// 10 seconds.
func SetTimeout(d time.Duration) Opt {
	return func(b *serverBuilder) error {
		b.httpTimeout = d
		return nil
	}
}

// SetAPIVersion will set a path to prepend to all routes so you can version via urls.
// Defaults to no path
func SetAPIVersion(s string) Opt {
	return func(b *serverBuilder) error {
		b.apiVersion = s
		return nil
	}
}

// SetLanding will set the top level home path for the server. Defaults to just the bare /
// If you are using a versioned api this will respect the versioning.
func SetLanding(s string) Opt {
	return func(b *serverBuilder) error {
		b.landing = s
		return nil
	}
}

// Handler configures the rest handler that will route and respond to requests.
// Use this configuration if you want to route your own requests outside of this libary.
func Handler(handler http.Handler) Opt {
	return func(b *serverBuilder) error {
		b.handler = handler
		return nil
	}
}

// build will build the rest server with the complex configuration. This is a bit of boiler plate
// but provides a really nice caller experience (see main.go). Required arguments are not passed via the
// variadic args (unless you have truly a ton, then you would add a validation step after assembling the builder)
func build(opts ...Opt) (s *Server, err error) {
	// These are internal defaults if all else fails during configuration
	b := serverBuilder{
		httpPort:    80,
		httpsPort:   443,
		httpTimeout: 10 * time.Second,
	}

	// loop through our configured options and apply them to the functional builder
	for _, opt := range opts {
		err = opt(&b)
		if err != nil {
			return s, err
		}
	}

	// validate we have all our required arguments
	err = b.validate()
	if err != nil {
		return s, err
	}

	secureServer := b.tlsCertPath != "" && b.tlsKeyPath != ""

	if b.log == nil {
		b.log = basicLogger{}
	}

	if !secureServer {
		return b.buildWithoutHTTPS()
	}

	return b.buildWithHTTPS()

}

// createDefaultRouter will create the basic router with authed routes and public routes
// It also initializes request fingerprinter, prometheus metrics middleware for all requests,
// and jwt auth for auth middleware.
func (b *serverBuilder) createDefaultRouter(pubKey *rsa.PublicKey) (h http.Handler, err error) {
	if !b.disableDefaultMiddleware {
		b.allMiddleware = append([]mux.MiddlewareFunc{middleware.RequestFingerprinter, middleware.MetricsRecorder}, b.allMiddleware...)
		if pubKey != nil {
			b.authedMiddleware = append([]mux.MiddlewareFunc{middleware.NewAuthenticator(pubKey).Authenticate})
		}
	}

	return newRouter(b.landing, b.apiVersion, b.authed, b.public, b.allMiddleware, b.publicMiddleware, b.authedMiddleware)
}

func (b *serverBuilder) buildWithoutHTTPS() (s *Server, err error) {
	// if the caller doesn't supply their own router initialize the default
	if b.handler == nil {
		b.handler, err = b.createDefaultRouter(nil)
		if err != nil {
			return s, err
		}
	}

	s = &Server{
		Life: life.NewLife(),
		server: &http.Server{
			Handler:      b.handler,
			Addr:         fmt.Sprintf(":%d", b.httpPort),
			ReadTimeout:  b.httpTimeout,
			WriteTimeout: b.httpTimeout,
		},
		log: b.log,
	}
	s.SetRun(s.run)
	return s, nil
}

func (b *serverBuilder) buildWithHTTPS() (s *Server, err error) {
	// this is where we would set cors options if we had them
	c := cors.New(b.corsOptions)

	if b.jwtSigningKey == nil {
		if b.jwtSigningKeyPath == "" || b.jwtPublicKeyPath == "" {
			b.jwtSigningKeyPath = b.tlsKeyPath
			b.jwtPublicKeyPath = b.tlsCertPath
		}

		b.jwtSigningKey, err = middleware.GetRSAKey(b.jwtSigningKeyPath, b.jwtPassphrase, b.jwtPublicKeyPath)
		if err != nil {
			return s, err
		}
	}

	// if the caller doesn't supply their own router initialize the default
	if b.handler == nil {
		b.handler, err = b.createDefaultRouter(&b.jwtSigningKey.PublicKey)
		if err != nil {
			return s, err
		}
	}

	// assemble our server
	s = &Server{
		Life: life.NewLife(),
		server: &http.Server{
			Handler:      c.Handler(b.handler),
			Addr:         fmt.Sprintf(":%d", b.httpsPort),
			ReadTimeout:  b.httpTimeout,
			WriteTimeout: b.httpTimeout,
		},
		redirectServer: &http.Server{
			Handler:      createHTTPSRedirect(b.httpsPort, b.log),
			Addr:         fmt.Sprintf(":%d", b.httpPort),
			ReadTimeout:  b.httpTimeout,
			WriteTimeout: b.httpTimeout,
		},
		tlsCertPath: b.tlsCertPath,
		tlsKeyPath:  b.tlsKeyPath,
		log:         b.log,
	}
	s.SetRun(s.run)
	return s, nil
}

// createHTTPSRedirect creates a redirect function that will redirect us to the right rest server
// to redirect us from http to https, even if the https server is served on a nonstandard port
func createHTTPSRedirect(httpsPort int, log Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cleanedHost := strings.Split(r.Host, ":")[0]
		from := fmt.Sprintf("http://%s%s", r.Host, r.RequestURI)
		redirect := fmt.Sprintf("https://%s:%d%s", cleanedHost, httpsPort, r.RequestURI)
		log.Infof("Redirecting [%s] to [%s]", from, redirect)
		http.Redirect(w, r, redirect, http.StatusMovedPermanently)
	}
}

type basicLogger struct{}

func (b basicLogger) Infof(template string, a ...interface{}) {
	fmt.Printf(template+"\n", a...)
}
func (b basicLogger) Fatalf(template string, a ...interface{}) {
	fmt.Printf(template+"\n", a...)
	os.Exit(1)
}
