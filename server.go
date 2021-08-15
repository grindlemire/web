package web

import (
	"context"
	"crypto/rsa"
	"net/http"
	"time"

	"github.com/vrecan/life"
)

// Server is a wrapper around the gorilla mux http server that manages signals
// Note that I don't use life' lifecycle here because we have a blocking call for
// run (so I don't use life.Close or life.Done for managing the background thread.
// I use the server.ListenAndServe and server.Shutdown).
type Server struct {
	*life.Life

	// This is the private key of the public key that will be used to sign jwts in the auth middleware
	SigningKey *rsa.PrivateKey

	log            Logger
	server         *http.Server
	redirectServer *http.Server
	tlsCertPath    string
	tlsKeyPath     string
}

// Logger is a logger you can use to optionally print out information
type Logger interface {
	Infof(template string, args ...interface{})
	Fatalf(template string, args ...interface{})
}

// NewServer creates a new http server with a router. The reason why we pass through is because we are using
// a functional constructor and we don't want to pollute the main struct with intermediate config state
func NewServer(opts ...Opt) (s *Server, err error) {
	return build(opts...)
}

// StartAndListen synchronously will start the server and bypass the clean goRoutine handling that life provides.
// It will block while the server is listening
func (s Server) StartAndListen() {
	s.run()
}

func (s Server) run() {
	// If no certs were specified just create a regular server with no redirect
	if s.tlsCertPath == "" || s.tlsKeyPath == "" {
		err := s.server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			s.log.Fatalf("unable to start listening: %v", err)
		}
		return
	}

	go func() {
		s.log.Infof("http redirect server listening on [%s]", s.redirectServer.Addr)
		err := s.redirectServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			s.log.Fatalf("unable to start listening on http redirect: %v", err)
		}
	}()

	s.log.Infof("server listening on [%s]", s.server.Addr)
	s.log.Infof("prometheus metrics at [%s/metrics]", s.server.Addr)

	err := s.server.ListenAndServeTLS(s.tlsCertPath, s.tlsKeyPath)
	if err != nil && err != http.ErrServerClosed {
		s.log.Fatalf("unable to start listening: %v", err)
	}
}

func (s Server) getServerAddr() string {
	return s.server.Addr
}

// Close closes the server down gracefully
func (s Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s.server.Shutdown(ctx)

	if s.tlsCertPath != "" && s.tlsKeyPath != "" {
		s.redirectServer.Shutdown(ctx)
	}
	s.log.Infof("successfully shut down http server")
	return nil
}
