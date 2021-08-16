package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/grindlemire/web"
	"github.com/grindlemire/web/middleware"
	"github.com/vrecan/death"
)

const (
	privateKeyFile = "./id_rsa_test"
	publicKeyFile  = "./id_rsa_test.pub"
)

func main() {
	key, err := generateCerts()
	if err != nil {
		fmt.Printf("Error generating certs: %s\n", err)
		return
	}
	defer func() {
		os.Remove(privateKeyFile)
		os.Remove(publicKeyFile)
	}()

	d := death.NewDeath(syscall.SIGINT, syscall.SIGTERM)
	goRoutines := []io.Closer{}

	login := web.Endpoint{
		Path:   "/login",
		Method: http.MethodGet,
		Handler: func(w http.ResponseWriter, r *http.Request) {
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, middleware.Claims{
				EntityID: "test entity",
				StandardClaims: jwt.StandardClaims{
					NotBefore: time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
					ExpiresAt: time.Now().Add(24 * 365 * time.Hour).Unix(),
				},
			})

			tokenString, err := token.SignedString(key)
			if err != nil {
				return
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf("Use this jwt in an authorization header: %s", tokenString)))
		},
	}

	authed := web.Endpoint{
		Path:   "/home",
		Method: http.MethodGet,
		Handler: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("hello world"))
		},
	}

	s, err := web.NewServer(
		web.HTTPSPort(4443),
		web.HTTPPort(8080),
		web.TLSCertPath("./id_rsa_test.pub"),
		web.TLSKeyPath("./id_rsa_test"),
		web.AddEndpoint(login),
		web.AddAuthedEndpoint(authed),
		web.AddAllMiddleware(myMiddleware),
		web.SetLanding("/login"),
	)
	if err != nil {
		fmt.Printf("Error creating server: %s\n", err)
		return
	}
	s.Start()
	goRoutines = append(goRoutines, s)

	fmt.Printf("Go to http://localhost:8080 to see the page\n")
	err = d.WaitForDeath(goRoutines...)
}

func myMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, err := middleware.GetRequestFingerprint(r)
		if err != nil {
			fmt.Printf("Fingerprint not found?\n")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Printf("In the middleware for request %s\n", f.GetID())
		next.ServeHTTP(w, r)
	})
}

// All the stuff below this is just for generate a temporary rsa key and x509 certificate
func generateCerts() (*rsa.PrivateKey, error) {
	bitSize := 4096

	privateKey, err := generatePrivateKey(bitSize)
	if err != nil {
		return nil, err
	}

	publicKeyBytes, err := generateX509Cert(privateKey)
	if err != nil {
		return nil, err
	}

	privateKeyBytes := encodePrivateKeyToPEM(privateKey)

	err = writeKeyToFile(privateKeyBytes, privateKeyFile)
	if err != nil {
		return nil, err
	}

	err = writeKeyToFile([]byte(publicKeyBytes), publicKeyFile)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// generatePrivateKey creates a RSA Private Key of specified byte size
func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// encodePrivateKeyToPEM encodes Private Key from RSA to PEM format
func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	// pem.Block
	privBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privBlock)

	return privatePEM
}

// generateX509Cert take a rsa.PublicKey and return bytes suitable for writing to .pub file
// returns in the format "ssh-rsa ..."
func generateX509Cert(privateKey *rsa.PrivateKey) (b []byte, err error) {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test cert"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return b, err
	}

	out := &bytes.Buffer{}
	err = pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		return b, err
	}

	return out.Bytes(), nil
}

// writePemToFile writes keys to a file
func writeKeyToFile(keyBytes []byte, saveFileTo string) error {
	err := ioutil.WriteFile(saveFileTo, keyBytes, 0600)
	if err != nil {
		return err
	}

	return nil
}
