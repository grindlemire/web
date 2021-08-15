package middleware

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

// Authenticator manages the authentication for requests. It is empty here but could be extended
// to pull in state (for example if you wanted to check entity auth against
// a persistent store then you would keep the connection in here).
type Authenticator struct {
	rsaKey *rsa.PublicKey
}

// NewAuthenticator creates a new authenticator struct that could be used to authenticate requests.
func NewAuthenticator(rsaKey *rsa.PublicKey) *Authenticator {
	return &Authenticator{rsaKey}
}

// GetRSAKey parses the rsa public and private keys
func GetRSAKey(rsaPrivateKeyLocation, privatePassphrase, rsaPublicKeyLocation string) (*rsa.PrivateKey, error) {
	priv, err := ioutil.ReadFile(rsaPrivateKeyLocation)
	if err != nil {
		return nil, errors.New("No RSA private key found")
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(priv)
	if err != nil {
		return privateKey, errors.Wrap(err, "unable to parse rsa private key from pem")
	}

	pub, err := ioutil.ReadFile(rsaPublicKeyLocation)
	if err != nil {
		return privateKey, errors.Wrap(err, "unable to read public key")
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(pub)
	if err != nil {
		return privateKey, errors.Wrap(err, "unable to parse rsa public key from pem")
	}

	privateKey.PublicKey = *publicKey

	return privateKey, nil
}

// Authenticate authenticates requests for the authenticator
func (a Authenticator) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// get the fingerprint of the request for logging and validation
		fingerprint, err := GetRequestFingerprint(r)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		entity, err := a.validateRequest(r)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("forbidden"))
			return
		}
		// set the entity in the fingerprint for downstream consumption
		fingerprint.SetEntity(entity)

		next.ServeHTTP(w, r)
	})
}

// Claims care the claims in the jwt for authentication
type Claims struct {
	jwt.StandardClaims
	EntityID string `json:"entityId"`
}

// validateRequest validates that the request is properly authenticated and authorized for the endpoint
func (a Authenticator) validateRequest(r *http.Request) (entity string, err error) {
	// get our route variables out of the path
	tokenString, err := getAuthHeader(r)
	if err != nil {
		return "", err
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return a.rsaKey, nil
	})
	if err != nil {
		return "", errors.Wrap(err, "failed to parse token")
	}

	if !token.Valid {
		return "", errors.New("failed to validate claims")
	}

	return claims.EntityID, nil
}

func getAuthHeader(r *http.Request) (string, error) {
	authString := r.Header.Get("Authorization")
	if authString == "" {
		return "", errors.New("No Authorization header")
	}

	tokens := strings.Split(authString, "Bearer ")
	if len(tokens) != 2 {
		return "", errors.New("invalid Authorization header")
	}

	return tokens[1], nil
}
