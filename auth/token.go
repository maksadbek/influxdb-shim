package auth

import (
	"errors"

	"github.com/dgrijalva/jwt-go"
)

var (
	errInvalidToken = errors.New("Invalid Token")
)

type signer struct {
	PrivKey []byte // private key to sign in
	PubKey  []byte // public key to verify
	TTL     int    // time to live of the token(expiration period), in minutes
	Method  string
}

func NewSigner(privKey, pubKey []byte, method string, ttl int) *signer {
	return &signer{
		PrivKey: privKey,
		PubKey:  pubKey,
		Method:  method,
		TTL:     ttl,
	}
}

// Sign can be used to get signed token of user
func (s *signer) Sign(user User) (string, error) {

	t := jwt.New(jwt.GetSigningMethod(s.Method))
	t.Claims["email"] = user.Email
	t.Claims["name"] = user.Name
	t.Claims["username"] = user.Username
	t.Claims["surname"] = user.Surname
	t.Claims["isAdmin"] = user.IsAdmin

	return t.SignedString(s.PrivKey)
}

func (s *signer) Parse(token string) (User, error) {
	var u User
	t, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return s.PubKey, nil
	})

	if err != nil {
		return u, err
	}

	if !t.Valid {
		return u, errInvalidToken
	}

	u = User{
		Email:    t.Claims["email"].(string),
		Name:     t.Claims["name"].(string),
		Username: t.Claims["username"].(string),
		Surname:  t.Claims["surname"].(string),
		IsAdmin:  t.Claims["isAdmin"].(bool),
	}
	return u, nil
}
