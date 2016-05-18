package auth

import (
	"reflect"
	"testing"
)

// test public key
var pubKey string = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDB76J5tJsBSLDovQTD+Si6mR8v
Pu2H8C2Q2SI7dKpJ3fWIBYtdeRrk+OBKC4iIBbdctAxogzd9iaySKcxGhq3cZfEI
IcRhjn+XvvC1Nrtn4a5OzZVOVLDzKu+bna80lUflgwDYxUA1qdnyfFwIrjShD4Jp
1Hi4dzKlFq46XB3ZnwIDAQAB
-----END PUBLIC KEY-----`

// test private key
var privKey string = `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDB76J5tJsBSLDovQTD+Si6mR8vPu2H8C2Q2SI7dKpJ3fWIBYtd
eRrk+OBKC4iIBbdctAxogzd9iaySKcxGhq3cZfEIIcRhjn+XvvC1Nrtn4a5OzZVO
VLDzKu+bna80lUflgwDYxUA1qdnyfFwIrjShD4Jp1Hi4dzKlFq46XB3ZnwIDAQAB
AoGAdN66ZOmHt6BcrASsiITwHHMGLeyYLCF69B1F2dqWfGk7+7qLn8rJgE7SqwyE
PKRlOYJvL9RTbl23F2YE6kNjJa+0Cs5crAAG+anANcBn8yorEx6nl8sUlqgPfCLy
+fTLLMCfpYuUCsQ+80nqIUcBVEXTAwe+jNO0NPpNQHjqp5ECQQDnQXeZIjNzO7Z3
G26bIKO3ZudfqFocvh/muSVwjLFNmG2hVVSEpJtT6jIbAYyv7jHrA3E0d0WbG71L
Vab08cAdAkEA1q/pS6rP0JlkfAbnu7s0eLJSnGjs/kTtjaB+LBp7c4W21gNEz8Wa
nnjPUnl8ixlc7wLcgE+4uJZc7wV8CnJL6wJAdK15VFAHOXrFQy8aDTbYo25OCtt8
K8hZfCWqGDFEO+xOU/ojnJEYtawR/8I2Y4WAthyUf242Nl42kc3zYN6gmQJAUGN2
XBsNzfJiKf777tPehgNf46l2dI+i1BFwrVsNNuiu2dxHe/VmPEjIeP18oSlSHz1X
C8TOSnAjRG0tUUwTGQJBAOEnkzhkz0gNtR+NxDMTZk20M9NiX34kjdX1AdFhWWWq
FIdb914fx8f/IJkW1ti90Xugw5+WBqdKXrr5cBEB3eM=
-----END RSA PRIVATE KEY-----`

var method string = "RS256"

var testUser User = User{
	Email:    "test@example.com",
	Name:     "testName",
	Username: "testUsername",
	Surname:  "testSurname",
	IsAdmin:  false,
}

func BenchmarkSign(b *testing.B) {
	signer := NewSigner(
		[]byte(privKey),
		[]byte(pubKey),
		method,
		10,
	)
	for n := 0; n < b.N; n++ {
		_, err := signer.Sign(testUser)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParse(b *testing.B) {
	signer := NewSigner(
		[]byte(privKey),
		[]byte(pubKey),
		method,
		10,
	)

	tokenString, err := signer.Sign(testUser)
	if err != nil {
		b.Fatal(err)
	}

	for n := 0; n < b.N; n++ {
		_, err := signer.Parse(tokenString)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestToken(t *testing.T) {
	signer := NewSigner(
		[]byte(privKey),
		[]byte(pubKey),
		method,
		10,
	)

	tokenString, err := signer.Sign(testUser)
	if err != nil {
		t.Fatal(err)
	}
	user, err := signer.Parse(tokenString)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(user, testUser) {
		t.Errorf("want %+v, got %+v", testUser, user)
	}
}
