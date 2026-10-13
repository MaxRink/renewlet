package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestSafeOIDCNextNeverReturnsExternalURL(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/settings", "/settings"}, {"//evil.example/", "/"}, {"https://evil.example/", "/"}, {"", "/"},
	} {
		if got := safeOIDCNext(tc.in); got != tc.want {
			t.Fatalf("safeOIDCNext(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestOIDCGroupPolicyRequiresConfiguredAdminGroup(t *testing.T) {
	if !oidcGroupAllowed([]string{"users", "admins"}, map[string]bool{"admins": true}) {
		t.Fatal("expected admins group to pass")
	}
	if oidcGroupAllowed([]string{"users"}, map[string]bool{"admins": true}) {
		t.Fatal("ordinary users must not pass")
	}
}

func TestValidateOIDCIssuerRequiresHTTPSOrigin(t *testing.T) {
	for _, issuer := range []string{"http://auth.example", "https://auth.example/path?x=1", "//auth.example"} {
		if err := validateOIDCIssuer(issuer); err == nil {
			t.Fatalf("validateOIDCIssuer(%q) unexpectedly passed", issuer)
		}
	}
	if err := validateOIDCIssuer("https://auth.example"); err != nil {
		t.Fatalf("valid issuer rejected: %v", err)
	}
}

func TestValidateOIDCRedirectURIRejectsIPAndQuery(t *testing.T) {
	for _, redirect := range []string{
		"https://192.168.1.10/api/app/auth/oidc/callback",
		"https://renewlet.example/api/app/auth/oidc/callback?next=/admin",
		"http://renewlet.example/api/app/auth/oidc/callback",
	} {
		if err := validateOIDCRedirectURI(redirect); err == nil {
			t.Fatalf("redirect %q unexpectedly passed", redirect)
		}
	}
	if err := validateOIDCRedirectURI("https://renewlet.example/api/app/auth/oidc/callback"); err != nil {
		t.Fatalf("valid redirect rejected: %v", err)
	}
}

func TestOIDCHTTPClientDoesNotFollowRedirects(t *testing.T) {
	if err := oidcHTTPClient().CheckRedirect(&http.Request{}, nil); err != http.ErrUseLastResponse {
		t.Fatalf("redirect policy = %v, want ErrUseLastResponse", err)
	}
}

func TestVerifyOIDCIDTokenWithFakeJWKSValidatesNonceIssuerAudienceAndExpiry(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks" {
			http.NotFound(w, r)
			return
		}
		n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(new(big.Int).SetInt64(int64(key.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "test", "alg": "RS256", "use": "sig", "n": n, "e": e}}})
	}))
	defer server.Close()
	oldTransport := oidcHTTPTransport
	oidcHTTPTransport = server.Client().Transport
	defer func() { oidcHTTPTransport = oldTransport }()
	issuerURL, _ := url.Parse(server.URL)
	t.Setenv("RENEWLET_OIDC_ISSUER", issuerURL.String())
	claims := oidcClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: issuerURL.String(), Subject: "subject-1", Audience: jwt.ClaimStrings{"client"}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)), IssuedAt: jwt.NewNumericDate(time.Now())}, Email: "admin@example.test", EmailVerified: true, Nonce: "nonce-1", Groups: []string{"admins"}}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "test"
	raw, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	d := oidcDiscovery{Issuer: issuerURL.String(), JWKSURI: server.URL + "/jwks"}
	s := oidcSettings{Issuer: issuerURL.String(), ClientID: "client", AllowedEndpointOrigins: map[string]bool{oidcOrigin(issuerURL): true}}
	got, err := verifyOIDCIDToken(context.Background(), raw, d, s, "nonce-1")
	if err != nil || got.Subject != "subject-1" {
		t.Fatalf("valid fake token rejected: %v", err)
	}
	if _, err := verifyOIDCIDToken(context.Background(), raw, d, s, "wrong"); err == nil {
		t.Fatal("nonce mismatch accepted")
	}
}
