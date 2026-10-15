package main

// Native OIDC login for the Docker server. The flow deliberately uses the
// authorization-code flow with state, nonce and PKCE; reverse-proxy headers
// are never treated as identity assertions.
import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"golang.org/x/oauth2"
)

const oidcCookiePath = "/api/app/auth/oidc"
const oidcStateTTL = 10 * time.Minute

type oidcSettings struct {
	Enabled                                     bool
	Issuer, ClientID, ClientSecret, RedirectURI string
	AllowedGroups                               map[string]bool
	AutoProvision                               bool
	RequireVerifiedEmail                        bool
	AllowedEndpointOrigins                      map[string]bool
}
type oidcDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	Issuer                string `json:"issuer"`
}
type oidcKeySet struct {
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Alg string `json:"alg"`
		Use string `json:"use"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}
type oidcClaims struct {
	jwt.RegisteredClaims
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Name          string   `json:"name"`
	Groups        []string `json:"groups"`
	Nonce         string   `json:"nonce"`
}

func oidcFromEnv() oidcSettings {
	groups := map[string]bool{}
	for _, g := range strings.Split(os.Getenv("RENEWLET_OIDC_ALLOWED_GROUPS"), ",") {
		if g = strings.TrimSpace(g); g != "" {
			groups[g] = true
		}
	}
	if len(groups) == 0 {
		groups["admins"] = true
	}
	issuer := strings.TrimRight(strings.TrimSpace(os.Getenv("RENEWLET_OIDC_ISSUER")), "/")
	origins := map[string]bool{}
	if u, err := url.Parse(issuer); err == nil {
		origins[oidcOrigin(u)] = true
	}
	for _, raw := range strings.Split(os.Getenv("RENEWLET_OIDC_ALLOWED_ENDPOINT_ORIGINS"), ",") {
		u, err := url.Parse(strings.TrimRight(strings.TrimSpace(raw), "/"))
		if err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" {
			origins[oidcOrigin(u)] = true
		}
	}
	return oidcSettings{Enabled: strings.EqualFold(os.Getenv("RENEWLET_OIDC_ENABLED"), "true"), Issuer: issuer, ClientID: strings.TrimSpace(os.Getenv("RENEWLET_OIDC_CLIENT_ID")), ClientSecret: os.Getenv("RENEWLET_OIDC_CLIENT_SECRET"), RedirectURI: strings.TrimSpace(os.Getenv("RENEWLET_OIDC_REDIRECT_URI")), AllowedGroups: groups, AutoProvision: strings.EqualFold(os.Getenv("RENEWLET_OIDC_AUTO_PROVISION_ADMIN"), "true"), RequireVerifiedEmail: !strings.EqualFold(os.Getenv("RENEWLET_OIDC_REQUIRE_VERIFIED_EMAIL"), "false"), AllowedEndpointOrigins: origins}
}

func handleOIDCStart(app core.App, e *core.RequestEvent) error {
	s := oidcFromEnv()
	if !s.Enabled || s.Issuer == "" || s.ClientID == "" || s.ClientSecret == "" || s.RedirectURI == "" {
		return e.NotFoundError("OIDC is not enabled", nil)
	}
	if err := validateOIDCIssuer(s.Issuer); err != nil {
		return e.InternalServerError("OIDC issuer is invalid", err)
	}
	if err := validateOIDCRedirectURI(s.RedirectURI); err != nil {
		return e.InternalServerError("OIDC redirect URI is invalid", err)
	}
	d, err := oidcDiscoveryFor(e.Request.Context(), s.Issuer)
	if err != nil {
		return e.InternalServerError("OIDC discovery failed", err)
	}
	state, verifier, nonce := randomToken(32), randomToken(32), randomToken(32)
	next := safeOIDCNext(e.Request.URL.Query().Get("next"))
	setOIDCCookie(e, "renewlet_oidc_state", state, oidcStateTTL, true)
	setOIDCCookie(e, "renewlet_oidc_verifier", verifier, oidcStateTTL, true)
	setOIDCCookie(e, "renewlet_oidc_nonce", nonce, oidcStateTTL, true)
	setOIDCCookie(e, "renewlet_oidc_next", next, oidcStateTTL, true)
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])
	u, _ := url.Parse(d.AuthorizationEndpoint)
	q := u.Query()
	q.Set("client_id", s.ClientID)
	q.Set("redirect_uri", s.RedirectURI)
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email groups")
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return e.Redirect(http.StatusFound, u.String())
}

func handleOIDCCallback(app core.App, e *core.RequestEvent) error {
	s := oidcFromEnv()
	if !s.Enabled {
		return e.NotFoundError("OIDC is not enabled", nil)
	}
	if err := validateOIDCIssuer(s.Issuer); err != nil {
		return e.InternalServerError("OIDC issuer is invalid", err)
	}
	if err := validateOIDCRedirectURI(s.RedirectURI); err != nil {
		return e.InternalServerError("OIDC redirect URI is invalid", err)
	}
	q := e.Request.URL.Query()
	if q.Get("error") != "" {
		return e.UnauthorizedError("OIDC authorization denied", errors.New(q.Get("error")))
	}
	get := func(n string) string {
		c, err := e.Request.Cookie(n)
		if err != nil {
			return ""
		}
		return c.Value
	}
	state, verifier, nonce := get("renewlet_oidc_state"), get("renewlet_oidc_verifier"), get("renewlet_oidc_nonce")
	if state == "" || verifier == "" || nonce == "" || subtle.ConstantTimeCompare([]byte(state), []byte(q.Get("state"))) != 1 {
		return e.UnauthorizedError("OIDC state validation failed", nil)
	}
	d, err := oidcDiscoveryFor(e.Request.Context(), s.Issuer)
	if err != nil {
		return e.InternalServerError("OIDC discovery failed", err)
	}
	conf := oauth2.Config{ClientID: s.ClientID, ClientSecret: s.ClientSecret, Endpoint: oauth2.Endpoint{AuthURL: d.AuthorizationEndpoint, TokenURL: d.TokenEndpoint}, RedirectURL: s.RedirectURI, Scopes: []string{"openid", "profile", "email", "groups"}}
	tok, err := conf.Exchange(e.Request.Context(), q.Get("code"), oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		return e.UnauthorizedError("OIDC token exchange failed", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return e.UnauthorizedError("OIDC identity token missing", nil)
	}
	claims, err := verifyOIDCIDToken(e.Request.Context(), raw, d, s, nonce)
	if err != nil {
		return e.UnauthorizedError("OIDC identity validation failed", err)
	}
	if s.RequireVerifiedEmail && !claims.EmailVerified {
		return e.ForbiddenError("OIDC email is not verified", nil)
	}
	if !oidcGroupAllowed(claims.Groups, s.AllowedGroups) {
		return e.ForbiddenError("OIDC account is not allowed", nil)
	}
	user, err := oidcFindOrLinkUser(app, claims, s.AutoProvision)
	if err != nil {
		return e.ForbiddenError("OIDC account is not linked", err)
	}
	response, err := createAppSessionResponse(app, user)
	if err != nil {
		return e.InternalServerError("session creation failed", err)
	}
	setAppSessionCookies(e, response.token, response.csrfToken, response.Session.ExpiresAt)
	clearOIDCCookies(e)
	return e.Redirect(http.StatusFound, safeOIDCNext(get("renewlet_oidc_next")))
}

func validateOIDCIssuer(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("issuer must be an https origin")
	}
	return nil
}

func oidcOrigin(u *url.URL) string { return strings.ToLower(u.Scheme + "://" + u.Host) }

func validateOIDCRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || net.ParseIP(u.Hostname()) != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path == "" || !strings.HasSuffix(u.Path, "/api/app/auth/oidc/callback") {
		return errors.New("redirect URI must be an exact HTTPS callback")
	}
	return nil
}

func oidcHTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: oidcHTTPTransport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
}

var oidcHTTPTransport http.RoundTripper = http.DefaultTransport

func oidcDiscoveryFor(ctx context.Context, issuer string) (oidcDiscovery, error) {
	var d oidcDiscovery
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	client := oidcHTTPClient()
	res, err := client.Do(req)
	if err != nil {
		return d, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return d, fmt.Errorf("discovery status %d", res.StatusCode)
	}
	err = json.NewDecoder(res.Body).Decode(&d)
	if err != nil || strings.TrimRight(d.Issuer, "/") != issuer {
		return d, errors.New("invalid discovery issuer")
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.JWKSURI == "" {
		return d, errors.New("incomplete discovery")
	}
	for _, endpoint := range []string{d.AuthorizationEndpoint, d.TokenEndpoint, d.JWKSURI} {
		u, parseErr := url.Parse(endpoint)
		if parseErr != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !oidcFromEnv().AllowedEndpointOrigins[oidcOrigin(u)] {
			return d, errors.New("discovery contains an unsafe endpoint")
		}
	}
	return d, nil
}

func verifyOIDCIDToken(ctx context.Context, raw string, d oidcDiscovery, s oidcSettings, nonce string) (oidcClaims, error) {
	var out oidcClaims
	ks, err := fetchOIDCKeys(ctx, d.JWKSURI)
	if err != nil {
		return out, err
	}
	tok, err := jwt.ParseWithClaims(raw, &out, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, errors.New("unsupported signing algorithm")
		}
		kid, _ := t.Header["kid"].(string)
		for _, k := range ks.Keys {
			if k.Kid == kid && k.Kty == "RSA" && k.Alg == "RS256" && (k.Use == "" || k.Use == "sig") {
				n, e := base64.RawURLEncoding.DecodeString(k.N)
				if e != nil {
					return nil, e
				}
				eb, e := base64.RawURLEncoding.DecodeString(k.E)
				if e != nil {
					return nil, e
				}
				exponent := new(big.Int).SetBytes(eb).Int64()
				if len(n) < 256 || (exponent != 3 && exponent != 65537) {
					return nil, errors.New("unsafe RSA signing key")
				}
				return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exponent)}, nil
			}
		}
		return nil, errors.New("unknown signing key")
	}, jwt.WithIssuer(s.Issuer), jwt.WithAudience(s.ClientID), jwt.WithLeeway(time.Minute))
	if err != nil || tok == nil || !tok.Valid || out.Subject == "" || out.Email == "" || out.Nonce != nonce {
		return out, errors.New("invalid claims")
	}
	return out, nil
}
func fetchOIDCKeys(ctx context.Context, uri string) (oidcKeySet, error) {
	var k oidcKeySet
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !oidcFromEnv().AllowedEndpointOrigins[oidcOrigin(u)] {
		return k, errors.New("untrusted jwks URL")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	res, err := oidcHTTPClient().Do(req)
	if err != nil {
		return k, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return k, fmt.Errorf("jwks status %d", res.StatusCode)
	}
	err = json.NewDecoder(res.Body).Decode(&k)
	return k, err
}
func oidcGroupAllowed(groups []string, allowed map[string]bool) bool {
	for _, g := range groups {
		if allowed[g] {
			return true
		}
	}
	return false
}
func oidcFindOrLinkUser(app core.App, c oidcClaims, provision bool) (*core.Record, error) {
	identity, err := app.FindFirstRecordByFilter("oidc_identities", "issuer={:issuer} && subject={:subject}", dbx.Params{"issuer": c.Issuer, "subject": c.Subject})
	if err == nil {
		user, e := app.FindRecordById("users", identity.GetString("user"))
		if e != nil || user.GetBool("banned") || user.GetString("role") != "admin" {
			return nil, errors.New("linked account unavailable")
		}
		return user, nil
	}
	user, err := app.FindAuthRecordByEmail("users", c.Email)
	if err != nil {
		if !provision {
			return nil, errors.New("unknown account")
		}
		user, err = createUser(app, firstNonEmpty(c.Name, c.Email), c.Email, randomToken(32), "admin")
		if err != nil {
			return nil, err
		}
	}
	if !user.Verified() || user.GetBool("banned") || user.GetString("role") != "admin" {
		return nil, errors.New("not an eligible admin")
	}
	col, err := app.FindCollectionByNameOrId("oidc_identities")
	if err != nil {
		return nil, err
	}
	rec := core.NewRecord(col)
	rec.Set("user", user.Id)
	rec.Set("issuer", c.Issuer)
	rec.Set("subject", c.Subject)
	if err = app.Save(rec); err != nil {
		return nil, err
	}
	return user, nil
}

// linkOIDCIdentity performs an explicit, idempotent administrator mapping.
// It deliberately does not auto-provision or match by email alone.
func linkOIDCIdentity(app core.App, req adminOIDCLinkRequest) error {
	s := oidcFromEnv()
	issuer := strings.TrimRight(strings.TrimSpace(req.Issuer), "/")
	email := strings.TrimSpace(req.Email)
	subject := strings.TrimSpace(req.Subject)
	if !s.Enabled || s.Issuer == "" || issuer != s.Issuer {
		return errors.New("issuer is not the configured OIDC provider")
	}
	if err := validateOIDCIssuer(issuer); err != nil {
		return err
	}
	if subject == "" || email == "" {
		return errors.New("subject and email are required")
	}
	user, err := app.FindRecordById("users", strings.TrimSpace(req.UserID))
	if err != nil {
		return errors.New("target user not found")
	}
	if user.GetBool("banned") || user.GetString("role") != "admin" || !user.Verified() {
		return errors.New("target user must be a verified administrator")
	}
	if !strings.EqualFold(strings.TrimSpace(user.GetString("email")), email) {
		return errors.New("OIDC email must match the target user")
	}
	identity, err := app.FindFirstRecordByFilter("oidc_identities", "issuer={:issuer} && subject={:subject}", dbx.Params{"issuer": issuer, "subject": subject})
	if err == nil {
		if identity.GetString("user") != user.Id {
			return errors.New("OIDC identity is already linked to another user")
		}
		return nil
	}
	if _, err := app.FindFirstRecordByFilter("oidc_identities", "user={:user} && issuer={:issuer}", dbx.Params{"user": user.Id, "issuer": issuer}); err == nil {
		return errors.New("target user already has an identity for this provider")
	}
	col, err := app.FindCollectionByNameOrId("oidc_identities")
	if err != nil {
		return err
	}
	rec := core.NewRecord(col)
	rec.Set("user", user.Id)
	rec.Set("issuer", issuer)
	rec.Set("subject", subject)
	return app.Save(rec)
}
func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return strings.TrimSpace(a)
	}
	return strings.TrimSpace(b)
}
func safeOIDCNext(n string) string {
	if strings.HasPrefix(n, "/") && !strings.HasPrefix(n, "//") {
		return n
	}
	return "/"
}
func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func setOIDCCookie(e *core.RequestEvent, name, value string, maxAge time.Duration, httpOnly bool) {
	e.Response.Header().Add("Set-Cookie", (&http.Cookie{Name: name, Value: value, Path: oidcCookiePath, MaxAge: int(maxAge.Seconds()), HttpOnly: httpOnly, Secure: appSessionCookieSecure(e.Request), SameSite: http.SameSiteLaxMode}).String())
}
func clearOIDCCookies(e *core.RequestEvent) {
	for _, n := range []string{"renewlet_oidc_state", "renewlet_oidc_verifier", "renewlet_oidc_nonce", "renewlet_oidc_next"} {
		setOIDCCookie(e, n, "", -time.Hour, true)
	}
}
