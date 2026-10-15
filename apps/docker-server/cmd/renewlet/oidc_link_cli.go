package main

import (
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/pocketbase/pocketbase"
	_ "modernc.org/sqlite"
)

// runOIDCLink is a console-only recovery path for installations whose
// local admin cannot sign in yet. It links an existing verified administrator;
// it never creates users, changes passwords, or edits the database directly.
func runOIDCLink(args []string) error {
	fs := flag.NewFlagSet("oidc-link", flag.ContinueOnError)
	dataDir := fs.String("data-dir", "", "PocketBase data directory (required)")
	userID := fs.String("user-id", "", "existing local administrator ID (required)")
	issuer := fs.String("issuer", "", "trusted OIDC issuer (required)")
	subject := fs.String("subject", "", "verified OIDC subject (required)")
	email := fs.String("email", "", "verified OIDC email (must match the local user)")
	expectedLocalEmail := fs.String("expected-local-email", "", "expected existing local email for an explicit cross-email mapping")
	confirmCrossEmail := fs.Bool("confirm-cross-email", false, "confirm the explicit cross-email mapping")
	dryRun := fs.Bool("dry-run", false, "validate the mapping without writing an identity")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*dataDir) == "" || strings.TrimSpace(*userID) == "" || strings.TrimSpace(*issuer) == "" || strings.TrimSpace(*subject) == "" || strings.TrimSpace(*email) == "" {
		return errors.New("oidc-link requires --data-dir, --user-id, --issuer, --subject and --email")
	}
	request := adminOIDCLinkRequest{UserID: *userID, Issuer: *issuer, Subject: *subject, Email: *email}
	allowEmailMismatch := strings.TrimSpace(*expectedLocalEmail) != ""
	if allowEmailMismatch && !*confirmCrossEmail {
		return errors.New("cross-email mapping requires --confirm-cross-email")
	}
	if *dryRun {
		if err := preflightOIDCIdentityReadOnly(*dataDir, request, *expectedLocalEmail, allowEmailMismatch); err != nil {
			return fmt.Errorf("OIDC identity preflight: %w", err)
		}
		fmt.Println("OIDC identity preflight passed")
		return nil
	}
	pb := pocketbase.NewWithConfig(pocketbase.Config{DefaultDataDir: *dataDir, HideStartBanner: true})
	if err := pb.Bootstrap(); err != nil {
		return fmt.Errorf("bootstrap: %w", err)
	}
	defer pb.ClearBootstrap()
	if err := ensureSchema(pb.App); err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	if err := linkOIDCIdentityWithLocalEmail(pb.App, request, *expectedLocalEmail, allowEmailMismatch); err != nil {
		return fmt.Errorf("link OIDC identity: %w", err)
	}
	fmt.Println("OIDC identity linked")
	return nil
}

// preflightOIDCIdentityReadOnly intentionally avoids PocketBase Bootstrap:
// bootstrap may create or migrate schema. The URI enforces SQLite read-only
// mode and query_only prevents accidental writes even if this code changes.
func preflightOIDCIdentityReadOnly(dataDir string, req adminOIDCLinkRequest, expectedLocalEmail string, allowEmailMismatch bool) error {
	settings := oidcFromEnv()
	issuer := strings.TrimRight(strings.TrimSpace(req.Issuer), "/")
	if !settings.Enabled || settings.Issuer == "" || issuer != settings.Issuer {
		return errors.New("issuer is not the configured OIDC provider")
	}
	if err := validateOIDCIssuer(issuer); err != nil {
		return err
	}
	if strings.TrimSpace(req.Subject) == "" || !isValidEmailAddress(strings.TrimSpace(req.Email)) {
		return errors.New("subject and valid email are required")
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dataDir, "data.db")+"?mode=ro&_pragma=query_only(1)")
	if err != nil {
		return err
	}
	defer db.Close()
	var email, role string
	var verified, banned int
	err = db.QueryRow(`SELECT email, verified, banned, role FROM users WHERE id = ?`, strings.TrimSpace(req.UserID)).Scan(&email, &verified, &banned, &role)
	if err == sql.ErrNoRows {
		return errors.New("target user not found")
	}
	if err != nil {
		return err
	}
	if verified == 0 || banned != 0 || role != "admin" {
		return errors.New("target user must be a verified administrator")
	}
	localEmail := strings.TrimSpace(email)
	if allowEmailMismatch {
		if strings.TrimSpace(expectedLocalEmail) == "" || !strings.EqualFold(localEmail, strings.TrimSpace(expectedLocalEmail)) {
			return errors.New("target user email does not match the expected local email")
		}
	} else if !strings.EqualFold(localEmail, strings.TrimSpace(req.Email)) {
		return errors.New("OIDC email must match the target user")
	}
	var linkedUser string
	err = db.QueryRow(`SELECT user FROM oidc_identities WHERE issuer = ? AND subject = ?`, issuer, strings.TrimSpace(req.Subject)).Scan(&linkedUser)
	if err == nil && linkedUser != strings.TrimSpace(req.UserID) {
		return errors.New("OIDC identity is already linked to another user")
	}
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	var existing int
	err = db.QueryRow(`SELECT count(*) FROM oidc_identities WHERE user = ? AND issuer = ?`, strings.TrimSpace(req.UserID), issuer).Scan(&existing)
	if err != nil {
		return err
	}
	if existing > 0 && linkedUser == "" {
		return errors.New("target user already has an identity for this provider")
	}
	return nil
}
