# Native OIDC (Docker server)

The Docker server supports optional native OIDC login. It is disabled unless
`RENEWLET_OIDC_ENABLED=true`. Forward authentication remains an independent
defense and should stay enabled at the ingress.

Required environment values:

- `RENEWLET_OIDC_ISSUER` — an HTTPS OIDC issuer origin
- `RENEWLET_OIDC_CLIENT_ID`
- `RENEWLET_OIDC_CLIENT_SECRET` — store in the deployment secret store
- `RENEWLET_OIDC_REDIRECT_URI` — the exact HTTPS callback

Optional values:

- `RENEWLET_OIDC_ALLOWED_GROUPS` (comma separated, defaults to `admins`)
- `RENEWLET_OIDC_AUTO_PROVISION_ADMIN` (defaults to `false`)
- `RENEWLET_OIDC_REQUIRE_VERIFIED_EMAIL` (defaults to `true`)
- `RENEWLET_OIDC_ALLOWED_ENDPOINT_ORIGINS` (optional comma-separated HTTPS origins for a provider whose discovery document deliberately places endpoints on another host; the issuer origin is always trusted)

The callback uses authorization code + PKCE, state, nonce, issuer/audience/
expiry/signature checks, verified-email linking, and an internal unique
issuer/subject identity table. Unknown accounts are rejected unless the
explicit admin-only provisioning switch is enabled. Local passwords, MFA,
passkeys, recovery codes, and existing sessions remain available.

The callback never trusts proxy headers as identity assertions. Discovery and
JWKS requests do not follow redirects and only use the issuer or explicitly
allowlisted HTTPS origins; private issuer hostnames remain supported. The
callback URI must be an exact HTTPS `/api/app/auth/oidc/callback` URL without
query or fragment. The Cloudflare Worker runtime does not inherit
this Docker-only feature until an equivalent implementation is separately
reviewed.
