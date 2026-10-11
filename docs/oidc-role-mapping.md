# OIDC access-token role mapping

OpenList can evaluate one CEL expression against a verified OIDC access token
to select the native `admin`, `general`, or `guest` role for each login session.
The browser continues using the existing OpenList login token and frontend.
Provider access and refresh tokens stay in backend memory.

## Configuration

Configure the existing SSO settings with platform `OIDC`, an issuer discovery
URL, client ID, client secret, and the normal callback URLs. Register OpenList
as a confidential authorization-code client. The provider must issue signed
JWT access tokens for the configured resource, and support refresh tokens to
keep access working after expiry. Opaque access tokens are rejected; no
introspection or provider management API is used.

In **Manage → Settings → SSO**, configure the two additional private settings
below. The resource uses a string input and the CEL expression uses a multiline
input; both are saved through the existing settings API. Use the matching
frontend build for their translated labels and help text.

Two additional private SSO settings enable this feature:

| Setting | Value |
| --- | --- |
| `sso_oidc_resource` | Expected access-token audience and OAuth2 resource indicator, for example `https://openlist.example/api` |
| `sso_oidc_role_mapping` | CEL expression returning exactly `admin`, `general`, or `guest` |

Both settings default to empty. An empty role expression preserves the legacy
SSO login flow for accounts that have not been bound to this feature. A nonempty
expression requires a resource audience. OpenList adds `offline_access`, nonce,
and PKCE S256 to new authorization requests, and sends the resource indicator
with authorization, code exchange, and refresh. Configure provider consent and
any additional scopes using the existing extra-scopes setting.

For a provider whose access token contains an array named `roles`:

```cel
has(claims.roles) && claims.roles != null && 'base:admin' in claims.roles
  ? 'admin'
  : (has(claims.roles) && claims.roles != null && 'base:reader' in claims.roles
      ? 'general'
      : 'guest')
```

A separate instance can use `share:admin` and `share:reader` in its expression.
For space-separated OAuth2 scopes, an expression can instead test
`has(claims.scope) && claims.scope.matches('(^| )files:admin( |$)')`.
Use the actual claim structure issued for the resource by your provider.
`claims` is the sole policy input: it contains verified access-token claims,
including nested data. ID-token roles, UserInfo, browser input, and local user
roles are not policy inputs. CEL has no network or filesystem functions.

Return `guest` explicitly for users without a matching external role. Invalid
syntax, a non-string result, unsupported role names, missing claims that cause
evaluation errors, and exceeded evaluation limits reject authorization. There
is no implicit guest fallback for errors. Expressions are limited to 4,096
characters, 64 levels of parser recursion, and 10,000 evaluation cost units.
Editing the issuer, audience, or expression invalidates existing mapped
sessions on their next request; users must log in again.

## Accounts and file permissions

The stable account binding uses the exact issuer and verified ID-token subject.
Display names are only initial usernames. A different subject with the same
display name gets a distinct account, and renaming does not change ownership.
New accounts require native SSO auto-registration and use the existing SSO
default directory and permission bits. Administrators can adjust each account's
BasePath and Permission through normal user administration.

For `admin` and `general`, requests use the external user's own account and
native directory, metadata, and file-operation checks. Mapping `admin` gives
native administrator API access; it does not copy the built-in administrator's
BasePath or permission bits. `/api/me` reports the effective session role.
The stored account role stays unchanged, and different sessions can have
different roles for the same account.

For `guest`, requests use the built-in guest account's ID, BasePath, Permission,
and metadata restrictions. A disabled guest cannot authorize mapped guest
requests. The original external account still owns the session, so its disabled
state and password timestamp are checked, and logout affects that login alone.

Existing legacy SSO bindings are not migrated automatically. Before enabling
mapping, retain a separate unbound local administrator for recovery. Rebind
each legacy account explicitly through the existing SSO binding flow while
logged into that account with its native credential, or have a trusted local
administrator set its canonical SSO ID. The canonical ID is `oidc:` followed
by unpadded base64url of SHA-256 of the compact JSON array `[issuer, subject]`.
Use verified identity information when preparing an administrative binding.
If a legacy binding already exists for the supplied display identifier, login
requires explicit rebinding rather than creating a replacement account.

## Session lifecycle and authentication boundaries

Each successful login gets an independent random session ID inside its signed
OpenList token. Access tokens are verified against discovered asymmetric signing
keys, issuer, resource audience, expiry, not-before, and the original subject.
Authorization lasts until the earlier of the JWT expiry and OAuth2 `expires_in`.
After expiry, the next API request refreshes the grant and reevaluates CEL before
proceeding. Concurrent requests share one refresh per session. Rotated refresh
tokens replace the previous value; an omitted refresh token preserves it.
Failed refresh or invalid new claims terminate the session. Role changes take
effect when new claims are issued, not immediately during an unexpired grant.

Logout closes both the native credential and its backend OAuth2 session.
Account invalidation discovered on a request also clears that session. Session
storage expires with the OpenList token lifetime. Restarting OpenList requires
login again. Multiple replicas require session affinity; session replication
and persistence are not provided. Local logout does not revoke the provider's
grant or end the provider's global SSO session.

Mapped sessions cannot use personal account APIs to change identity bindings,
passwords, SSH keys, 2FA, or WebAuthn credentials. The same account restrictions
apply to self-editing through administrator user APIs. Existing passwords,
LDAP, WebAuthn, WebDAV, FTP, and SFTP credentials cannot log into a managed
account through an alternative route. These file protocols do not accept the
browser's OAuth2 session; use an explicitly separate native account if needed.
Clearing the role expression does not restore alternate authentication for
canonical `oidc:` bindings; explicitly unbind the account to restore it.

Unrelated native accounts, native recovery access, anonymous guest behavior,
and the operator's global S3 credentials retain their existing behavior.
The native `admin` role remains a trusted administrator with normal application
configuration powers. This feature does not introduce a restricted administrator
or make application configuration read-only.

## Verification

The integration tests use the real Gin login callbacks, authorization middleware,
current-user and administrator APIs, and disposable local storage. A local
simulated OIDC provider supplies discovery, JWKS, code exchange, and rotating
refresh tokens; no production credentials are needed.

```sh
go test ./internal/oidcauth ./server -run 'TestRoleMapping|TestOIDC' -count=1
go test -race ./internal/oidcauth ./server -run 'TestRoleMapping|TestOIDC' -count=1
go test ./...
```

### Initial usernames

`sso_oidc_username_mapping` optionally evaluates a CEL string expression over
verified ID-token `claims` when provisioning a new mapped OIDC account. For
example, `'oidc:' + claims.sub` produces `oidc:alice`. It does not change the
issuer/subject binding, authorize requests, or rename existing users. Leave it
empty to retain the existing username-claim behavior. Invalid expressions,
missing claims, empty names, path separators, control characters, surrounding
whitespace and names exceeding 255 bytes reject provisioning. Multiple issuers
should use distinct naming namespaces; username collisions remain separate
accounts and never bind to the existing account.
