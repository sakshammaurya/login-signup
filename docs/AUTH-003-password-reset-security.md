# AUTH-003: Password reset token security

## Implementation

`forgot.php` validates scalar email input and uses a prepared lookup. It returns the same response for known and unknown addresses. For a known account, it issues a 32-byte `random_bytes()` token encoded as 64 lowercase hexadecimal characters. The database stores only the SHA-256 digest in `password_reset_token_hash` and a one-hour UTC expiry in `password_reset_expires_at`. A replacement request overwrites the prior digest. Reset links use `APP_BASE_URL` (local Docker default `http://localhost:8080`) rather than request headers.

If `mail()` reports failure, the application clears the matching issued token and logs a generic operational message. Neither raw tokens nor account data are included in that message. The public response remains the same.

`reset.php` validates scalar, well-formed parameters and checks the digest and expiry with a prepared statement before rendering the form. Invalid links redirect and exit without rendering it. Hidden fields are HTML-escaped and are treated only as submitted values, not authorization.

`reset_password.php` accepts POST only, validates all values as strings, checks password confirmation, and rejects passwords over bcrypt's 72-byte input limit. It hashes the new password and performs one prepared conditional update requiring matching email, token digest, and unexpired timestamp. The same update changes the password and clears both reset fields. Clearing the non-null token digest guarantees a matching, valid update changes the row; a second or concurrent request no longer matches.

The legacy `hash`, `verification_token_hash`, and `verification_expires_at` columns are unchanged. Reset requests do not modify verification state.

## Schema migration

Fresh databases receive the reset columns from `login-system/sql/sql.txt`. Existing databases apply:

```sh
docker compose exec -T db mysql -uroot -p accounts < login-system/sql/migrations/2026-11-04-password-reset-tokens.sql
```

Existing links based on the legacy `hash` field are intentionally invalid under the new reset flow. Users must request a new password reset link after deployment. The legacy column itself remains in the schema.

## Verification

Run the database and HTTP tests:

```sh
docker compose exec -T app php tests/password_reset_regression.php
docker compose exec -T app php tests/password_reset_endpoint_regression.php
```

The database suite checks token entropy/digest storage, password change, invalid/expired/replaced/reused tokens, wrong-account rejection, unchanged password on failure, and two-connection single use. The HTTP suite checks valid form rendering and submission, redirects and session messages, invalid/expired/replaced/reused/wrong-account cases, confirmation mismatch, malformed arrays, simultaneous duplicate reset posts, and generic responses for known and unknown emails. It also checks reset leaves AUTH-002 verification fields untouched and that a definite email-delivery failure clears the issued reset token.

The Docker Apache configuration changes the `combined` access-log format to record the request path without query strings or referrers, preventing reset bearer tokens from appearing in those logs. Other production web servers must be configured to redact query strings and referrers as well.

## Remaining limitations

- The application still uses PHP `mail()` and does not provide a production mail transport. Its boolean failure path is handled, but delivery is not guaranteed.
- Email enumeration is avoided through a common response and redirect, but the code path can still have timing differences between an unknown account and email delivery for a known account.
- The legacy `hash` column remains populated by registration for compatibility but is not reset authorization. Its other legacy consumers should be reviewed before removing it.
- This does not add CSRF protection or redesign password policy; those remain separate application-wide concerns.
