# AUTH-002: Email verification token security

## Findings addressed

- The former token used `md5(rand(0, 1000))`, making it guessable from a tiny non-cryptographic space.
- Verification tokens had no expiry and were stored in plaintext in the password-reset `hash` column.
- Verification selected a matching account and later updated it in a separate query, allowing duplicate requests to race.
- Registration and verification interpolated escaped values into SQL.

## Implementation

Registration generates 32 random bytes using `random_bytes()` and hex-encodes the value for a URL-safe 256-bit bearer token. It stores only `SHA-256(token)` in `verification_token_hash` and sets `verification_expires_at` to 24 hours after issuance. Registration email lookup and insertion use prepared statements. The URL encodes the email.

Verification accepts only scalar email and a 64-character lowercase hexadecimal token. It hashes the supplied token and runs one prepared conditional update requiring the matching email and digest, `active = 0`, and an expiry later than MySQL's `UTC_TIMESTAMP()`. The same statement activates the user and clears the token fields. Exactly one row must be affected. Invalid, expired, reused, already-used, wrong-account, and concurrent duplicate attempts therefore do not activate an account.

The pre-existing `hash` field remains unchanged for password-reset compatibility; AUTH-003 later moved reset authorization into dedicated reset-token fields. No raw verification token is written to the database or emitted by tests.

## Schema migration

Fresh databases use the updated `login-system/sql/sql.txt`. Existing installations must apply:

```sh
docker compose exec -T db mysql -uroot -p accounts < login-system/sql/migrations/2026-11-03-verification-tokens.sql
```

The migration adds nullable `verification_token_hash CHAR(64)` and `verification_expires_at DATETIME` fields. Existing accounts are preserved. Existing unverified users must receive a new verification link because old tokens are not migrated. At the time AUTH-002 was implemented, password reset still used `hash`; AUTH-003 moved it to separate columns without changing this migration.

## Tests

Run `docker compose exec -T app php tests/verification_token_regression.php`. The database-backed test checks:

1. Token format, entropy source, and digest relationship.
2. Valid token activation and token consumption.
3. Invalid and expired token rejection.
4. Reuse and already-verified account rejection.
5. Wrong-account rejection.
6. Replacement invalidates the prior token.
7. Two separate database connections attempting to consume the same token allow only one successful update.

Fixtures are created using random test-only addresses and removed after the cases complete. Two connections validate atomic single-use behavior; this is a targeted concurrency regression, not a high-load stress test.

The HTTP endpoint suite runs as `docker compose exec -T app php tests/verification_endpoint_regression.php`. It sends requests through Apache to `verify.php`, checks success/error redirects, verifies that the existing activation message is stored in and rendered from the same PHP session, checks database state for valid and rejected tokens, and rejects malformed array parameters.

## Remaining limitations

- The deployment-specific verification link origin remains hard-coded to localhost, as changing environment-specific URLs is outside this focused security fix.
- The legacy `hash` field remains present for compatibility but is no longer used by the reset authorization flow.
- Email delivery success is not checked by the legacy registration flow.
- Expiry timestamps are written in UTC and compared against MySQL `UTC_TIMESTAMP()`.
