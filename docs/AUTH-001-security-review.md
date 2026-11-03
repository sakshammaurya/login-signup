# AUTH-001: Login credential regression coverage

## Scope

Document the history of the login SQL injection fix accurately, expand database-backed coverage for credential outcomes, and preserve the existing login messages and redirects.

## Security history

An older version of `login-system/login.php` interpolated an escaped email into its SQL string. That implementation is present in the parent of commit `f68971d` (`Use prepared statement for login lookup`). The prepared lookup was added in `f68971d`, and `findUserByEmail()` was added in `bef3a51` (`Add prepared user lookup helper`). Both changes were merged into `master` by commit `ebaf3f8` before this PR's base was created.

Therefore, the parameterized SQL lookup is already present in the base branch. This PR does not introduce the SQL injection fix and should not be represented as the commit that closed the original vulnerability.

## Changes in this PR

- Added `checkLoginCredentials()` in `login-system/auth.php`. It uses the pre-existing `findUserByEmail()` lookup, verifies the password hash, and returns `authenticated`, `unknown_email`, or `invalid_password`.
- Updated `login-system/login.php` to use the shared credential check while preserving the existing session setup, messages, and redirects.
- Expanded the existing regression test from lookup-only checks to cover valid credentials, incorrect password, unknown email, and SQL injection-shaped email input.
- Added Docker Compose setup, architecture and run documentation, and corrected both form targets to `index1.php`.

## Regression coverage

`login-system/tests/login_query_regression.php` creates a temporary fixture inside a transaction and verifies the database-backed credential-check results:

1. Correct email and password authenticate the fixture account.
2. A wrong password returns an invalid-password result without an authenticated user.
3. An unknown email returns an unknown-email result without an authenticated user.
4. The injection-shaped email `' OR '1'='1` is treated as a literal value and cannot authenticate.

The test rolls back its fixture in a `finally` block. It calls `checkLoginCredentials()` directly. It does **not** make an HTTP request through `index1.php` or assert the resulting PHP session, redirect, or response message. The separate HTTP smoke check below requests only the login page and confirms the forms render. Run the credential regression against the Compose database using:

```sh
docker compose exec -T app php tests/login_query_regression.php
```

## Verification record

- Source inspection: confirmed the base branch already has the bound-parameter lookup; this PR's handler only establishes the authenticated session for the `authenticated` result.
- Container build and startup: `docker compose config` and `docker compose up --build -d` passed. The app and database containers started successfully; MySQL became healthy before the app started.
- Regression integration test: `docker compose exec -T app php tests/login_query_regression.php` passed:

  ```text
  PASS: valid credentials authenticate the fixture user.
  PASS: an incorrect password is rejected.
  PASS: an unknown email is rejected.
  PASS: injection-shaped email input cannot authenticate.
  ```

- PHP syntax checks passed for `auth.php`, `login.php`, `index1.php`, and `tests/login_query_regression.php` under PHP 8.4.27 with `mysqli`/`mysqlnd`. The integration test ran against MySQL 8.4.13.
- HTTP smoke check: `GET http://127.0.0.1:8080/index1.php` returned HTTP 200 and rendered both login and signup forms.
- `git diff --check` passed.
- The page smoke check exposed both forms posting to a nonexistent `index.php`; their targets were corrected to `index1.php` so form submissions reach the dispatcher. The HTTP authentication session and redirect behavior were not exercised end-to-end.

## Remaining scope

The prepared login lookup predates this PR. This PR adds database-backed credential regression coverage but does not provide endpoint-level session/redirect coverage. Other request-driven account queries in registration and recovery/verification files still need separate review and parameterization. This proof does not claim the whole application is production-secure.
