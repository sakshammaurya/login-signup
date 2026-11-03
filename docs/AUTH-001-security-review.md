# AUTH-001: SQL injection prevention in login

## Scope

Secure the login account lookup so email input is treated as data, add regression coverage for the credential outcomes, and preserve the existing login messages and redirects.

## Finding and root cause

Before AUTH-001, `login-system/login.php` assembled a `SELECT` statement by inserting the submitted email into the SQL string. User-controlled input could therefore be interpreted as SQL syntax. Escaping input manually is easy to apply inconsistently and depends on correct character-set handling.

## Fix

`login-system/auth.php` now fetches accounts with a MySQLi prepared statement (`WHERE email = ?`) and binds the submitted email using the string parameter type. The database parses the SQL structure separately from the bound value. Login also uses the shared credential-check function, which verifies the stored password hash and returns one of three outcomes: authenticated, unknown email, or invalid password. `login-system/login.php` maps those outcomes to the existing session setup, messages, and redirects.

## Regression coverage

`login-system/tests/login_query_regression.php` creates a temporary fixture inside a transaction and verifies:

1. Correct email and password authenticate the fixture account.
2. A wrong password returns an invalid-password result without an authenticated user.
3. An unknown email returns an unknown-email result without an authenticated user.
4. The injection-shaped email `' OR '1'='1` is treated as a literal value and cannot authenticate.

The test rolls back its fixture in a `finally` block. Run it against the Compose database using:

```sh
docker compose exec -T app php tests/login_query_regression.php
```

## Verification record

- Source inspection: confirmed the login query uses a bound parameter and the login handler only establishes the authenticated session for the `authenticated` result.
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
- The page smoke check exposed both forms posting to a nonexistent `index.php`; their targets were corrected to `index1.php` so the form requests reach the dispatcher.

## Remaining scope

This closes the login lookup issue only. Other request-driven account queries in registration and recovery/verification files still need separate review and parameterization. This proof does not claim the whole application is production-secure.
