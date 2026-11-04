-- AUTH-003: dedicated password-reset token lifecycle.
-- Existing password hashes, legacy `hash`, and verification-token fields are unchanged.
ALTER TABLE users
    ADD COLUMN password_reset_token_hash CHAR(64) NULL,
    ADD COLUMN password_reset_expires_at DATETIME NULL;
