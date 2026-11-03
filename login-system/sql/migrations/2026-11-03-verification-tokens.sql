-- AUTH-002: dedicated hashed verification token lifecycle.
-- Existing accounts remain unchanged. Unverified accounts must request a fresh
-- verification token after this migration; legacy `hash` remains for password reset.
ALTER TABLE users
    ADD COLUMN verification_token_hash CHAR(64) NULL,
    ADD COLUMN verification_expires_at DATETIME NULL;
