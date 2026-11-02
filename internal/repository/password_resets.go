package repository

import (
	"context"
	"time"
)

type PasswordReset struct {
	CodeHash  string
	ExpiresAt time.Time
	Attempts  int
}

func (db *DB) SavePasswordReset(ctx context.Context, userID int64, codeHash string, expires time.Time) error {
	_, err := db.ex.ExecContext(ctx, `
INSERT INTO password_resets (user_id, code_hash, expires_at, attempts, created_at)
VALUES ($1, $2, $3, 0, NOW())
ON CONFLICT (user_id) DO UPDATE
SET code_hash = EXCLUDED.code_hash,
    expires_at = EXCLUDED.expires_at,
    attempts = 0,
    created_at = NOW()`, userID, codeHash, expires)
	return err
}

func (db *DB) GetPasswordReset(ctx context.Context, userID int64) (*PasswordReset, error) {
	var item PasswordReset
	err := db.ex.QueryRowContext(ctx, `
SELECT code_hash, expires_at, attempts FROM password_resets WHERE user_id = $1`, userID).
		Scan(&item.CodeHash, &item.ExpiresAt, &item.Attempts)
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (db *DB) AddPasswordResetAttempt(ctx context.Context, userID int64) (int, error) {
	var attempts int
	err := db.ex.QueryRowContext(ctx, `
UPDATE password_resets SET attempts = attempts + 1 WHERE user_id = $1 RETURNING attempts`, userID).Scan(&attempts)
	if err != nil {
		return 0, err
	}
	return attempts, nil
}

func (db *DB) DeletePasswordReset(ctx context.Context, userID int64) error {
	_, err := db.ex.ExecContext(ctx, `DELETE FROM password_resets WHERE user_id = $1`, userID)
	return err
}
