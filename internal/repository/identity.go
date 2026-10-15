package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (db *DB) CompanyIDForUser(ctx context.Context, userID int64) (int64, error) {
	var id int64
	err := db.ex.QueryRowContext(ctx, `SELECT company_id FROM company_users WHERE user_id = $1 LIMIT 1`, userID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return id, err
}

func (db *DB) SetUserTOTP(ctx context.Context, userID int64, secret string) error {
	_, err := db.ex.ExecContext(ctx, `UPDATE users SET totp_secret = $2 WHERE id = $1`, userID, secret)
	return err
}

func (db *DB) InsertAudit(ctx context.Context, actor, target, company int64, action string) error {
	_, err := db.ex.ExecContext(ctx, `
INSERT INTO auth_audit (actor_user_id, target_user_id, company_id, action)
VALUES (NULLIF($1, 0), NULLIF($2, 0), NULLIF($3, 0), $4)`,
		actor, target, company, action)
	return err
}

type LiveJTI struct {
	JTI     string
	Expires time.Time
}

func (db *DB) ListLiveRevokedJTIs(ctx context.Context) ([]LiveJTI, error) {
	rows, err := db.ex.QueryContext(ctx, `
SELECT jti, expires_at FROM revoked_access_tokens WHERE expires_at > NOW()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LiveJTI
	for rows.Next() {
		var item LiveJTI
		if err := rows.Scan(&item.JTI, &item.Expires); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
