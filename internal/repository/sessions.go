package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type RefreshRotate string

const (
	RefreshOK      RefreshRotate = "ok"
	RefreshMissing RefreshRotate = "missing"
	RefreshReuse   RefreshRotate = "reuse"
	RefreshExpired RefreshRotate = "expired"
)

type RefreshRotation struct {
	Status      RefreshRotate
	UserID      int64
	AbsoluteAt  time.Time
	RevokedJTIs []string
}

func (db *DB) CreateAuthSession(ctx context.Context, userID int64, tokenHash, accessJTI string, accessExp, now, absolute time.Time) error {
	tx, rw, err := db.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var id int64
	if err := rw.ex.QueryRowContext(ctx, `
INSERT INTO auth_sessions (user_id, current_token_hash, created_at, last_seen_at, absolute_expires_at)
VALUES ($1, $2, $3, $3, $4)
RETURNING id`,
		userID, tokenHash, now, absolute,
	).Scan(&id); err != nil {
		return err
	}
	if _, err := rw.ex.ExecContext(ctx, `
INSERT INTO auth_session_tokens (token_hash, session_id) VALUES ($1, $2)`,
		tokenHash, id,
	); err != nil {
		return err
	}
	if _, err := rw.ex.ExecContext(ctx, `
INSERT INTO session_access_tokens (jti, session_id, expires_at) VALUES ($1, $2, $3)`,
		accessJTI, id, accessExp,
	); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) RememberAccessJTI(ctx context.Context, refreshHash, jti string, exp time.Time) error {
	res, err := db.ex.ExecContext(ctx, `
INSERT INTO session_access_tokens (jti, session_id, expires_at)
SELECT $1, s.id, $3
FROM auth_sessions s
WHERE s.current_token_hash = $2 AND s.revoked_at IS NULL`,
		jti, refreshHash, exp,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("sesión sin token de acceso")
	}
	return nil
}

// RotateRefresh valida el token presentado. Si ya fue usado, cierra esa sesión.
// Si sigue vigente, lo marca usado y deja el nuevo hash como el único válido.
func (db *DB) RotateRefresh(ctx context.Context, presentedHash, nextHash string, now time.Time, idle time.Duration) (RefreshRotation, error) {
	tx, rw, err := db.BeginTx(ctx)
	if err != nil {
		return RefreshRotation{}, err
	}
	defer tx.Rollback()

	var sessionID, userID int64
	var lastSeen, absolute time.Time
	var revoked sql.NullTime
	var consumed sql.NullTime
	err = rw.ex.QueryRowContext(ctx, `
SELECT s.id, s.user_id, s.last_seen_at, s.absolute_expires_at, s.revoked_at, t.consumed_at
FROM auth_session_tokens t
JOIN auth_sessions s ON s.id = t.session_id
WHERE t.token_hash = $1
FOR UPDATE`,
		presentedHash,
	).Scan(&sessionID, &userID, &lastSeen, &absolute, &revoked, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return RefreshRotation{Status: RefreshMissing}, nil
	}
	if err != nil {
		return RefreshRotation{}, err
	}

	out := RefreshRotation{UserID: userID, AbsoluteAt: absolute}
	if revoked.Valid || consumed.Valid {
		jtis, err := rw.takeSessionJTIs(ctx, sessionID)
		if err != nil {
			return RefreshRotation{}, err
		}
		if !revoked.Valid {
			if _, err := rw.ex.ExecContext(ctx, `UPDATE auth_sessions SET revoked_at = $2 WHERE id = $1`, sessionID, now); err != nil {
				return RefreshRotation{}, err
			}
		}
		if err := tx.Commit(); err != nil {
			return RefreshRotation{}, err
		}
		out.Status = RefreshReuse
		out.RevokedJTIs = jtis
		return out, nil
	}
	if !now.Before(absolute) || !now.Before(lastSeen.Add(idle)) {
		jtis, err := rw.takeSessionJTIs(ctx, sessionID)
		if err != nil {
			return RefreshRotation{}, err
		}
		if _, err := rw.ex.ExecContext(ctx, `UPDATE auth_sessions SET revoked_at = $2 WHERE id = $1`, sessionID, now); err != nil {
			return RefreshRotation{}, err
		}
		if err := tx.Commit(); err != nil {
			return RefreshRotation{}, err
		}
		out.Status = RefreshExpired
		out.RevokedJTIs = jtis
		return out, nil
	}

	if _, err := rw.ex.ExecContext(ctx, `
UPDATE auth_session_tokens SET consumed_at = $2 WHERE token_hash = $1`,
		presentedHash, now,
	); err != nil {
		return RefreshRotation{}, err
	}
	if _, err := rw.ex.ExecContext(ctx, `
INSERT INTO auth_session_tokens (token_hash, session_id) VALUES ($1, $2)`,
		nextHash, sessionID,
	); err != nil {
		return RefreshRotation{}, err
	}
	if _, err := rw.ex.ExecContext(ctx, `
UPDATE auth_sessions SET current_token_hash = $2, last_seen_at = $3 WHERE id = $1`,
		sessionID, nextHash, now,
	); err != nil {
		return RefreshRotation{}, err
	}
	if err := tx.Commit(); err != nil {
		return RefreshRotation{}, err
	}
	out.Status = RefreshOK
	return out, nil
}

func (db *DB) SessionUserByHash(ctx context.Context, tokenHash string) (int64, error) {
	var userID int64
	err := db.ex.QueryRowContext(ctx, `
SELECT s.user_id
FROM auth_session_tokens t
JOIN auth_sessions s ON s.id = t.session_id
WHERE t.token_hash = $1`, tokenHash).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return userID, err
}

func (db *DB) takeSessionJTIs(ctx context.Context, sessionID int64) ([]string, error) {
	return db.takeJTIs(ctx, `
INSERT INTO revoked_access_tokens (jti, expires_at)
SELECT jti, expires_at FROM session_access_tokens
WHERE session_id = $1 AND expires_at > NOW()
ON CONFLICT (jti) DO NOTHING
RETURNING jti`, sessionID)
}

func (db *DB) takeJTIs(ctx context.Context, query string, arg any) ([]string, error) {
	rows, err := db.ex.QueryContext(ctx, query, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var jti string
		if err := rows.Scan(&jti); err != nil {
			return nil, err
		}
		out = append(out, jti)
	}
	return out, rows.Err()
}

func (db *DB) RevokeUserSessions(ctx context.Context, userID int64) ([]string, error) {
	if db.raw == nil {
		return db.revokeUserSessions(ctx, userID)
	}
	tx, rw, err := db.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	jtis, err := rw.revokeUserSessions(ctx, userID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return jtis, nil
}

func (db *DB) revokeUserSessions(ctx context.Context, userID int64) ([]string, error) {
	jtis, err := db.takeJTIs(ctx, `
INSERT INTO revoked_access_tokens (jti, expires_at)
SELECT t.jti, t.expires_at
FROM session_access_tokens t
JOIN auth_sessions s ON s.id = t.session_id
WHERE s.user_id = $1 AND s.revoked_at IS NULL AND t.expires_at > NOW()
ON CONFLICT (jti) DO NOTHING
RETURNING jti`, userID)
	if err != nil {
		return nil, err
	}
	if _, err := db.ex.ExecContext(ctx, `
UPDATE auth_sessions SET revoked_at = NOW()
WHERE user_id = $1 AND revoked_at IS NULL`, userID); err != nil {
		return nil, err
	}
	return jtis, nil
}

func (db *DB) RevokeCompanySessions(ctx context.Context, companyID int64) ([]string, error) {
	if db.raw == nil {
		return db.revokeCompanySessions(ctx, companyID)
	}
	tx, rw, err := db.BeginTx(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	jtis, err := rw.revokeCompanySessions(ctx, companyID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return jtis, nil
}

func (db *DB) revokeCompanySessions(ctx context.Context, companyID int64) ([]string, error) {
	jtis, err := db.takeJTIs(ctx, `
INSERT INTO revoked_access_tokens (jti, expires_at)
SELECT t.jti, t.expires_at
FROM session_access_tokens t
JOIN auth_sessions s ON s.id = t.session_id
WHERE s.revoked_at IS NULL AND t.expires_at > NOW() AND s.user_id IN (
  SELECT user_id FROM company_users WHERE company_id = $1
)
ON CONFLICT (jti) DO NOTHING
RETURNING jti`, companyID)
	if err != nil {
		return nil, err
	}
	if _, err := db.ex.ExecContext(ctx, `
UPDATE auth_sessions SET revoked_at = NOW()
WHERE revoked_at IS NULL AND user_id IN (
  SELECT user_id FROM company_users WHERE company_id = $1
)`, companyID); err != nil {
		return nil, err
	}
	return jtis, nil
}

func (db *DB) CompanyMemberAccess(ctx context.Context, companyID, userID int64) (role string, active bool, err error) {
	err = db.ex.QueryRowContext(ctx, `
SELECT cu.role, u.is_active
FROM company_users cu
JOIN users u ON u.id = cu.user_id
WHERE cu.company_id = $1 AND cu.user_id = $2 AND u.is_platform_admin = FALSE
LIMIT 1`, companyID, userID).Scan(&role, &active)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, ErrCompanyUserNotFound
	}
	return role, active, err
}
