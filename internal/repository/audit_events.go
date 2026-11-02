package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/flowpay/flowpay-sso/internal/audit"
)

func (db *DB) EnsureAuditEvents(ctx context.Context) error {
	for _, q := range audit.SchemaStatements() {
		if _, err := db.ex.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) RecordAudit(ctx context.Context, e audit.Event) error {
	return audit.Insert(ctx, db.ex, e)
}

type AuditFilter struct {
	Domain    string
	Outcome   string
	CompanyID int64
	BeforeID  int64
	Limit     int
}

type AuditRow struct {
	ID          int64
	OccurredAt  time.Time
	Service     string
	Domain      string
	Action      string
	Outcome     string
	ActorUserID sql.NullInt64
	ActorRole   string
	CompanyID   sql.NullInt64
	TargetType  string
	TargetID    string
	IP          string
	Summary     string
	Metadata    json.RawMessage
}

func (db *DB) ListAuditEvents(ctx context.Context, f AuditFilter) ([]AuditRow, error) {
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := db.ex.QueryContext(ctx, `
SELECT id, occurred_at, service, domain, action, outcome,
	actor_user_id, actor_role, company_id, target_type, target_id,
	ip, summary, metadata
FROM audit_events
WHERE ($1 = '' OR domain = $1)
	AND ($2 = '' OR outcome = $2)
	AND ($3 = 0 OR company_id = $3)
	AND ($4 = 0 OR id < $4)
ORDER BY id DESC
LIMIT $5`, f.Domain, f.Outcome, f.CompanyID, f.BeforeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		var row AuditRow
		if err := rows.Scan(
			&row.ID, &row.OccurredAt, &row.Service, &row.Domain, &row.Action, &row.Outcome,
			&row.ActorUserID, &row.ActorRole, &row.CompanyID, &row.TargetType, &row.TargetID,
			&row.IP, &row.Summary, &row.Metadata,
		); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
