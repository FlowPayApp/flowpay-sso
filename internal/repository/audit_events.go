package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
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
	Service   string
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
	UserAgent   string
	ClientHint  string
	Summary     string
	Metadata    json.RawMessage
	ActorName   string
	ActorEmail  string
	CompanyName string
	TargetLabel string
}

func (db *DB) ListAuditEvents(ctx context.Context, f AuditFilter) ([]AuditRow, error) {
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := db.ex.QueryContext(ctx, `
SELECT e.id, e.occurred_at, e.service, e.domain, e.action, e.outcome,
	e.actor_user_id, e.actor_role, e.company_id, e.target_type, e.target_id,
	e.ip, e.user_agent, e.client_hint, e.summary, e.metadata,
	COALESCE(actor.name, ''), COALESCE(actor.email, ''),
	COALESCE(co.name, ''),
	COALESCE(tu.name, ''), COALESCE(tc.name, ''), COALESCE(cl.name, ''), COALESCE(chcl.name, '')
FROM audit_events e
LEFT JOIN users actor ON actor.id = e.actor_user_id
LEFT JOIN companies co ON co.id = e.company_id
LEFT JOIN users tu
	ON e.target_type = 'user'
	AND tu.id = CASE WHEN e.target_id ~ '^[0-9]+$' THEN e.target_id::bigint END
LEFT JOIN companies tc
	ON e.target_type = 'company'
	AND tc.id = CASE WHEN e.target_id ~ '^[0-9]+$' THEN e.target_id::bigint END
LEFT JOIN clients cl
	ON e.target_type = 'client'
	AND cl.id = CASE WHEN e.target_id ~ '^[0-9]+$' THEN e.target_id::bigint END
LEFT JOIN charges ch
	ON e.target_type = 'charge'
	AND ch.id = CASE WHEN e.target_id ~ '^[0-9]+$' THEN e.target_id::bigint END
LEFT JOIN clients chcl ON chcl.id = ch.client_id
WHERE ($1 = '' OR e.service = $1)
	AND ($2 = '' OR e.domain = $2)
	AND ($3 = '' OR e.outcome = $3)
	AND ($4 = 0 OR e.company_id = $4)
	AND ($5 = 0 OR e.id < $5)
ORDER BY e.id DESC
LIMIT $6`, f.Service, f.Domain, f.Outcome, f.CompanyID, f.BeforeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		var row AuditRow
		var targetUser, targetCompany, targetClient, chargeClient string
		if err := rows.Scan(
			&row.ID, &row.OccurredAt, &row.Service, &row.Domain, &row.Action, &row.Outcome,
			&row.ActorUserID, &row.ActorRole, &row.CompanyID, &row.TargetType, &row.TargetID,
			&row.IP, &row.UserAgent, &row.ClientHint, &row.Summary, &row.Metadata,
			&row.ActorName, &row.ActorEmail, &row.CompanyName,
			&targetUser, &targetCompany, &targetClient, &chargeClient,
		); err != nil {
			return nil, err
		}
		row.TargetLabel = targetLabel(row.TargetType, targetUser, targetCompany, targetClient, chargeClient)
		out = append(out, row)
	}
	return out, rows.Err()
}

func targetLabel(kind, userName, companyName, clientName, chargeClient string) string {
	switch kind {
	case "user":
		return strings.TrimSpace(userName)
	case "company":
		return strings.TrimSpace(companyName)
	case "client":
		return strings.TrimSpace(clientName)
	case "charge":
		return strings.TrimSpace(chargeClient)
	default:
		return ""
	}
}
