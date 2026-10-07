package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/flowpay/flowpay-sso/internal/signup"
)

func splitFeatures(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	if out == nil {
		return []string{}
	}
	return out
}

func planFromRow(id, label, detail, period, features string, priceCLP int, highlight bool, commission float64) signup.Plan {
	return signup.Plan{
		ID:                id,
		Label:             label,
		Detail:            detail,
		Price:             signup.FormatCLP(priceCLP),
		Period:            period,
		Features:          splitFeatures(features),
		Highlight:         highlight,
		PriceCLP:          priceCLP,
		CommissionPercent: commission,
	}
}

const signupPlanSelect = `
SELECT id, label, detail, price_clp, period, features, highlight, commission_percent
FROM signup_plans
`

// ListSignupPlans devuelve los planes publicados, en el orden del menú.
func (db *DB) ListSignupPlans(ctx context.Context) ([]signup.Plan, error) {
	rows, err := db.ex.QueryContext(ctx, signupPlanSelect+` ORDER BY sort_order ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []signup.Plan
	for rows.Next() {
		var id, label, detail, period, features string
		var priceCLP int
		var highlight bool
		var commission float64
		if err := rows.Scan(&id, &label, &detail, &priceCLP, &period, &features, &highlight, &commission); err != nil {
			return nil, err
		}
		out = append(out, planFromRow(id, label, detail, period, features, priceCLP, highlight, commission))
	}
	return out, rows.Err()
}

// GetSignupPlan busca un plan por id.
func (db *DB) GetSignupPlan(ctx context.Context, id string) (signup.Plan, error) {
	var label, detail, period, features string
	var priceCLP int
	var highlight bool
	var commission float64
	err := db.ex.QueryRowContext(ctx, signupPlanSelect+` WHERE id = $1`, id).
		Scan(&id, &label, &detail, &priceCLP, &period, &features, &highlight, &commission)
	if err != nil {
		return signup.Plan{}, err
	}
	return planFromRow(id, label, detail, period, features, priceCLP, highlight, commission), nil
}

// UpdateSignupPlan guarda el texto, el precio y la comisión de un plan existente.
func (db *DB) UpdateSignupPlan(ctx context.Context, plan signup.Plan) error {
	tx, rw, err := db.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if plan.Highlight {
		if _, err := rw.ex.ExecContext(ctx, `UPDATE signup_plans SET highlight = FALSE WHERE id <> $1`, plan.ID); err != nil {
			return err
		}
	}
	res, err := rw.ex.ExecContext(ctx, `
UPDATE signup_plans
SET label = $2, detail = $3, price_clp = $4, features = $5, highlight = $6, commission_percent = $7
WHERE id = $1
`, plan.ID, strings.TrimSpace(plan.Label), strings.TrimSpace(plan.Detail), plan.PriceCLP, strings.Join(plan.Features, "\n"), plan.Highlight, plan.CommissionPercent)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return tx.Commit()
}

// SetCompanyCommercial asigna el plan y, si vienen, un precio o una comisión propios de esa empresa.
func (db *DB) SetCompanyCommercial(ctx context.Context, companyID int64, plan *string, price *int, clearPrice bool, commission *float64, clearCommission bool) error {
	var parts []string
	var args []any
	n := 1
	if plan != nil {
		parts = append(parts, fmt.Sprintf("requested_plan = $%d", n))
		args = append(args, strings.TrimSpace(*plan))
		n++
	}
	if clearPrice {
		parts = append(parts, "price_clp_override = NULL")
	} else if price != nil {
		parts = append(parts, fmt.Sprintf("price_clp_override = $%d", n))
		args = append(args, *price)
		n++
	}
	if clearCommission {
		parts = append(parts, "commission_percent_override = NULL")
	} else if commission != nil {
		parts = append(parts, fmt.Sprintf("commission_percent_override = $%d", n))
		args = append(args, *commission)
		n++
	}
	if len(parts) == 0 {
		return errors.New("nada que actualizar")
	}
	args = append(args, companyID)
	q := fmt.Sprintf("UPDATE companies SET %s WHERE id = $%d", strings.Join(parts, ", "), n)
	res, err := db.ex.ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	aff, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if aff == 0 {
		return sql.ErrNoRows
	}
	return nil
}
