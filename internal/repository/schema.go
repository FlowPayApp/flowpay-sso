package repository

import "context"

// EnsureClientPortfolioColumns agrega created_by / assigned_to en clients.
// Criterio de cartera: el vendedor dueño es COALESCE(assigned_to, created_by).
func (db *DB) EnsureClientPortfolioColumns(ctx context.Context) error {
	stmts := []string{
		`ALTER TABLE clients ADD COLUMN IF NOT EXISTS created_by BIGINT NULL`,
		`ALTER TABLE clients ADD COLUMN IF NOT EXISTS assigned_to BIGINT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_clients_company_assigned_to ON clients (company_id, assigned_to)`,
		`CREATE INDEX IF NOT EXISTS idx_clients_company_created_by ON clients (company_id, created_by)`,
	}
	for _, q := range stmts {
		if _, err := db.ex.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}
