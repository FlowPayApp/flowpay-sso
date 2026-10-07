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

// EnsureSignupColumns guarda el teléfono y el plan pedido en el registro público.
func (db *DB) EnsureSignupColumns(ctx context.Context) error {
	stmts := []string{
		`ALTER TABLE companies ADD COLUMN IF NOT EXISTS contact_phone TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE companies ADD COLUMN IF NOT EXISTS requested_plan TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE companies ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ NULL`,
		`ALTER TABLE companies ADD COLUMN IF NOT EXISTS price_clp_override INT NULL`,
		`ALTER TABLE companies ADD COLUMN IF NOT EXISTS commission_percent_override NUMERIC(5,2) NULL`,
		`CREATE TABLE IF NOT EXISTS signup_plans (
			id TEXT PRIMARY KEY,
			label TEXT NOT NULL,
			detail TEXT NOT NULL DEFAULT '',
			price_clp INT NOT NULL,
			period TEXT NOT NULL DEFAULT 'mes',
			features TEXT NOT NULL DEFAULT '',
			highlight BOOLEAN NOT NULL DEFAULT FALSE,
			commission_percent NUMERIC(5,2) NOT NULL DEFAULT 0,
			sort_order INT NOT NULL DEFAULT 0
		)`,
		`INSERT INTO signup_plans (id, label, detail, price_clp, period, features, highlight, commission_percent, sort_order) VALUES
			('esencial', 'Esencial', 'Para una operación chica que hoy cobra a mano.', 39000, 'mes', E'Hasta 25 sucursales\nRecordatorios por correo y WhatsApp\nEnlace de pago con Webpay\n1 administrador', FALSE, 0, 1),
			('crecimiento', 'Crecimiento', 'Para quien ya recorre varias sucursales y necesita equipo.', 89000, 'mes', E'Hasta 120 sucursales\nTodo lo de Esencial\nCobradores en el equipo\nCarga de sucursales desde Excel', TRUE, 0, 2),
			('empresa', 'Empresa', 'Para una red grande, con puesta en marcha acompañada.', 169000, 'mes', E'Sucursales sin tope\nTodo lo de Crecimiento\nVarios administradores\nAcompañamiento en la carga inicial', FALSE, 0, 3)
		ON CONFLICT (id) DO NOTHING`,
		`UPDATE companies SET approved_at = NOW() WHERE is_active = TRUE AND approved_at IS NULL`,
		`UPDATE users u SET is_active = FALSE
FROM company_users cu
JOIN companies c ON c.id = cu.company_id
WHERE cu.user_id = u.id
  AND u.is_platform_admin = FALSE
  AND c.is_active = FALSE
  AND NOT EXISTS (
    SELECT 1 FROM company_users cu2
    JOIN companies c2 ON c2.id = cu2.company_id
    WHERE cu2.user_id = u.id AND cu2.company_id <> c.id AND c2.is_active = TRUE
  )`,
	}
	for _, q := range stmts {
		if _, err := db.ex.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}
