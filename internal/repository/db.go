package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

type User struct {
	ID                 int64
	Email              string
	PasswordHash       string
	Name               string
	IsPlatformAdmin    bool
	MustChangePassword bool
	IsActive           bool
}

type Company struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	IsActive    bool   `json:"is_active"`
	ClientCount int64  `json:"client_count"`
	AdminCount  int64  `json:"admin_count"`
}

type CompanyAdmin struct {
	UserID      int64  `json:"user_id"`
	CompanyID   int64  `json:"company_id"`
	CompanyName string `json:"company_name"`
	Email       string `json:"email"`
	Name        string `json:"name"`
	Role        string `json:"role"`
	IsActive    bool   `json:"is_active"`
}

type CompanyUser struct {
	UserID   int64  `json:"user_id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Role     string `json:"role"`
	IsActive bool   `json:"is_active"`
}

type DB struct {
	ex  execer
	raw *sql.DB // solo en repo raíz; permite BeginTx
}

func New(db *sql.DB) *DB {
	return &DB{ex: db, raw: db}
}

// BeginTx inicia transacción; el segundo retorno usa la misma API sobre el Tx.
func (db *DB) BeginTx(ctx context.Context) (*sql.Tx, *DB, error) {
	if db.raw == nil {
		return nil, nil, errors.New("no se puede anidar transacción")
	}
	tx, err := db.raw.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	return tx, &DB{ex: tx, raw: nil}, nil
}

func (db *DB) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	var u User
	err := db.ex.QueryRowContext(ctx,
		`SELECT id, email, password_hash, name, is_platform_admin, must_change_password, is_active FROM users WHERE email = $1 LIMIT 1`,
		email,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.IsPlatformAdmin, &u.MustChangePassword, &u.IsActive)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (db *DB) GetUserByID(ctx context.Context, userID int64) (*User, error) {
	var u User
	err := db.ex.QueryRowContext(ctx,
		`SELECT id, email, password_hash, name, is_platform_admin, must_change_password, is_active FROM users WHERE id = $1 LIMIT 1`,
		userID,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.IsPlatformAdmin, &u.MustChangePassword, &u.IsActive)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (db *DB) CreateUser(ctx context.Context, email, passwordHash, name string, isPlatformAdmin, mustChangePassword, isActive bool) (int64, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	var id int64
	err := db.ex.QueryRowContext(ctx,
		`INSERT INTO users (email, password_hash, name, is_platform_admin, must_change_password, is_active) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		email, passwordHash, strings.TrimSpace(name), isPlatformAdmin, mustChangePassword, isActive,
	).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (db *DB) SetUserPasswordAndClearMustChange(ctx context.Context, userID int64, passwordHash string) error {
	res, err := db.ex.ExecContext(ctx, `UPDATE users SET password_hash = $1, must_change_password = FALSE WHERE id = $2`, passwordHash, userID)
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
	return nil
}

// UpdateOwnProfile actualiza nombre/correo y opcionalmente contraseña para un usuario existente.
func (db *DB) UpdateOwnProfile(ctx context.Context, userID int64, email, name string, passwordHash *string) error {
	if userID <= 0 {
		return errors.New("user_id inválido")
	}
	if email == "" || name == "" {
		return errors.New("email y name son obligatorios")
	}
	if passwordHash != nil {
		res, err := db.ex.ExecContext(ctx,
			`UPDATE users SET email = $1, name = $2, password_hash = $3, must_change_password = FALSE WHERE id = $4`,
			strings.TrimSpace(strings.ToLower(email)), strings.TrimSpace(name), *passwordHash, userID,
		)
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
		return nil
	}

	res, err := db.ex.ExecContext(ctx,
		`UPDATE users SET email = $1, name = $2 WHERE id = $3`,
		strings.TrimSpace(strings.ToLower(email)), strings.TrimSpace(name), userID,
	)
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
	return nil
}

func (db *DB) CreateCompany(ctx context.Context, name string) (int64, error) {
	var id int64
	err := db.ex.QueryRowContext(ctx,
		`INSERT INTO companies (name) VALUES ($1) RETURNING id`,
		strings.TrimSpace(name),
	).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (db *DB) AddCompanyUser(ctx context.Context, companyID, userID int64, role string) error {
	if role == "" {
		role = "admin"
	}
	_, err := db.ex.ExecContext(ctx,
		`INSERT INTO company_users (company_id, user_id, role) VALUES ($1, $2, $3)`,
		companyID, userID, role,
	)
	return err
}

// FirstCompanyIDForUser devuelve la primera empresa asociada (MVP: una sola).
func (db *DB) FirstCompanyIDForUser(ctx context.Context, userID int64) (int64, string, error) {
	var cid int64
	var role string
	err := db.ex.QueryRowContext(ctx,
		`SELECT cu.company_id, cu.role
FROM company_users cu
JOIN companies c ON c.id = cu.company_id
WHERE cu.user_id = $1 AND c.is_active = TRUE
ORDER BY cu.company_id ASC LIMIT 1`,
		userID,
	).Scan(&cid, &role)
	if err != nil {
		return 0, "", err
	}
	return cid, role, nil
}

func (db *DB) CountPlatformAdmins(ctx context.Context) (int64, error) {
	var total int64
	err := db.ex.QueryRowContext(ctx, `SELECT COUNT(1) FROM users WHERE is_platform_admin = TRUE`).Scan(&total)
	if err != nil {
		return 0, err
	}
	return total, nil
}

func (db *DB) ListCompanies(ctx context.Context) ([]Company, error) {
	rows, err := db.ex.QueryContext(ctx, `
SELECT c.id, c.name, c.is_active,
       COALESCE(cc.client_count, 0) AS client_count,
       COALESCE(ac.admin_count, 0) AS admin_count
FROM companies c
LEFT JOIN (
	SELECT company_id, COUNT(1) AS client_count
	FROM clients
	GROUP BY company_id
) cc ON cc.company_id = c.id
LEFT JOIN (
	SELECT cu.company_id, COUNT(1) AS admin_count
	FROM company_users cu
	JOIN users u ON u.id = cu.user_id
	WHERE cu.role = 'admin' AND u.is_platform_admin = FALSE
	GROUP BY cu.company_id
) ac ON ac.company_id = c.id
ORDER BY c.id ASC
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Company
	for rows.Next() {
		var c Company
		if err := rows.Scan(&c.ID, &c.Name, &c.IsActive, &c.ClientCount, &c.AdminCount); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// PatchCompany actualiza nombre y/o estado. Al menos uno debe ser no nil.
func (db *DB) PatchCompany(ctx context.Context, companyID int64, name *string, isActive *bool) error {
	if name == nil && isActive == nil {
		return errors.New("nada que actualizar")
	}
	var parts []string
	var args []any
	n := 1
	if name != nil {
		parts = append(parts, fmt.Sprintf("name = $%d", n))
		args = append(args, strings.TrimSpace(*name))
		n++
	}
	if isActive != nil {
		parts = append(parts, fmt.Sprintf("is_active = $%d", n))
		args = append(args, *isActive)
		n++
	}
	idPH := n
	args = append(args, companyID)
	q := fmt.Sprintf("UPDATE companies SET %s WHERE id = $%d", strings.Join(parts, ", "), idPH)
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

func (db *DB) ListCompanyAdmins(ctx context.Context) ([]CompanyAdmin, error) {
	q := `
SELECT u.id, cu.company_id, c.name, u.email, u.name, cu.role, u.is_active
FROM company_users cu
JOIN users u ON u.id = cu.user_id
JOIN companies c ON c.id = cu.company_id
WHERE cu.role = 'admin' AND u.is_platform_admin = FALSE
ORDER BY cu.company_id ASC, u.id ASC
`
	rows, err := db.ex.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CompanyAdmin
	for rows.Next() {
		var a CompanyAdmin
		if err := rows.Scan(&a.UserID, &a.CompanyID, &a.CompanyName, &a.Email, &a.Name, &a.Role, &a.IsActive); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (db *DB) UpdateCompanyAdmin(ctx context.Context, userID int64, email, name string) error {
	res, err := db.ex.ExecContext(ctx, `UPDATE users SET email = $1, name = $2 WHERE id = $3 AND is_platform_admin = FALSE`, strings.TrimSpace(strings.ToLower(email)), strings.TrimSpace(name), userID)
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
	return nil
}

func (db *DB) UpdateCompanyAdminPassword(ctx context.Context, userID int64, passwordHash string) error {
	res, err := db.ex.ExecContext(ctx, `UPDATE users SET password_hash = $1 WHERE id = $2 AND is_platform_admin = FALSE`, passwordHash, userID)
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
	return nil
}

// SetCompanyAdminTemporaryPassword asigna hash y obliga cambio en próximo acceso.
func (db *DB) SetCompanyAdminTemporaryPassword(ctx context.Context, userID int64, passwordHash string) error {
	res, err := db.ex.ExecContext(ctx,
		`UPDATE users SET password_hash = $1, must_change_password = TRUE WHERE id = $2 AND is_platform_admin = FALSE`,
		passwordHash, userID,
	)
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
	return nil
}

// SetCompanyAdminActive activa o desactiva el login del usuario (no aplica a platform_admin).
func (db *DB) SetCompanyAdminActive(ctx context.Context, userID int64, active bool) error {
	res, err := db.ex.ExecContext(ctx, `UPDATE users SET is_active = $1 WHERE id = $2 AND is_platform_admin = FALSE`, active, userID)
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
	return nil
}

func (db *DB) ListCompanyUsers(ctx context.Context, companyID int64) ([]CompanyUser, error) {
	q := `
SELECT u.id, u.email, u.name, cu.role, u.is_active
FROM company_users cu
JOIN users u ON u.id = cu.user_id
WHERE cu.company_id = $1 AND u.is_platform_admin = FALSE
ORDER BY CASE cu.role WHEN 'admin' THEN 0 ELSE 1 END, u.name ASC, u.id ASC
`
	rows, err := db.ex.QueryContext(ctx, q, companyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CompanyUser
	for rows.Next() {
		var u CompanyUser
		if err := rows.Scan(&u.UserID, &u.Email, &u.Name, &u.Role, &u.IsActive); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (db *DB) CompanyHasMember(ctx context.Context, companyID, userID int64) (bool, error) {
	var one int
	err := db.ex.QueryRowContext(ctx, `
SELECT 1 FROM company_users cu
JOIN users u ON u.id = cu.user_id
WHERE cu.company_id = $1 AND cu.user_id = $2 AND cu.role = 'member' AND u.is_platform_admin = FALSE
LIMIT 1`,
		companyID, userID,
	).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

var ErrEmailTaken = errors.New("email ya registrado")
