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
	ID                        int64    `json:"id"`
	Name                      string   `json:"name"`
	IsActive                  bool     `json:"is_active"`
	ClientCount               int64    `json:"client_count"`
	AdminCount                int64    `json:"admin_count"`
	ContactPhone              string   `json:"contact_phone"`
	RequestedPlan             string   `json:"requested_plan"`
	ContactName               string   `json:"contact_name"`
	ContactEmail              string   `json:"contact_email"`
	Approved                  bool     `json:"approved"`
	PriceCLPOverride          *int     `json:"price_clp_override"`
	CommissionPercentOverride *float64 `json:"commission_percent_override"`
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
	return db.insertCompany(ctx, name, true, "", "")
}

// CreatePendingCompany deja la empresa inactiva hasta que un platform_admin la active.
func (db *DB) CreatePendingCompany(ctx context.Context, name, phone, plan string) (int64, error) {
	return db.insertCompany(ctx, name, false, phone, plan)
}

func (db *DB) insertCompany(ctx context.Context, name string, active bool, phone, plan string) (int64, error) {
	var id int64
	err := db.ex.QueryRowContext(ctx,
		`INSERT INTO companies (name, is_active, contact_phone, requested_plan) VALUES ($1, $2, $3, $4) RETURNING id`,
		strings.TrimSpace(name), active, strings.TrimSpace(phone), strings.TrimSpace(plan),
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

// CompanyLoginForUser distingue empresa activa, solicitud pendiente y empresa ya aprobada pero apagada.
// status: "active", "pending" o "inactive".
func (db *DB) CompanyLoginForUser(ctx context.Context, userID int64) (companyID int64, role string, status string, err error) {
	companyID, role, err = db.FirstCompanyIDForUser(ctx, userID)
	if err == nil {
		return companyID, role, "active", nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, "", "", err
	}
	var inactiveID int64
	var approved bool
	var plan string
	err = db.ex.QueryRowContext(ctx, `
SELECT c.id, (c.approved_at IS NOT NULL), COALESCE(c.requested_plan, '')
FROM company_users cu
JOIN companies c ON c.id = cu.company_id
WHERE cu.user_id = $1 AND c.is_active = FALSE
ORDER BY c.id ASC
LIMIT 1
`, userID).Scan(&inactiveID, &approved, &plan)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", "", sql.ErrNoRows
	}
	if err != nil {
		return 0, "", "", err
	}
	if !approved && plan != "" {
		return 0, "", "pending", nil
	}
	return 0, "", "inactive", nil
}

// ListPlatformAdminEmails correos de los super admin activos.
func (db *DB) ListPlatformAdminEmails(ctx context.Context) ([]string, error) {
	rows, err := db.ex.QueryContext(ctx, `
SELECT email FROM users
WHERE is_platform_admin = TRUE AND is_active = TRUE AND email <> ''
ORDER BY id ASC
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			return nil, err
		}
		out = append(out, email)
	}
	return out, rows.Err()
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
       COALESCE(ac.admin_count, 0) AS admin_count,
       COALESCE(c.contact_phone, '') AS contact_phone,
       COALESCE(c.requested_plan, '') AS requested_plan,
       COALESCE(adm.name, '') AS contact_name,
       COALESCE(adm.email, '') AS contact_email,
       (c.approved_at IS NOT NULL) AS approved,
       c.price_clp_override,
       c.commission_percent_override
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
LEFT JOIN LATERAL (
	SELECT u.name, u.email
	FROM company_users cu
	JOIN users u ON u.id = cu.user_id
	WHERE cu.company_id = c.id AND cu.role = 'admin' AND u.is_platform_admin = FALSE
	ORDER BY u.id ASC
	LIMIT 1
) adm ON TRUE
ORDER BY c.id ASC
`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Company
	for rows.Next() {
		var c Company
		var price sql.NullInt64
		var commission sql.NullFloat64
		if err := rows.Scan(&c.ID, &c.Name, &c.IsActive, &c.ClientCount, &c.AdminCount, &c.ContactPhone, &c.RequestedPlan, &c.ContactName, &c.ContactEmail, &c.Approved, &price, &commission); err != nil {
			return nil, err
		}
		if price.Valid {
			v := int(price.Int64)
			c.PriceCLPOverride = &v
		}
		if commission.Valid {
			v := commission.Float64
			c.CommissionPercentOverride = &v
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SignupAdmin es el primer administrador de una solicitud pública.
type SignupAdmin struct {
	UserID     int64
	Email      string
	MustChange bool
	Plan       string
	Active     bool
	Approved   bool
}

func (db *DB) SignupAdminForCompany(ctx context.Context, companyID int64) (SignupAdmin, error) {
	var admin SignupAdmin
	err := db.ex.QueryRowContext(ctx, `
SELECT c.is_active, COALESCE(c.requested_plan, ''),
       COALESCE(u.id, 0), COALESCE(u.email, ''), COALESCE(u.must_change_password, FALSE),
       (c.approved_at IS NOT NULL)
FROM companies c
LEFT JOIN LATERAL (
	SELECT u.id, u.email, u.must_change_password
	FROM company_users cu
	JOIN users u ON u.id = cu.user_id
	WHERE cu.company_id = c.id AND cu.role = 'admin' AND u.is_platform_admin = FALSE
	ORDER BY u.id ASC
	LIMIT 1
) u ON TRUE
WHERE c.id = $1
`, companyID).Scan(&admin.Active, &admin.Plan, &admin.UserID, &admin.Email, &admin.MustChange, &admin.Approved)
	return admin, err
}

func (db *DB) MarkCompanyApproved(ctx context.Context, companyID int64) error {
	_, err := db.ex.ExecContext(ctx, `UPDATE companies SET approved_at = NOW() WHERE id = $1 AND approved_at IS NULL`, companyID)
	return err
}

// SetCompanyUsersActive prende o apaga a las personas de la empresa. No toca super admins
// ni a quien siga en otra empresa activa.
func (db *DB) SetCompanyUsersActive(ctx context.Context, companyID int64, active bool) error {
	_, err := db.ex.ExecContext(ctx, `
UPDATE users u
SET is_active = $2
FROM company_users cu
WHERE cu.user_id = u.id
  AND cu.company_id = $1
  AND u.is_platform_admin = FALSE
  AND (
    $2 = TRUE
    OR NOT EXISTS (
      SELECT 1
      FROM company_users cu2
      JOIN companies c2 ON c2.id = cu2.company_id
      WHERE cu2.user_id = u.id
        AND cu2.company_id <> $1
        AND c2.is_active = TRUE
    )
  )
`, companyID, active)
	return err
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
var ErrCompanyUserNotFound = errors.New("usuario no encontrado en el equipo")
var ErrLastCompanyAdmin = errors.New("la empresa debe conservar al menos un administrador activo")

func (db *DB) countOtherActiveAdmins(ctx context.Context, companyID, exceptUserID int64) (int, error) {
	var n int
	err := db.ex.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM company_users cu
JOIN users u ON u.id = cu.user_id
WHERE cu.company_id = $1 AND cu.user_id <> $2 AND cu.role = 'admin'
  AND u.is_active = TRUE AND u.is_platform_admin = FALSE`,
		companyID, exceptUserID,
	).Scan(&n)
	return n, err
}

func (db *DB) companyMemberRole(ctx context.Context, companyID, userID int64) (string, error) {
	var role string
	err := db.ex.QueryRowContext(ctx, `
SELECT cu.role
FROM company_users cu
JOIN users u ON u.id = cu.user_id
WHERE cu.company_id = $1 AND cu.user_id = $2 AND u.is_platform_admin = FALSE
LIMIT 1`,
		companyID, userID,
	).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrCompanyUserNotFound
	}
	if err != nil {
		return "", err
	}
	return role, nil
}

func (db *DB) UpdateCompanyMember(ctx context.Context, companyID, userID int64, email, name, role string, active bool) error {
	currentRole, err := db.companyMemberRole(ctx, companyID, userID)
	if err != nil {
		return err
	}
	if currentRole == "admin" && (role != "admin" || !active) {
		others, err := db.countOtherActiveAdmins(ctx, companyID, userID)
		if err != nil {
			return err
		}
		if others == 0 {
			return ErrLastCompanyAdmin
		}
	}

	tx, rw, err := db.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := rw.ex.ExecContext(ctx,
		`UPDATE users SET email = $1, name = $2, is_active = $3 WHERE id = $4 AND is_platform_admin = FALSE`,
		strings.TrimSpace(strings.ToLower(email)), strings.TrimSpace(name), active, userID,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrCompanyUserNotFound
	}
	res, err = rw.ex.ExecContext(ctx,
		`UPDATE company_users SET role = $1 WHERE company_id = $2 AND user_id = $3`,
		role, companyID, userID,
	)
	if err != nil {
		return err
	}
	n, err = res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrCompanyUserNotFound
	}
	return tx.Commit()
}

func missingRelation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "42p01") || strings.Contains(msg, "does not exist")
}

// DeleteCompany borra la empresa, sus datos y las cuentas que solo pertenecían a ella.
func (db *DB) DeleteCompany(ctx context.Context, companyID int64) error {
	tx, rw, err := db.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	rows, err := rw.ex.QueryContext(ctx, `
SELECT cu.user_id
FROM company_users cu
JOIN users u ON u.id = cu.user_id
WHERE cu.company_id = $1 AND u.is_platform_admin = FALSE
`, companyID)
	if err != nil {
		return err
	}
	var userIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		userIDs = append(userIDs, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	for _, q := range []string{
		`DELETE FROM reminder_messages WHERE company_id = $1`,
		`DELETE FROM messages WHERE company_id = $1`,
		`DELETE FROM company_mailboxes WHERE company_id = $1`,
	} {
		if _, err := rw.ex.ExecContext(ctx, q, companyID); err != nil && !missingRelation(err) {
			return err
		}
	}
	res, err := rw.ex.ExecContext(ctx, `DELETE FROM companies WHERE id = $1`, companyID)
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
	for _, id := range userIDs {
		var left int
		if err := rw.ex.QueryRowContext(ctx, `SELECT COUNT(*) FROM company_users WHERE user_id = $1`, id).Scan(&left); err != nil {
			return err
		}
		if left > 0 {
			continue
		}
		if _, err := rw.ex.ExecContext(ctx, `DELETE FROM client_import_batches WHERE user_id = $1`, id); err != nil {
			return err
		}
		if _, err := rw.ex.ExecContext(ctx, `
DELETE FROM users WHERE id = $1 AND is_platform_admin = FALSE
`, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteCompanyAdmin borra la cuenta de un administrador de empresa. No toca super admins.
func (db *DB) DeleteCompanyAdmin(ctx context.Context, userID int64) error {
	tx, rw, err := db.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var platform bool
	err = rw.ex.QueryRowContext(ctx, `SELECT is_platform_admin FROM users WHERE id = $1`, userID).Scan(&platform)
	if err != nil {
		return err
	}
	if platform {
		return errors.New("no se puede borrar un super admin desde aquí")
	}
	if _, err := rw.ex.ExecContext(ctx, `DELETE FROM client_import_batches WHERE user_id = $1`, userID); err != nil {
		return err
	}
	res, err := rw.ex.ExecContext(ctx, `DELETE FROM users WHERE id = $1 AND is_platform_admin = FALSE`, userID)
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

// RemoveCompanyMember saca al usuario del equipo. Los clientes que tenía pasan al admin que lo elimina.
func (db *DB) RemoveCompanyMember(ctx context.Context, companyID, userID, reassignTo int64) error {
	currentRole, err := db.companyMemberRole(ctx, companyID, userID)
	if err != nil {
		return err
	}
	if currentRole == "admin" {
		others, err := db.countOtherActiveAdmins(ctx, companyID, userID)
		if err != nil {
			return err
		}
		if others == 0 {
			return ErrLastCompanyAdmin
		}
	}

	tx, rw, err := db.BeginTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := rw.ex.ExecContext(ctx,
		`UPDATE clients SET assigned_to = NULL WHERE company_id = $1 AND assigned_to = $2`,
		companyID, userID,
	); err != nil {
		return err
	}
	if reassignTo > 0 && reassignTo != userID {
		if _, err := rw.ex.ExecContext(ctx,
			`UPDATE clients SET created_by = $3 WHERE company_id = $1 AND created_by = $2`,
			companyID, userID, reassignTo,
		); err != nil {
			return err
		}
	}
	res, err := rw.ex.ExecContext(ctx,
		`DELETE FROM company_users WHERE company_id = $1 AND user_id = $2`,
		companyID, userID,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrCompanyUserNotFound
	}
	if _, err := rw.ex.ExecContext(ctx,
		`UPDATE users SET is_active = FALSE WHERE id = $1 AND NOT EXISTS (SELECT 1 FROM company_users WHERE user_id = $1)`,
		userID,
	); err != nil {
		return err
	}
	return tx.Commit()
}
