package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

func assignNullString(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	s := ns.String
	return &s
}

type Client struct {
	ID              int64     `json:"id"`
	CompanyID       int64     `json:"company_id"`
	Name            string    `json:"name"`
	Email           *string   `json:"email,omitempty"`
	Phone           *string   `json:"phone,omitempty"`
	ExternalCode    *string   `json:"external_code,omitempty"`
	Address         *string   `json:"address,omitempty"`
	ClientCode      *string   `json:"client_code,omitempty"`
	BranchName      *string   `json:"branch_name,omitempty"`
	PaymentTerms    *string   `json:"payment_terms,omitempty"`
	IsActive        bool      `json:"is_active"`
	FollowupChannel string    `json:"followup_channel"`
	CreatedAt       time.Time `json:"created_at"`
}

type ClientImportFields struct {
	Name         string
	Email        string
	Phone        string
	Address      string
	IsActive     bool
	ExternalCode string
	ClientCode   string
	BranchName   string
	PaymentTerms string
}

type ClientImportBatchRow struct {
	ID           int64      `json:"id"`
	CompanyID    int64      `json:"company_id"`
	UserID       *int64     `json:"user_id,omitempty"`
	Source       string     `json:"source"`
	Filename     *string    `json:"filename,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	CreatedCount int        `json:"created_count"`
	UpdatedCount int        `json:"updated_count"`
	ErrorCount   int        `json:"error_count"`
	ErrorsJSON   *string    `json:"-"`
}

type ClientRow struct {
	Client
	TotalOwed   float64 `json:"total_owed"`
	OverdueCnt  int     `json:"overdue_count"`
	ChargeCount int     `json:"charge_count"`
}

type ClientPatch struct {
	IsActive        *bool
	FollowupChannel *string
	Name            *string
	Email           *string
	Phone           *string
	Address         *string
	ClientCode      *string
	BranchName      *string
	PaymentTerms    *string
	ExternalCode    *string
}

func (db *DB) ListClients(ctx context.Context, companyID int64) ([]ClientRow, error) {
	q := `
SELECT c.id, c.company_id, c.name, c.email, c.phone, c.external_code, c.address,
       c.client_code, c.branch_name, c.payment_terms,
       c.created_at,
       c.is_active,
       c.followup_channel,
       COALESCE(SUM(CASE WHEN i.paid_at IS NULL THEN i.amount ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN i.paid_at IS NULL AND i.due_date < CURRENT_DATE THEN 1 ELSE 0 END), 0),
       COUNT(i.id)
FROM clients c
LEFT JOIN charges i ON i.client_id = c.id AND i.company_id = c.company_id
WHERE c.company_id = $1
GROUP BY c.id, c.company_id, c.name, c.email, c.phone, c.external_code, c.address,
         c.client_code, c.branch_name, c.payment_terms,
         c.created_at, c.is_active, c.followup_channel
ORDER BY c.created_at DESC, c.id DESC
`
	rows, err := db.ex.QueryContext(ctx, q, companyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ClientRow
	for rows.Next() {
		var cr ClientRow
		var isActive bool
		var email, phone, extCode, addr sql.NullString
		var clientCode, branchName, payTerms sql.NullString
		if err := rows.Scan(
			&cr.ID, &cr.CompanyID, &cr.Name, &email, &phone, &extCode, &addr,
			&clientCode, &branchName, &payTerms,
			&cr.CreatedAt, &isActive, &cr.FollowupChannel, &cr.TotalOwed, &cr.OverdueCnt, &cr.ChargeCount,
		); err != nil {
			return nil, err
		}
		cr.Email = assignNullString(email)
		cr.Phone = assignNullString(phone)
		cr.ExternalCode = assignNullString(extCode)
		cr.Address = assignNullString(addr)
		cr.ClientCode = assignNullString(clientCode)
		cr.BranchName = assignNullString(branchName)
		cr.PaymentTerms = assignNullString(payTerms)
		cr.IsActive = isActive
		if cr.FollowupChannel == "" {
			cr.FollowupChannel = "all"
		}
		out = append(out, cr)
	}
	return out, rows.Err()
}

func (db *DB) GetClient(ctx context.Context, companyID, clientID int64) (*ClientRow, error) {
	q := `
SELECT c.id, c.company_id, c.name, c.email, c.phone, c.external_code, c.address,
       c.client_code, c.branch_name, c.payment_terms,
       c.created_at,
       c.is_active,
       c.followup_channel,
       COALESCE(SUM(CASE WHEN i.paid_at IS NULL THEN i.amount ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN i.paid_at IS NULL AND i.due_date < CURRENT_DATE THEN 1 ELSE 0 END), 0),
       COUNT(i.id)
FROM clients c
LEFT JOIN charges i ON i.client_id = c.id AND i.company_id = c.company_id
WHERE c.company_id = $1 AND c.id = $2
GROUP BY c.id, c.company_id, c.name, c.email, c.phone, c.external_code, c.address,
         c.client_code, c.branch_name, c.payment_terms,
         c.created_at, c.is_active, c.followup_channel
`
	var cr ClientRow
	var isActive bool
	var email, phone, extCode, addr sql.NullString
	var clientCode, branchName, payTerms sql.NullString
	err := db.ex.QueryRowContext(ctx, q, companyID, clientID).Scan(
		&cr.ID, &cr.CompanyID, &cr.Name, &email, &phone, &extCode, &addr,
		&clientCode, &branchName, &payTerms,
		&cr.CreatedAt, &isActive, &cr.FollowupChannel, &cr.TotalOwed, &cr.OverdueCnt, &cr.ChargeCount,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, err
	}
	cr.Email = assignNullString(email)
	cr.Phone = assignNullString(phone)
	cr.ExternalCode = assignNullString(extCode)
	cr.Address = assignNullString(addr)
	cr.ClientCode = assignNullString(clientCode)
	cr.BranchName = assignNullString(branchName)
	cr.PaymentTerms = assignNullString(payTerms)
	cr.IsActive = isActive
	if cr.FollowupChannel == "" {
		cr.FollowupChannel = "all"
	}
	return &cr, nil
}

func (db *DB) DeleteClient(ctx context.Context, companyID, clientID int64) error {
	res, err := db.ex.ExecContext(ctx,
		`DELETE FROM clients WHERE id = $1 AND company_id = $2`,
		clientID, companyID,
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

func trimImport(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max]
	}
	return s
}

func (db *DB) CreateClient(ctx context.Context, companyID int64, name, email, phone, extCode, address, clientCode, branchName, payTerms string) (int64, error) {
	name = trimImport(name, 255)
	if name == "" {
		return 0, errors.New("nombre vacío")
	}
	email = trimImport(email, 255)
	phone = trimImport(phone, 64)
	extCode = trimImport(extCode, 128)
	address = trimImport(address, 512)
	clientCode = trimImport(clientCode, 64)
	branchName = trimImport(branchName, 255)
	payTerms = trimImport(payTerms, 64)

	var id int64
	err := db.ex.QueryRowContext(ctx,
		`INSERT INTO clients (
			company_id, name, email, phone, external_code, address,
			client_code, branch_name, payment_terms,
			is_active, followup_channel
		) VALUES (
			$1, $2, NULLIF($3, ''), NULLIF($4, ''), NULLIF($5, ''),
			NULLIF($6, ''), NULLIF($7, ''), NULLIF($8, ''), NULLIF($9, ''),
			TRUE, 'all'
		) RETURNING id`,
		companyID, name, email, phone, extCode, address, clientCode, branchName, payTerms,
	).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (db *DB) UpsertClientImport(ctx context.Context, companyID int64, in ClientImportFields) (inserted bool, err error) {
	ec := trimImport(in.ExternalCode, 128)
	if ec == "" {
		return false, errors.New("external_code vacío")
	}
	name := trimImport(in.Name, 255)
	if name == "" {
		return false, errors.New("nombre vacío")
	}
	em := trimImport(in.Email, 255)
	phone := trimImport(in.Phone, 64)
	addr := trimImport(in.Address, 512)
	cc := trimImport(in.ClientCode, 64)
	bn := trimImport(in.BranchName, 255)
	pay := trimImport(in.PaymentTerms, 64)
	active := in.IsActive
	res, err := db.ex.ExecContext(ctx, `
UPDATE clients SET
  name = $1, email = NULLIF($2, ''), phone = NULLIF($3, ''), address = NULLIF($4, ''), is_active = $5,
  client_code = NULLIF($6, ''), branch_name = NULLIF($7, ''),
  payment_terms = NULLIF($8, '')
WHERE company_id = $9 AND external_code = $10`,
		name, em, phone, addr, active, cc, bn, pay, companyID, ec,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n > 0 {
		return false, nil
	}
	_, err = db.ex.ExecContext(ctx, `
INSERT INTO clients (
  company_id, name, email, phone, external_code, address,
  client_code, branch_name, payment_terms,
  is_active, followup_channel
) VALUES (
  $1, $2, NULLIF($3, ''), NULLIF($4, ''), $5, NULLIF($6, ''),
  NULLIF($7, ''), NULLIF($8, ''), NULLIF($9, ''),
  $10, 'all'
)`,
		companyID, name, em, phone, ec, addr,
		cc, bn, pay,
		active,
	)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (db *DB) PatchClient(ctx context.Context, companyID, clientID int64, p ClientPatch) error {
	var sets []string
	var args []any
	n := 1
	if p.IsActive != nil {
		sets = append(sets, fmt.Sprintf("is_active = $%d", n))
		args = append(args, *p.IsActive)
		n++
	}
	if p.FollowupChannel != nil {
		sets = append(sets, fmt.Sprintf("followup_channel = $%d", n))
		args = append(args, strings.TrimSpace(strings.ToLower(*p.FollowupChannel)))
		n++
	}
	if p.Name != nil {
		sets = append(sets, fmt.Sprintf("name = $%d", n))
		args = append(args, trimImport(*p.Name, 255))
		n++
	}
	if p.Email != nil {
		sets = append(sets, fmt.Sprintf("email = NULLIF($%d::text, '')", n))
		args = append(args, trimImport(*p.Email, 255))
		n++
	}
	if p.Phone != nil {
		sets = append(sets, fmt.Sprintf("phone = NULLIF($%d::text, '')", n))
		args = append(args, trimImport(*p.Phone, 64))
		n++
	}
	if p.Address != nil {
		sets = append(sets, fmt.Sprintf("address = NULLIF($%d::text, '')", n))
		args = append(args, trimImport(*p.Address, 512))
		n++
	}
	if p.ClientCode != nil {
		sets = append(sets, fmt.Sprintf("client_code = NULLIF($%d::text, '')", n))
		args = append(args, trimImport(*p.ClientCode, 64))
		n++
	}
	if p.BranchName != nil {
		sets = append(sets, fmt.Sprintf("branch_name = NULLIF($%d::text, '')", n))
		args = append(args, trimImport(*p.BranchName, 255))
		n++
	}
	if p.PaymentTerms != nil {
		sets = append(sets, fmt.Sprintf("payment_terms = NULLIF($%d::text, '')", n))
		args = append(args, trimImport(*p.PaymentTerms, 64))
		n++
	}
	if p.ExternalCode != nil {
		sets = append(sets, fmt.Sprintf("external_code = NULLIF($%d::text, '')", n))
		args = append(args, trimImport(*p.ExternalCode, 128))
		n++
	}
	if len(sets) == 0 {
		return nil
	}
	idPH := n
	compPH := n + 1
	args = append(args, clientID, companyID)
	q := fmt.Sprintf("UPDATE clients SET %s WHERE id = $%d AND company_id = $%d", strings.Join(sets, ", "), idPH, compPH)
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

const clientImportBatchListLimit = 100

func (db *DB) InsertClientImportBatch(ctx context.Context, companyID int64, userID *int64, source, filename string, createdCount, updatedCount, errorCount int, errorsJSON []byte) (int64, error) {
	var uid sql.NullInt64
	if userID != nil && *userID != 0 {
		uid = sql.NullInt64{Int64: *userID, Valid: true}
	}
	fn := strings.TrimSpace(filename)
	var fnArg interface{}
	if fn != "" {
		fnArg = fn
	} else {
		fnArg = nil
	}
	var errBlob interface{}
	if len(errorsJSON) > 0 {
		errBlob = errorsJSON
	}
	var id int64
	err := db.ex.QueryRowContext(ctx, `
INSERT INTO client_import_batches (company_id, user_id, source, filename, created_count, updated_count, error_count, errors_json)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
		companyID, uid, source, fnArg, createdCount, updatedCount, errorCount, errBlob,
	).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (db *DB) ListClientImportBatches(ctx context.Context, companyID int64) ([]ClientImportBatchRow, error) {
	q := `
SELECT id, company_id, user_id, source, filename, created_at, created_count, updated_count, error_count
FROM client_import_batches
WHERE company_id = $1
ORDER BY created_at DESC, id DESC
LIMIT $2`
	rows, err := db.ex.QueryContext(ctx, q, companyID, clientImportBatchListLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ClientImportBatchRow
	for rows.Next() {
		var b ClientImportBatchRow
		var uid sql.NullInt64
		var fn sql.NullString
		if err := rows.Scan(&b.ID, &b.CompanyID, &uid, &b.Source, &fn, &b.CreatedAt, &b.CreatedCount, &b.UpdatedCount, &b.ErrorCount); err != nil {
			return nil, err
		}
		if uid.Valid {
			v := uid.Int64
			b.UserID = &v
		}
		b.Filename = assignNullString(fn)
		out = append(out, b)
	}
	return out, rows.Err()
}

func (db *DB) GetClientImportBatch(ctx context.Context, companyID, batchID int64) (*ClientImportBatchRow, error) {
	q := `
SELECT id, company_id, user_id, source, filename, created_at, created_count, updated_count, error_count, errors_json
FROM client_import_batches
WHERE company_id = $1 AND id = $2
LIMIT 1`
	var b ClientImportBatchRow
	var uid sql.NullInt64
	var fn sql.NullString
	var errJSON []byte
	err := db.ex.QueryRowContext(ctx, q, companyID, batchID).Scan(
		&b.ID, &b.CompanyID, &uid, &b.Source, &fn, &b.CreatedAt, &b.CreatedCount, &b.UpdatedCount, &b.ErrorCount, &errJSON,
	)
	if err != nil {
		return nil, err
	}
	if uid.Valid {
		v := uid.Int64
		b.UserID = &v
	}
	b.Filename = assignNullString(fn)
	if len(errJSON) > 0 {
		s := string(errJSON)
		b.ErrorsJSON = &s
	}
	return &b, nil
}
