package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/flowpay/flowpay-sso/internal/dberrors"
	"github.com/flowpay/flowpay-sso/internal/domain"
	"github.com/flowpay/flowpay-sso/internal/repository"
)

type ClientDTO struct {
	repository.ClientRow
	RiskLevel string `json:"risk_level"`
}

type ClientsService struct {
	Repo *repository.DB
}

func NewClientsService(db *repository.DB) *ClientsService {
	return &ClientsService{Repo: db}
}

func ErrNotFound(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}

var ErrForbidden = errors.New("sin permisos")

func (s *ClientsService) ListClients(ctx context.Context, companyID, memberUID int64) ([]ClientDTO, error) {
	rows, err := s.Repo.ListClients(ctx, companyID, memberUID)
	if err != nil {
		return nil, err
	}
	out := make([]ClientDTO, 0, len(rows))
	for _, r := range rows {
		atRisk := 0.0
		if r.OverdueCnt > 0 {
			atRisk = r.TotalOwed
		}
		out = append(out, ClientDTO{
			ClientRow: r,
			RiskLevel: domain.RiskLevel(r.OverdueCnt, atRisk),
		})
	}
	return out, nil
}

func (s *ClientsService) GetClient(ctx context.Context, companyID, clientID, memberUID int64) (*ClientDTO, error) {
	row, err := s.Repo.GetClient(ctx, companyID, clientID, memberUID)
	if err != nil {
		return nil, err
	}
	atRisk := 0.0
	if row.OverdueCnt > 0 {
		atRisk = row.TotalOwed
	}
	return &ClientDTO{
		ClientRow: *row,
		RiskLevel: domain.RiskLevel(row.OverdueCnt, atRisk),
	}, nil
}

func (s *ClientsService) DeleteClient(ctx context.Context, companyID, clientID int64) error {
	return s.Repo.DeleteClient(ctx, companyID, clientID)
}

type CreateClientInput struct {
	Name         string
	Email        string
	Phone        string
	Address      string
	ClientCode   string
	BranchName   string
	PaymentTerms string
	CreatedBy    int64
	AssignedTo   *int64
	IsMember     bool
}

func (s *ClientsService) CreateClient(ctx context.Context, companyID int64, in CreateClientInput) (int64, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return 0, errors.New("el nombre del encargado (NOMBRE) es obligatorio")
	}
	assignedTo := in.AssignedTo
	if in.IsMember {
		uid := in.CreatedBy
		assignedTo = &uid
	} else if assignedTo != nil && *assignedTo > 0 {
		ok, err := s.Repo.CompanyHasMember(ctx, companyID, *assignedTo)
		if err != nil {
			return 0, err
		}
		if !ok {
			return 0, errors.New("el vendedor asignado debe ser un member de la empresa")
		}
	}
	ext := buildExternalCode(in.BranchName, in.ClientCode)
	id, err := s.Repo.CreateClient(ctx, companyID,
		name,
		strings.TrimSpace(in.Email),
		strings.TrimSpace(in.Phone),
		ext,
		strings.TrimSpace(in.Address),
		strings.TrimSpace(in.ClientCode),
		strings.TrimSpace(in.BranchName),
		strings.TrimSpace(in.PaymentTerms),
		in.CreatedBy,
		assignedTo,
	)
	if err != nil {
		if dberrors.IsUniqueViolation(err) {
			return 0, errors.New("ya existe un cliente con la misma clave de código/sucursal en esta empresa")
		}
		return 0, err
	}
	return id, nil
}

func validFollowupChannel(ch string) bool {
	switch ch {
	case "none", "email", "whatsapp", "all":
		return true
	default:
		return false
	}
}

type PatchClientInput struct {
	IsActive        *bool
	FollowupChannel *string
	Name            *string
	Email           *string
	Phone           *string
	Address         *string
	ClientCode      *string
	BranchName      *string
	PaymentTerms    *string
	AssignedTo      *int64
	IsMember        bool
	MemberUID       int64
}

func (s *ClientsService) PatchClient(ctx context.Context, companyID, clientID int64, in PatchClientInput) error {
	if _, err := s.Repo.GetClient(ctx, companyID, clientID, in.MemberUID); err != nil {
		return err
	}
	if in.IsMember && (in.IsActive != nil || in.FollowupChannel != nil || in.AssignedTo != nil) {
		return ErrForbidden
	}
	var follow *string
	if in.FollowupChannel != nil {
		v := strings.TrimSpace(strings.ToLower(*in.FollowupChannel))
		if !validFollowupChannel(v) {
			return errors.New("followup_channel inválido (none|email|whatsapp|all)")
		}
		follow = &v
	}
	if in.AssignedTo != nil && *in.AssignedTo > 0 {
		ok, err := s.Repo.CompanyHasMember(ctx, companyID, *in.AssignedTo)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("el vendedor asignado debe ser un member de la empresa")
		}
	}
	patch := repository.ClientPatch{
		IsActive:        in.IsActive,
		FollowupChannel: follow,
		AssignedTo:      in.AssignedTo,
	}
	profile := in.Name != nil || in.Email != nil || in.Phone != nil || in.Address != nil ||
		in.ClientCode != nil || in.BranchName != nil || in.PaymentTerms != nil
	if profile {
		if in.Name == nil || strings.TrimSpace(*in.Name) == "" {
			return errors.New("el nombre del encargado (NOMBRE) es obligatorio")
		}
		if in.ClientCode == nil || in.BranchName == nil {
			return errors.New("código y sucursal son obligatorios al actualizar los datos del cliente")
		}
		ext := buildExternalCode(*in.BranchName, *in.ClientCode)
		patch.Name = in.Name
		patch.Email = in.Email
		patch.Phone = in.Phone
		patch.Address = in.Address
		patch.ClientCode = in.ClientCode
		patch.BranchName = in.BranchName
		patch.PaymentTerms = in.PaymentTerms
		patch.ExternalCode = &ext
	}
	err := s.Repo.PatchClient(ctx, companyID, clientID, patch)
	if err != nil {
		if dberrors.IsUniqueViolation(err) {
			return errors.New("ya existe un cliente con la misma clave de código/sucursal en esta empresa")
		}
		return err
	}
	return nil
}

// --- import planilla distribuidor ---

var ErrImportHistoryUnavailable = errors.New("import history table missing")

type ImportDistributorResult struct {
	Created int                    `json:"created"`
	Updated int                    `json:"updated"`
	Errors  []ImportDistributorErr `json:"errors"`
}

type ImportDistributorErr struct {
	Line    int    `json:"line"`
	Message string `json:"message"`
}

var fixedDistributorImportHeaders = []string{
	"CODIGO", "SUCURSAL", "NOMBRE", "DIRECCION", "TELEFONO",
}

var distributorHeaderSet = func() map[string]struct{} {
	m := make(map[string]struct{}, 10)
	for _, h := range fixedDistributorImportHeaders {
		m[h] = struct{}{}
	}
	m["EMAIL"] = struct{}{}
	m["MPAGO"] = struct{}{}
	m["CPAGO"] = struct{}{}
	return m
}()

const maxImportDataRows = 10000

func (s *ClientsService) ImportClientsDistributorRows(ctx context.Context, companyID, createdBy int64, rows [][]string) (*ImportDistributorResult, error) {
	if len(rows) == 0 {
		return nil, fmt.Errorf("sin filas")
	}
	header := rows[0]
	idx, err := validateDistributorHeader(header)
	if err != nil {
		return nil, err
	}
	if len(rows) > maxImportDataRows+1 {
		return nil, fmt.Errorf("demasiadas filas (máximo %d datos; tienes %d)", maxImportDataRows, len(rows)-1)
	}

	out := &ImportDistributorResult{Errors: []ImportDistributorErr{}}
	const maxErrors = 80
	lineNum := 1

	for _, rec := range rows[1:] {
		lineNum++
		if rowEmpty(rec) {
			continue
		}
		codigo := getCol(rec, idx, "CODIGO")
		sucursal := getCol(rec, idx, "SUCURSAL")
		nombre := getCol(rec, idx, "NOMBRE")
		dir := getCol(rec, idx, "DIRECCION")
		tel := getCol(rec, idx, "TELEFONO")
		email := getCol(rec, idx, "EMAIL")
		mpago := getPaymentCol(rec, idx)

		ext := buildExternalCode(sucursal, codigo)
		if ext == "" {
			if len(out.Errors) < maxErrors {
				out.Errors = append(out.Errors, ImportDistributorErr{Line: lineNum, Message: "CODIGO/SUCURSAL: se necesita al menos CODIGO para identificar el cliente"})
			}
			continue
		}
		if strings.TrimSpace(nombre) == "" {
			if len(out.Errors) < maxErrors {
				out.Errors = append(out.Errors, ImportDistributorErr{Line: lineNum, Message: "NOMBRE obligatorio"})
			}
			continue
		}

		inserted, err := s.Repo.UpsertClientImport(ctx, companyID, repository.ClientImportFields{
			Name:         nombre,
			Email:        email,
			Phone:        tel,
			Address:      dir,
			IsActive:     true,
			ExternalCode: ext,
			ClientCode:   codigo,
			BranchName:   sucursal,
			PaymentTerms: mpago,
			CreatedBy:    createdBy,
		})
		if err != nil {
			if len(out.Errors) < maxErrors {
				out.Errors = append(out.Errors, ImportDistributorErr{Line: lineNum, Message: err.Error()})
			}
			continue
		}
		if inserted {
			out.Created++
		} else {
			out.Updated++
		}
	}
	return out, nil
}

func normHeader(s string) string {
	return strings.TrimSpace(strings.ToUpper(strings.Trim(s, "\t\r ")))
}

func validateDistributorHeader(header []string) (map[string]int, error) {
	idx := make(map[string]int, 10)
	nonEmpty := 0
	for i, h := range header {
		key := normHeader(h)
		if key == "" {
			continue
		}
		nonEmpty++
		if _, ok := distributorHeaderSet[key]; !ok {
			return nil, fmt.Errorf("columna no permitida %q; solo: CODIGO, SUCURSAL, NOMBRE, DIRECCION, TELEFONO, EMAIL (opcional), MPAGO o CPAGO (antiguo)", strings.TrimSpace(h))
		}
		if _, dup := idx[key]; dup {
			return nil, fmt.Errorf("columna repetida: %q", key)
		}
		idx[key] = i
	}
	const maxCols = 7
	if nonEmpty > maxCols {
		return nil, fmt.Errorf("demasiadas columnas en la cabecera (máximo %d)", maxCols)
	}
	for _, want := range fixedDistributorImportHeaders {
		if _, ok := idx[want]; !ok {
			return nil, fmt.Errorf("falta la columna obligatoria %q en la primera fila", want)
		}
	}
	_, hasMP := idx["MPAGO"]
	_, hasCP := idx["CPAGO"]
	if !hasMP && !hasCP {
		return nil, fmt.Errorf("falta la columna MPAGO (método de pago); en archivos antiguos puede llamarse CPAGO")
	}
	if hasMP && hasCP {
		return nil, fmt.Errorf("no puede haber columnas MPAGO y CPAGO a la vez; dejá solo MPAGO")
	}
	return idx, nil
}

func getPaymentCol(rec []string, idx map[string]int) string {
	if i, ok := idx["MPAGO"]; ok && i < len(rec) {
		return strings.TrimSpace(rec[i])
	}
	if i, ok := idx["CPAGO"]; ok && i < len(rec) {
		return strings.TrimSpace(rec[i])
	}
	return ""
}

func getCol(rec []string, idx map[string]int, col string) string {
	i, ok := idx[col]
	if !ok || i >= len(rec) {
		return ""
	}
	return strings.TrimSpace(rec[i])
}

func rowEmpty(rec []string) bool {
	for _, c := range rec {
		if strings.TrimSpace(c) != "" {
			return false
		}
	}
	return true
}

func buildExternalCode(sucursal, codigo string) string {
	su := strings.TrimSpace(sucursal)
	co := strings.TrimSpace(codigo)
	if co == "" {
		return ""
	}
	if su == "" {
		return co
	}
	return su + "|" + co
}

type ClientImportBatchListItem struct {
	ID           int64     `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	Source       string    `json:"source"`
	Filename     *string   `json:"filename,omitempty"`
	CreatedCount int       `json:"created_count"`
	UpdatedCount int       `json:"updated_count"`
	ErrorCount   int       `json:"error_count"`
}

type ClientImportBatchDetail struct {
	ClientImportBatchListItem
	Errors []ImportDistributorErr `json:"errors"`
}

func (s *ClientsService) RecordClientImportBatch(ctx context.Context, companyID int64, userID *int64, source, filename string, res *ImportDistributorResult) (int64, error) {
	var errJSON []byte
	if len(res.Errors) > 0 {
		var err error
		errJSON, err = json.Marshal(res.Errors)
		if err != nil {
			return 0, err
		}
	}
	return s.Repo.InsertClientImportBatch(ctx, companyID, userID, source, filename, res.Created, res.Updated, len(res.Errors), errJSON)
}

func (s *ClientsService) ListClientImportBatches(ctx context.Context, companyID int64) ([]ClientImportBatchListItem, error) {
	rows, err := s.Repo.ListClientImportBatches(ctx, companyID)
	if err != nil {
		if dberrors.IsUndefinedTable(err) {
			return []ClientImportBatchListItem{}, nil
		}
		return nil, err
	}
	out := make([]ClientImportBatchListItem, 0, len(rows))
	for _, r := range rows {
		out = append(out, ClientImportBatchListItem{
			ID:           r.ID,
			CreatedAt:    r.CreatedAt,
			Source:       r.Source,
			Filename:     r.Filename,
			CreatedCount: r.CreatedCount,
			UpdatedCount: r.UpdatedCount,
			ErrorCount:   r.ErrorCount,
		})
	}
	return out, nil
}

func (s *ClientsService) GetClientImportBatch(ctx context.Context, companyID, batchID int64) (*ClientImportBatchDetail, error) {
	r, err := s.Repo.GetClientImportBatch(ctx, companyID, batchID)
	if err != nil {
		if dberrors.IsUndefinedTable(err) {
			return nil, ErrImportHistoryUnavailable
		}
		return nil, err
	}
	d := &ClientImportBatchDetail{
		ClientImportBatchListItem: ClientImportBatchListItem{
			ID:           r.ID,
			CreatedAt:    r.CreatedAt,
			Source:       r.Source,
			Filename:     r.Filename,
			CreatedCount: r.CreatedCount,
			UpdatedCount: r.UpdatedCount,
			ErrorCount:   r.ErrorCount,
		},
		Errors: []ImportDistributorErr{},
	}
	if r.ErrorsJSON != nil && *r.ErrorsJSON != "" {
		if err := json.Unmarshal([]byte(*r.ErrorsJSON), &d.Errors); err != nil {
			return nil, err
		}
	}
	return d, nil
}
