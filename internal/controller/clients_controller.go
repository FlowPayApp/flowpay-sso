package controller

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/flowpay/flowpay-sso/internal/audit"
	"github.com/flowpay/flowpay-sso/internal/service"
	"github.com/gin-gonic/gin"
)

type ClientsController struct {
	Svc *service.ClientsService
}

func NewClientsController(svc *service.ClientsService) *ClientsController {
	return &ClientsController{Svc: svc}
}

func companyIDFromJWT(c *gin.Context) int64 {
	if v, ok := c.Get("company_id"); ok {
		if id, ok := v.(int64); ok {
			return id
		}
	}
	return 0
}

func jwtUserID(c *gin.Context) *int64 {
	if v, ok := c.Get("user_id"); ok {
		if id, ok := v.(int64); ok && id != 0 {
			return &id
		}
	}
	return nil
}

func jwtUserIDValue(c *gin.Context) int64 {
	if id := jwtUserID(c); id != nil {
		return *id
	}
	return 0
}

func jwtRole(c *gin.Context) string {
	if v, ok := c.Get("role"); ok {
		if s, ok := v.(string); ok {
			return strings.TrimSpace(strings.ToLower(s))
		}
	}
	return ""
}

func memberUIDFromJWT(c *gin.Context) int64 {
	if jwtRole(c) == "member" {
		return jwtUserIDValue(c)
	}
	return 0
}

func requireCompanyAdmin(c *gin.Context) bool {
	if jwtRole(c) == "admin" {
		return true
	}
	c.JSON(http.StatusForbidden, gin.H{"error": "solo el administrador de la empresa puede hacer esta acción"})
	return false
}

func (h *ClientsController) ListClients(c *gin.Context) {
	list, err := h.Svc.ListClients(c.Request.Context(), companyIDFromJWT(c), memberUIDFromJWT(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, list)
}

type createClientBody struct {
	Name         string `json:"name"`
	Email        string `json:"email"`
	Phone        string `json:"phone"`
	Address      string `json:"address"`
	ClientCode   string `json:"client_code"`
	BranchName   string `json:"branch_name"`
	PaymentTerms string `json:"payment_terms"`
	AssignedTo   *int64 `json:"assigned_to"`
}

type patchClientBody struct {
	IsActive        *bool   `json:"is_active"`
	FollowupChannel *string `json:"followup_channel"`
	Name            *string `json:"name"`
	Email           *string `json:"email"`
	Phone           *string `json:"phone"`
	Address         *string `json:"address"`
	ClientCode      *string `json:"client_code"`
	BranchName      *string `json:"branch_name"`
	PaymentTerms    *string `json:"payment_terms"`
	AssignedTo      *int64  `json:"assigned_to"`
}

func clientPatchMeta(body patchClientBody) map[string]any {
	fields := make([]string, 0, 8)
	if body.Name != nil {
		fields = append(fields, "name")
	}
	if body.Email != nil {
		fields = append(fields, "email")
	}
	if body.Phone != nil {
		fields = append(fields, "phone")
	}
	if body.Address != nil {
		fields = append(fields, "address")
	}
	if body.ClientCode != nil {
		fields = append(fields, "client_code")
	}
	if body.BranchName != nil {
		fields = append(fields, "branch_name")
	}
	if body.PaymentTerms != nil {
		fields = append(fields, "payment_terms")
	}
	if body.FollowupChannel != nil {
		fields = append(fields, "followup_channel")
	}
	meta := map[string]any{"fields": fields}
	if body.IsActive != nil {
		meta["is_active"] = *body.IsActive
	}
	if body.AssignedTo != nil {
		meta["assigned_to"] = *body.AssignedTo
	}
	return meta
}

func (b patchClientBody) hasPatchFields() bool {
	return b.IsActive != nil || b.FollowupChannel != nil ||
		b.Name != nil || b.Email != nil || b.Phone != nil || b.Address != nil ||
		b.ClientCode != nil || b.BranchName != nil || b.PaymentTerms != nil ||
		b.AssignedTo != nil
}

func (h *ClientsController) CreateClient(c *gin.Context) {
	var body createClientBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	role := jwtRole(c)
	id, err := h.Svc.CreateClient(c.Request.Context(), companyIDFromJWT(c), service.CreateClientInput{
		Name:         body.Name,
		Email:        body.Email,
		Phone:        body.Phone,
		Address:      body.Address,
		ClientCode:   body.ClientCode,
		BranchName:   body.BranchName,
		PaymentTerms: body.PaymentTerms,
		CreatedBy:    jwtUserIDValue(c),
		AssignedTo:   body.AssignedTo,
		IsMember:     role == "member",
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.audit(c, audit.Event{
		Domain:     audit.DomainClient,
		Action:     audit.ActionClientCreated,
		TargetType: audit.TargetClient,
		TargetID:   audit.ID(id),
		Summary:    "Creó un cliente",
	})
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

func (h *ClientsController) audit(c *gin.Context, e audit.Event) {
	e.ActorID = jwtUserIDValue(c)
	e.ActorRole = jwtRole(c)
	e.CompanyID = companyIDFromJWT(c)
	if err := h.Svc.Repo.RecordAudit(c.Request.Context(), e); err != nil {
		log.Printf("[FlowPay audit] %s.%s: %v", e.Domain, e.Action, err)
	}
}

func (h *ClientsController) PatchClient(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad id"})
		return
	}
	var body patchClientBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	if !body.hasPatchFields() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "indica al menos un campo para actualizar"})
		return
	}
	role := jwtRole(c)
	if err := h.Svc.PatchClient(c.Request.Context(), companyIDFromJWT(c), id, service.PatchClientInput{
		IsActive:        body.IsActive,
		FollowupChannel: body.FollowupChannel,
		Name:            body.Name,
		Email:           body.Email,
		Phone:           body.Phone,
		Address:         body.Address,
		ClientCode:      body.ClientCode,
		BranchName:      body.BranchName,
		PaymentTerms:    body.PaymentTerms,
		AssignedTo:      body.AssignedTo,
		IsMember:        role == "member",
		MemberUID:       memberUIDFromJWT(c),
	}); err != nil {
		if errors.Is(err, service.ErrForbidden) {
			c.JSON(http.StatusForbidden, gin.H{"error": "el vendedor no puede cambiar estados ni la asignación"})
			return
		}
		if service.ErrNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.audit(c, audit.Event{
		Domain:     audit.DomainClient,
		Action:     audit.ActionClientUpdated,
		TargetType: audit.TargetClient,
		TargetID:   audit.ID(id),
		Summary:    "Actualizó un cliente",
		Meta:       clientPatchMeta(body),
	})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *ClientsController) GetClient(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad id"})
		return
	}
	dto, err := h.Svc.GetClient(c.Request.Context(), companyIDFromJWT(c), id, memberUIDFromJWT(c))
	if err != nil {
		if service.ErrNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto)
}

func (h *ClientsController) DeleteClient(c *gin.Context) {
	if !requireCompanyAdmin(c) {
		return
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad id"})
		return
	}
	if err := h.Svc.DeleteClient(c.Request.Context(), companyIDFromJWT(c), id); err != nil {
		if service.ErrNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.audit(c, audit.Event{
		Domain:     audit.DomainClient,
		Action:     audit.ActionClientDeleted,
		TargetType: audit.TargetClient,
		TargetID:   audit.ID(id),
		Summary:    "Eliminó un cliente",
	})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

type importDistributorRowsBody struct {
	Rows     [][]string `json:"rows"`
	Filename *string    `json:"filename"`
}

func (h *ClientsController) ImportDistributorRows(c *gin.Context) {
	if !requireCompanyAdmin(c) {
		return
	}
	var body importDistributorRowsBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "JSON inválido: se espera { \"rows\": [[...]] }"})
		return
	}
	if len(body.Rows) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "rows vacío"})
		return
	}
	res, err := h.Svc.ImportClientsDistributorRows(c.Request.Context(), companyIDFromJWT(c), jwtUserIDValue(c), body.Rows)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	fn := ""
	if body.Filename != nil {
		fn = *body.Filename
	}
	if _, err := h.Svc.RecordClientImportBatch(c.Request.Context(), companyIDFromJWT(c), jwtUserID(c), "excel", fn, res); err != nil {
		log.Printf("client import batch: %v", err)
	}
	h.audit(c, audit.Event{
		Domain:     audit.DomainClient,
		Action:     audit.ActionClientsImported,
		TargetType: audit.TargetCompany,
		TargetID:   audit.ID(companyIDFromJWT(c)),
		Summary:    "Importó clientes",
		Meta:       map[string]any{"created": res.Created, "updated": res.Updated, "errors": len(res.Errors)},
	})
	c.JSON(http.StatusOK, res)
}

func (h *ClientsController) ListImportBatches(c *gin.Context) {
	if !requireCompanyAdmin(c) {
		return
	}
	list, err := h.Svc.ListClientImportBatches(c.Request.Context(), companyIDFromJWT(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, list)
}

func (h *ClientsController) GetImportBatch(c *gin.Context) {
	if !requireCompanyAdmin(c) {
		return
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id inválido"})
		return
	}
	detail, err := h.Svc.GetClientImportBatch(c.Request.Context(), companyIDFromJWT(c), id)
	if err != nil {
		if errors.Is(err, service.ErrImportHistoryUnavailable) {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "Falta la tabla de historial (client_import_batches). Ejecuta el DDL en PostgreSQL (postgresql_migration/02_schema.sql) y reinicia el API.",
			})
			return
		}
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "no encontrado"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, detail)
}
