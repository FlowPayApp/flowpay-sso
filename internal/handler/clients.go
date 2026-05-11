package handler

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/flowpay/flowpay-sso/internal/clients"
	"github.com/gin-gonic/gin"
)

type ClientsHTTP struct {
	Svc *clients.Service
}

func NewClientsHTTP(svc *clients.Service) *ClientsHTTP {
	return &ClientsHTTP{Svc: svc}
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

func (h *ClientsHTTP) ListClients(c *gin.Context) {
	list, err := h.Svc.ListClients(c.Request.Context(), companyIDFromJWT(c))
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
}

func (b patchClientBody) hasPatchFields() bool {
	return b.IsActive != nil || b.FollowupChannel != nil ||
		b.Name != nil || b.Email != nil || b.Phone != nil || b.Address != nil ||
		b.ClientCode != nil || b.BranchName != nil || b.PaymentTerms != nil
}

func (h *ClientsHTTP) CreateClient(c *gin.Context) {
	var body createClientBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	id, err := h.Svc.CreateClient(c.Request.Context(), companyIDFromJWT(c), clients.CreateClientInput{
		Name:         body.Name,
		Email:        body.Email,
		Phone:        body.Phone,
		Address:      body.Address,
		ClientCode:   body.ClientCode,
		BranchName:   body.BranchName,
		PaymentTerms: body.PaymentTerms,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

func (h *ClientsHTTP) PatchClient(c *gin.Context) {
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
	if err := h.Svc.PatchClient(c.Request.Context(), companyIDFromJWT(c), id, clients.PatchClientInput{
		IsActive:        body.IsActive,
		FollowupChannel: body.FollowupChannel,
		Name:            body.Name,
		Email:           body.Email,
		Phone:           body.Phone,
		Address:         body.Address,
		ClientCode:      body.ClientCode,
		BranchName:      body.BranchName,
		PaymentTerms:    body.PaymentTerms,
	}); err != nil {
		if clients.ErrNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *ClientsHTTP) GetClient(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad id"})
		return
	}
	dto, err := h.Svc.GetClient(c.Request.Context(), companyIDFromJWT(c), id)
	if err != nil {
		if clients.ErrNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, dto)
}

func (h *ClientsHTTP) DeleteClient(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad id"})
		return
	}
	if err := h.Svc.DeleteClient(c.Request.Context(), companyIDFromJWT(c), id); err != nil {
		if clients.ErrNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

type importDistributorRowsBody struct {
	Rows     [][]string `json:"rows"`
	Filename *string    `json:"filename"`
}

func (h *ClientsHTTP) ImportDistributorRows(c *gin.Context) {
	var body importDistributorRowsBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "JSON inválido: se espera { \"rows\": [[...]] }"})
		return
	}
	if len(body.Rows) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "rows vacío"})
		return
	}
	res, err := h.Svc.ImportClientsDistributorRows(c.Request.Context(), companyIDFromJWT(c), body.Rows)
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
	c.JSON(http.StatusOK, res)
}

func (h *ClientsHTTP) ListImportBatches(c *gin.Context) {
	list, err := h.Svc.ListClientImportBatches(c.Request.Context(), companyIDFromJWT(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, list)
}

func (h *ClientsHTTP) GetImportBatch(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id inválido"})
		return
	}
	detail, err := h.Svc.GetClientImportBatch(c.Request.Context(), companyIDFromJWT(c), id)
	if err != nil {
		if errors.Is(err, clients.ErrImportHistoryUnavailable) {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error": "Falta la tabla de historial (client_import_batches). Ejecutá el DDL en PostgreSQL (postgresql_migration/02_schema.sql) y reiniciá el API.",
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
