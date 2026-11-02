package controller

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/flowpay/flowpay-sso/internal/audit"
	"github.com/flowpay/flowpay-sso/internal/repository"
	"github.com/gin-gonic/gin"
)

type auditEventJSON struct {
	ID          int64   `json:"id"`
	OccurredAt  string  `json:"occurred_at"`
	Service     string  `json:"service"`
	Domain      string  `json:"domain"`
	DomainLabel string  `json:"domain_label"`
	Action      string  `json:"action"`
	Outcome     string  `json:"outcome"`
	ActorUserID *int64  `json:"actor_user_id,omitempty"`
	ActorRole   string  `json:"actor_role,omitempty"`
	CompanyID   *int64  `json:"company_id,omitempty"`
	TargetType  string  `json:"target_type,omitempty"`
	TargetID    string  `json:"target_id,omitempty"`
	IP          string  `json:"ip,omitempty"`
	Summary     string  `json:"summary"`
	Metadata    jsonRaw `json:"metadata"`
}

type jsonRaw []byte

func (r jsonRaw) MarshalJSON() ([]byte, error) {
	if len(r) == 0 {
		return []byte("{}"), nil
	}
	return r, nil
}

func (h *AuthController) ListAudit(c *gin.Context) {
	if _, ok := h.authorize(c, "platform_admin"); !ok {
		return
	}
	companyID, _ := strconv.ParseInt(strings.TrimSpace(c.Query("company_id")), 10, 64)
	beforeID, _ := strconv.ParseInt(strings.TrimSpace(c.Query("before_id")), 10, 64)
	limit, _ := strconv.Atoi(strings.TrimSpace(c.Query("limit")))
	rows, err := h.Repo.ListAuditEvents(c.Request.Context(), repository.AuditFilter{
		Domain:    strings.TrimSpace(c.Query("domain")),
		Outcome:   strings.TrimSpace(c.Query("outcome")),
		CompanyID: companyID,
		BeforeID:  beforeID,
		Limit:     limit,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo leer la auditoría"})
		return
	}
	events := make([]auditEventJSON, 0, len(rows))
	for _, row := range rows {
		item := auditEventJSON{
			ID:          row.ID,
			OccurredAt:  row.OccurredAt.UTC().Format("2006-01-02T15:04:05Z"),
			Service:     row.Service,
			Domain:      row.Domain,
			DomainLabel: audit.DomainLabel(row.Domain),
			Action:      row.Action,
			Outcome:     row.Outcome,
			ActorRole:   row.ActorRole,
			TargetType:  row.TargetType,
			TargetID:    row.TargetID,
			IP:          row.IP,
			Summary:     row.Summary,
			Metadata:    jsonRaw(row.Metadata),
		}
		if row.ActorUserID.Valid {
			id := row.ActorUserID.Int64
			item.ActorUserID = &id
		}
		if row.CompanyID.Valid {
			id := row.CompanyID.Int64
			item.CompanyID = &id
		}
		events = append(events, item)
	}
	c.JSON(http.StatusOK, gin.H{
		"domains": audit.Domains(),
		"events":  events,
	})
}
