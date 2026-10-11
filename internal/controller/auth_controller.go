package controller

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/flowpay/flowpay-sso/internal/authjwt"
	"github.com/flowpay/flowpay-sso/internal/notify"
	"github.com/flowpay/flowpay-sso/internal/repository"
	"github.com/flowpay/flowpay-sso/internal/signup"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type AuthController struct {
	Repo              *repository.DB
	JWTSecret         []byte
	JWTTTL            time.Duration
	SignupSMTP        notify.SMTP
	SignupNotifyEmail string
}

func NewAuthController(db *repository.DB, secret []byte, ttl time.Duration) *AuthController {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &AuthController{Repo: db, JWTSecret: secret, JWTTTL: ttl}
}

type registerBody struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	Name        string `json:"name"`
	CompanyName string `json:"company_name"`
	Phone       string `json:"phone"`
	Plan        string `json:"plan"`
}

type loginBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type createCompanyWithAdminBody struct {
	CompanyName string `json:"company_name"`
	AdminEmail  string `json:"admin_email"`
	AdminPass   string `json:"admin_password"`
	AdminName   string `json:"admin_name"`
}

type createCompanyBody struct {
	Name string `json:"name"`
}

type createCompanyUserBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
	Role     string `json:"role"`
}

type updateCompanyUserBody struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Role     string `json:"role"`
	IsActive *bool  `json:"is_active"`
}

type createCompanyAdminBody struct {
	CompanyID int64  `json:"company_id"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	Name      string `json:"name"`
}

type bootstrapPlatformAdminBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type updateCompanyBody struct {
	Name                      *string  `json:"name"`
	IsActive                  *bool    `json:"is_active"`
	RequestedPlan             *string  `json:"requested_plan"`
	PriceCLPOverride          *int     `json:"price_clp_override"`
	CommissionPercentOverride *float64 `json:"commission_percent_override"`
	ClearPriceOverride        *bool    `json:"clear_price_override"`
	ClearCommissionOverride   *bool    `json:"clear_commission_override"`
}

type updatePlanBody struct {
	Label             string   `json:"label"`
	Detail            string   `json:"detail"`
	PriceCLP          int      `json:"price_clp"`
	Features          []string `json:"features"`
	Highlight         bool     `json:"highlight"`
	CommissionPercent float64  `json:"commission_percent"`
}

type updateCompanyAdminBody struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	IsActive *bool  `json:"is_active"`
}

type firstPasswordChangeBody struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	NewPassword string `json:"new_password"`
}

type updateOwnProfileBody struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

func tokenResponse(token string, ttl time.Duration) gin.H {
	sec := int(ttl.Seconds())
	if sec < 0 {
		sec = 86400
	}
	return gin.H{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   sec,
	}
}

func generateTemporaryPassword() (string, error) {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	// Base64 URL-safe: temporal robusta y fácil de copiar.
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (h *AuthController) Register(c *gin.Context) {
	var body registerBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "json inválido"})
		return
	}
	body.Email = strings.TrimSpace(strings.ToLower(body.Email))
	body.Name = strings.TrimSpace(body.Name)
	body.CompanyName = strings.TrimSpace(body.CompanyName)
	body.Phone = strings.TrimSpace(body.Phone)
	body.Plan = strings.TrimSpace(strings.ToLower(body.Plan))
	if body.Email == "" || body.Name == "" || body.CompanyName == "" || body.Phone == "" || body.Plan == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "completa empresa, nombre, correo, teléfono y plan"})
		return
	}
	if digits := onlyDigits(body.Phone); len(digits) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "el teléfono no es válido"})
		return
	}
	plan, err := h.planByID(c, body.Plan)
	if err != nil {
		return
	}
	placeholder, err := generateTemporaryPassword()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo registrar la solicitud"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(placeholder), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash"})
		return
	}

	tx, rw, err := h.Repo.BeginTx(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	companyID, err := rw.CreatePendingCompany(c.Request.Context(), body.CompanyName, body.Phone, plan.ID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	userID, err := rw.CreateUser(c.Request.Context(), body.Email, string(hash), body.Name, false, true, false)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(err.Error(), "23505") || strings.Contains(strings.ToLower(err.Error()), "unique constraint") {
			c.JSON(http.StatusConflict, gin.H{"error": "email ya registrado"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := rw.AddCompanyUser(c.Request.Context(), companyID, userID, "admin"); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	admins, err := h.Repo.ListPlatformAdminEmails(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	recipients := append([]string{}, admins...)
	if extra := strings.TrimSpace(h.SignupNotifyEmail); extra != "" {
		recipients = append(recipients, strings.Split(extra, ",")...)
	}
	_ = h.SignupSMTP.SendSignup(recipients, notify.SignupNotice{
		CompanyName: body.CompanyName,
		PersonName:  body.Name,
		Email:       body.Email,
		Phone:       body.Phone,
		PlanLabel:   plan.Label + " · " + plan.Price + " / " + plan.Period,
	})
	c.JSON(http.StatusCreated, gin.H{
		"pending": true,
		"message": "Recibimos tu solicitud. La revisamos y, cuando la empresa quede lista, te escribimos con la contraseña para entrar.",
	})
}

func (h *AuthController) ListSignupPlans(c *gin.Context) {
	c.JSON(http.StatusOK, h.publishedPlans(c.Request.Context()))
}

func (h *AuthController) publishedPlans(ctx context.Context) []signup.Plan {
	list, err := h.Repo.ListSignupPlans(ctx)
	if err != nil || len(list) == 0 {
		return signup.Plans
	}
	return list
}

func (h *AuthController) planByID(c *gin.Context, id string) (signup.Plan, error) {
	plan, err := h.Repo.GetSignupPlan(c.Request.Context(), id)
	if err == nil {
		return plan, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudieron leer los planes"})
		return signup.Plan{}, err
	}
	if fallback, ok := signup.Find(id); ok {
		return fallback, nil
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": "elige un plan"})
	return signup.Plan{}, sql.ErrNoRows
}

func (h *AuthController) UpdateSignupPlan(c *gin.Context) {
	if _, ok := h.authorize(c, "platform_admin"); !ok {
		return
	}
	id := strings.TrimSpace(strings.ToLower(c.Param("id")))
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "plan inválido"})
		return
	}
	var body updatePlanBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "json inválido"})
		return
	}
	label := strings.TrimSpace(body.Label)
	if label == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "el plan necesita un nombre"})
		return
	}
	if body.PriceCLP < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "el precio no puede ser negativo"})
		return
	}
	if body.CommissionPercent < 0 || body.CommissionPercent > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "la comisión va de 0 a 100"})
		return
	}
	var features []string
	for _, line := range body.Features {
		line = strings.TrimSpace(line)
		if line != "" {
			features = append(features, line)
		}
	}
	plan := signup.Plan{
		ID:                id,
		Label:             label,
		Detail:            strings.TrimSpace(body.Detail),
		PriceCLP:          body.PriceCLP,
		Features:          features,
		Highlight:         body.Highlight,
		CommissionPercent: body.CommissionPercent,
	}
	if err := h.Repo.UpdateSignupPlan(c.Request.Context(), plan); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "plan no encontrado"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "no se pudo guardar el plan"})
		return
	}
	saved, err := h.Repo.GetSignupPlan(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"ok": true})
		return
	}
	c.JSON(http.StatusOK, saved)
}

func onlyDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (h *AuthController) Login(c *gin.Context) {
	var body loginBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "json inválido"})
		return
	}
	body.Email = strings.TrimSpace(strings.ToLower(body.Email))
	if body.Email == "" || body.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email y password obligatorios"})
		return
	}

	u, err := h.Repo.GetUserByEmail(c.Request.Context(), body.Email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "credenciales inválidas"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(body.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "credenciales inválidas"})
		return
	}
	cid := int64(0)
	role := "platform_admin"
	if !u.IsPlatformAdmin {
		var status string
		cid, role, status, err = h.Repo.CompanyLoginForUser(c.Request.Context(), u.ID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(http.StatusForbidden, gin.H{"error": "usuario sin empresa asignada"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if status == "pending" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Tu empresa aún no está activa. Te escribimos cuando quede lista."})
			return
		}
		if status == "inactive" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Tu empresa está desactivada. Cuando vuelva a estar activa podrás entrar con la misma contraseña."})
			return
		}
	}
	if !u.IsActive {
		c.JSON(http.StatusForbidden, gin.H{"error": "cuenta desactivada"})
		return
	}
	if u.MustChangePassword {
		c.JSON(http.StatusForbidden, gin.H{
			"error":                    "debes actualizar tu contraseña temporal",
			"requires_password_change": true,
		})
		return
	}

	token, err := authjwt.SignAccessToken(h.JWTSecret, u.ID, cid, u.Email, role, h.JWTTTL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, tokenResponse(token, h.JWTTTL))
}

func (h *AuthController) authorize(c *gin.Context, allowedRoles ...string) (*authjwt.AccessClaims, bool) {
	hdr := strings.TrimSpace(c.GetHeader("Authorization"))
	if hdr == "" || !strings.HasPrefix(hdr, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "se requiere Bearer token"})
		return nil, false
	}
	raw := strings.TrimSpace(strings.TrimPrefix(hdr, "Bearer "))
	claims, err := authjwt.ParseAccessToken(h.JWTSecret, raw)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "token inválido o expirado"})
		return nil, false
	}
	for _, role := range allowedRoles {
		if claims.Role == role {
			return claims, true
		}
	}
	c.JSON(http.StatusForbidden, gin.H{"error": "sin permisos"})
	return nil, false
}

func (h *AuthController) GetProfile(c *gin.Context) {
	claims, ok := h.authorize(c, "platform_admin", "admin", "member")
	if !ok {
		return
	}
	u, err := h.Repo.GetUserByID(c.Request.Context(), claims.UserID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "usuario no encontrado"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"user_id":    u.ID,
		"email":      u.Email,
		"name":       u.Name,
		"role":       claims.Role,
		"company_id": claims.CompanyID,
		"is_active":  u.IsActive,
	})
}

func (h *AuthController) UpdateProfile(c *gin.Context) {
	claims, ok := h.authorize(c, "platform_admin", "admin", "member")
	if !ok {
		return
	}
	var body updateOwnProfileBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "json inválido"})
		return
	}
	email := strings.TrimSpace(strings.ToLower(body.Email))
	name := strings.TrimSpace(body.Name)
	if email == "" || name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email y name son obligatorios"})
		return
	}
	var hashPtr *string
	if strings.TrimSpace(body.Password) != "" {
		if err := validatePasswordPolicy(body.Password); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "hash"})
			return
		}
		s := string(hash)
		hashPtr = &s
	}
	if err := h.Repo.UpdateOwnProfile(c.Request.Context(), claims.UserID, email, name, hashPtr); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "usuario no encontrado"})
			return
		}
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(err.Error(), "23505") || strings.Contains(strings.ToLower(err.Error()), "unique constraint") {
			c.JSON(http.StatusConflict, gin.H{"error": "email ya registrado"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *AuthController) CreateCompanyWithAdmin(c *gin.Context) {
	if _, ok := h.authorize(c, "platform_admin"); !ok {
		return
	}
	var body createCompanyWithAdminBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "json inválido"})
		return
	}
	body.CompanyName = strings.TrimSpace(body.CompanyName)
	body.AdminEmail = strings.TrimSpace(strings.ToLower(body.AdminEmail))
	body.AdminName = strings.TrimSpace(body.AdminName)

	// Compatibilidad: si viene solo nombre de empresa, crear empresa sin admin.
	if body.CompanyName != "" && body.AdminEmail == "" && strings.TrimSpace(body.AdminPass) == "" && body.AdminName == "" {
		companyID, err := h.Repo.CreateCompany(c.Request.Context(), body.CompanyName)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusCreated, gin.H{"company_id": companyID})
		return
	}

	if body.CompanyName == "" || body.AdminEmail == "" || body.AdminName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "company_name, admin_email, admin_password y admin_name son obligatorios"})
		return
	}
	if err := validatePasswordPolicy(body.AdminPass); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(body.AdminPass), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash"})
		return
	}
	tx, rw, err := h.Repo.BeginTx(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	companyID, err := rw.CreateCompany(c.Request.Context(), body.CompanyName)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	userID, err := rw.CreateUser(c.Request.Context(), body.AdminEmail, string(hash), body.AdminName, false, false, true)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(err.Error(), "23505") || strings.Contains(strings.ToLower(err.Error()), "unique constraint") {
			c.JSON(http.StatusConflict, gin.H{"error": "email ya registrado"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := rw.AddCompanyUser(c.Request.Context(), companyID, userID, "admin"); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"company_id": companyID, "admin_user_id": userID})
}

func (h *AuthController) CreateCompany(c *gin.Context) {
	if _, ok := h.authorize(c, "platform_admin"); !ok {
		return
	}
	var body createCompanyBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "json inválido"})
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name es obligatorio"})
		return
	}
	companyID, err := h.Repo.CreateCompany(c.Request.Context(), name)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"company_id": companyID})
}

func (h *AuthController) CreateCompanyUser(c *gin.Context) {
	claims, ok := h.authorize(c, "admin")
	if !ok {
		return
	}
	if claims.CompanyID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token sin company_id válido"})
		return
	}
	var body createCompanyUserBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "json inválido"})
		return
	}
	body.Email = strings.TrimSpace(strings.ToLower(body.Email))
	body.Name = strings.TrimSpace(body.Name)
	body.Role = strings.TrimSpace(strings.ToLower(body.Role))
	if body.Role == "" {
		body.Role = "member"
	}
	if body.Email == "" || body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email, password y name son obligatorios"})
		return
	}
	if err := validatePasswordPolicy(body.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Role != "admin" && body.Role != "member" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role debe ser admin o member"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash"})
		return
	}
	tx, rw, err := h.Repo.BeginTx(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer tx.Rollback()
	userID, err := rw.CreateUser(c.Request.Context(), body.Email, string(hash), body.Name, false, false, true)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(err.Error(), "23505") || strings.Contains(strings.ToLower(err.Error()), "unique constraint") {
			c.JSON(http.StatusConflict, gin.H{"error": "email ya registrado"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := rw.AddCompanyUser(c.Request.Context(), claims.CompanyID, userID, body.Role); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"user_id": userID, "company_id": claims.CompanyID, "role": body.Role})
}

func (h *AuthController) ListCompanyUsers(c *gin.Context) {
	claims, ok := h.authorize(c, "admin")
	if !ok {
		return
	}
	if claims.CompanyID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token sin company_id válido"})
		return
	}
	list, err := h.Repo.ListCompanyUsers(c.Request.Context(), claims.CompanyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if list == nil {
		list = []repository.CompanyUser{}
	}
	c.JSON(http.StatusOK, list)
}

func (h *AuthController) UpdateCompanyUser(c *gin.Context) {
	claims, ok := h.authorize(c, "admin")
	if !ok {
		return
	}
	if claims.CompanyID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token sin company_id válido"})
		return
	}
	userID, err := strconv.ParseInt(c.Param("user_id"), 10, 64)
	if err != nil || userID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id inválido"})
		return
	}
	var body updateCompanyUserBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "json inválido"})
		return
	}
	body.Email = strings.TrimSpace(strings.ToLower(body.Email))
	body.Name = strings.TrimSpace(body.Name)
	body.Role = strings.TrimSpace(strings.ToLower(body.Role))
	if body.Email == "" || body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email y name son obligatorios"})
		return
	}
	if body.Role != "admin" && body.Role != "member" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role debe ser admin o member"})
		return
	}
	active := true
	if body.IsActive != nil {
		active = *body.IsActive
	}
	if userID == claims.UserID && (body.Role != "admin" || !active) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no puedes cambiar tu propio rol ni desactivarte"})
		return
	}
	if err := h.Repo.UpdateCompanyMember(c.Request.Context(), claims.CompanyID, userID, body.Email, body.Name, body.Role, active); err != nil {
		writeCompanyMemberError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *AuthController) DeleteCompanyUser(c *gin.Context) {
	claims, ok := h.authorize(c, "admin")
	if !ok {
		return
	}
	if claims.CompanyID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token sin company_id válido"})
		return
	}
	userID, err := strconv.ParseInt(c.Param("user_id"), 10, 64)
	if err != nil || userID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id inválido"})
		return
	}
	if userID == claims.UserID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no puedes eliminarte a ti mismo"})
		return
	}
	if err := h.Repo.RemoveCompanyMember(c.Request.Context(), claims.CompanyID, userID, claims.UserID); err != nil {
		writeCompanyMemberError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func writeCompanyMemberError(c *gin.Context, err error) {
	if errors.Is(err, repository.ErrCompanyUserNotFound) || errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, gin.H{"error": "usuario no encontrado en el equipo"})
		return
	}
	if errors.Is(err, repository.ErrLastCompanyAdmin) {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(err.Error(), "23505") || strings.Contains(strings.ToLower(err.Error()), "unique constraint") {
		c.JSON(http.StatusConflict, gin.H{"error": "email ya registrado"})
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
}

func (h *AuthController) BootstrapPlatformAdmin(c *gin.Context) {
	total, err := h.Repo.CountPlatformAdmins(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if total > 0 {
		c.JSON(http.StatusForbidden, gin.H{"error": "bootstrap deshabilitado: ya existe platform_admin"})
		return
	}

	var body bootstrapPlatformAdminBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "json inválido"})
		return
	}
	body.Email = strings.TrimSpace(strings.ToLower(body.Email))
	body.Name = strings.TrimSpace(body.Name)
	if body.Email == "" || body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email, password y name son obligatorios"})
		return
	}
	if err := validatePasswordPolicy(body.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash"})
		return
	}
	userID, err := h.Repo.CreateUser(c.Request.Context(), body.Email, string(hash), body.Name, true, false, true)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(err.Error(), "23505") || strings.Contains(strings.ToLower(err.Error()), "unique constraint") {
			c.JSON(http.StatusConflict, gin.H{"error": "email ya registrado"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"user_id": userID, "email": body.Email, "role": "platform_admin"})
}

func (h *AuthController) CreateCompanyAdmin(c *gin.Context) {
	if _, ok := h.authorize(c, "platform_admin"); !ok {
		return
	}
	var body createCompanyAdminBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "json inválido"})
		return
	}
	body.Email = strings.TrimSpace(strings.ToLower(body.Email))
	body.Name = strings.TrimSpace(body.Name)
	if body.CompanyID <= 0 || body.Email == "" || body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "company_id, email y name son obligatorios"})
		return
	}
	tempPassword, err := generateTemporaryPassword()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo generar contraseña temporal"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(tempPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash"})
		return
	}

	tx, rw, err := h.Repo.BeginTx(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	userID, err := rw.CreateUser(c.Request.Context(), body.Email, string(hash), body.Name, false, true, true)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(err.Error(), "23505") || strings.Contains(strings.ToLower(err.Error()), "unique constraint") {
			c.JSON(http.StatusConflict, gin.H{"error": "email ya registrado"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := rw.AddCompanyUser(c.Request.Context(), body.CompanyID, userID, "admin"); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no se pudo vincular admin a empresa"})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"user_id":              userID,
		"company_id":           body.CompanyID,
		"role":                 "admin",
		"temporary_password":   tempPassword,
		"must_change_password": true,
	})
}

func (h *AuthController) FirstPasswordChange(c *gin.Context) {
	var body firstPasswordChangeBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "json inválido"})
		return
	}
	body.Email = strings.TrimSpace(strings.ToLower(body.Email))
	if body.Email == "" || body.Password == "" || body.NewPassword == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email, password actual y new_password son obligatorios"})
		return
	}
	if err := validatePasswordPolicy(body.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	u, err := h.Repo.GetUserByEmail(c.Request.Context(), body.Email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "credenciales inválidas"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(body.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "credenciales inválidas"})
		return
	}
	if !u.IsActive {
		c.JSON(http.StatusForbidden, gin.H{"error": "cuenta desactivada"})
		return
	}
	if !u.MustChangePassword {
		c.JSON(http.StatusBadRequest, gin.H{"error": "este usuario no requiere cambio de contraseña inicial"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(body.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash"})
		return
	}
	if err := h.Repo.SetUserPasswordAndClearMustChange(c.Request.Context(), u.ID, string(hash)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *AuthController) ListCompanies(c *gin.Context) {
	if _, ok := h.authorize(c, "platform_admin"); !ok {
		return
	}
	list, err := h.Repo.ListCompanies(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, list)
}

func (h *AuthController) UpdateCompany(c *gin.Context) {
	if _, ok := h.authorize(c, "platform_admin"); !ok {
		return
	}
	companyID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || companyID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id inválido"})
		return
	}
	var body updateCompanyBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "json inválido"})
		return
	}
	hasCommercial := body.RequestedPlan != nil || body.PriceCLPOverride != nil || body.CommissionPercentOverride != nil ||
		(body.ClearPriceOverride != nil && *body.ClearPriceOverride) ||
		(body.ClearCommissionOverride != nil && *body.ClearCommissionOverride)
	if body.Name == nil && body.IsActive == nil && !hasCommercial {
		c.JSON(http.StatusBadRequest, gin.H{"error": "indica qué quieres cambiar"})
		return
	}
	if hasCommercial {
		if body.RequestedPlan != nil {
			id := strings.TrimSpace(strings.ToLower(*body.RequestedPlan))
			body.RequestedPlan = &id
			if id != "" {
				if _, err := h.planByID(c, id); err != nil {
					return
				}
			}
		}
		if body.PriceCLPOverride != nil && *body.PriceCLPOverride < 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "el precio no puede ser negativo"})
			return
		}
		if body.CommissionPercentOverride != nil && (*body.CommissionPercentOverride < 0 || *body.CommissionPercentOverride > 100) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "la comisión va de 0 a 100"})
			return
		}
		clearPrice := body.ClearPriceOverride != nil && *body.ClearPriceOverride
		clearCommission := body.ClearCommissionOverride != nil && *body.ClearCommissionOverride
		if err := h.Repo.SetCompanyCommercial(c.Request.Context(), companyID, body.RequestedPlan, body.PriceCLPOverride, clearPrice, body.CommissionPercentOverride, clearCommission); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(http.StatusNotFound, gin.H{"error": "empresa no encontrada"})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": "no se pudo guardar el plan de la empresa"})
			return
		}
	}
	if body.Name == nil && body.IsActive == nil {
		c.JSON(http.StatusOK, gin.H{"ok": true})
		return
	}
	var namePtr *string
	if body.Name != nil {
		n := strings.TrimSpace(*body.Name)
		if n == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "name no puede estar vacío"})
			return
		}
		namePtr = &n
	}
	var signupAdmin repository.SignupAdmin
	if body.IsActive != nil {
		signupAdmin, err = h.Repo.SignupAdminForCompany(c.Request.Context(), companyID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(http.StatusNotFound, gin.H{"error": "empresa no encontrada"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	activating := body.IsActive != nil && *body.IsActive
	firstApproval := activating && signupAdmin.Plan != "" && !signupAdmin.Approved
	issuingPassword := firstApproval && signupAdmin.UserID > 0 && signupAdmin.MustChange
	if err := h.Repo.PatchCompany(c.Request.Context(), companyID, namePtr, body.IsActive); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "empresa no encontrada"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if firstApproval {
		if err := h.Repo.MarkCompanyApproved(c.Request.Context(), companyID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	if body.IsActive != nil {
		if err := h.Repo.SetCompanyUsersActive(c.Request.Context(), companyID, *body.IsActive); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	if !issuingPassword {
		c.JSON(http.StatusOK, gin.H{"ok": true})
		return
	}
	tempPassword, err := generateTemporaryPassword()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "la empresa quedó activa, pero no se pudo generar la contraseña"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(tempPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash"})
		return
	}
	if err := h.Repo.SetCompanyAdminTemporaryPassword(c.Request.Context(), signupAdmin.UserID, string(hash)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":                 true,
		"email":              signupAdmin.Email,
		"temporary_password": tempPassword,
	})
}

func (h *AuthController) DeleteCompany(c *gin.Context) {
	if _, ok := h.authorize(c, "platform_admin"); !ok {
		return
	}
	companyID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || companyID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "id inválido"})
		return
	}
	if err := h.Repo.DeleteCompany(c.Request.Context(), companyID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "empresa no encontrada"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "no se pudo borrar la empresa"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *AuthController) ListCompanyAdmins(c *gin.Context) {
	if _, ok := h.authorize(c, "platform_admin"); !ok {
		return
	}
	list, err := h.Repo.ListCompanyAdmins(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, list)
}

func (h *AuthController) UpdateCompanyAdmin(c *gin.Context) {
	if _, ok := h.authorize(c, "platform_admin"); !ok {
		return
	}
	userID, err := strconv.ParseInt(c.Param("user_id"), 10, 64)
	if err != nil || userID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id inválido"})
		return
	}
	var body updateCompanyAdminBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "json inválido"})
		return
	}
	email := strings.TrimSpace(strings.ToLower(body.Email))
	name := strings.TrimSpace(body.Name)

	if body.IsActive != nil && email == "" && name == "" {
		if err := h.Repo.SetCompanyAdminActive(c.Request.Context(), userID, *body.IsActive); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(http.StatusNotFound, gin.H{"error": "admin no encontrado"})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
		return
	}
	if email == "" || name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email y name son obligatorios (o envía solo is_active)"})
		return
	}
	if err := h.Repo.UpdateCompanyAdmin(c.Request.Context(), userID, email, name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "admin no encontrado"})
			return
		}
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(err.Error(), "23505") || strings.Contains(strings.ToLower(err.Error()), "unique constraint") {
			c.JSON(http.StatusConflict, gin.H{"error": "email ya registrado"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.IsActive != nil {
		if err := h.Repo.SetCompanyAdminActive(c.Request.Context(), userID, *body.IsActive); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *AuthController) ResetCompanyAdminPassword(c *gin.Context) {
	if _, ok := h.authorize(c, "platform_admin"); !ok {
		return
	}
	userID, err := strconv.ParseInt(c.Param("user_id"), 10, 64)
	if err != nil || userID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id inválido"})
		return
	}
	tempPassword, err := generateTemporaryPassword()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo generar contraseña temporal"})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(tempPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash"})
		return
	}
	if err := h.Repo.SetCompanyAdminTemporaryPassword(c.Request.Context(), userID, string(hash)); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "admin no encontrado"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"temporary_password":   tempPassword,
		"must_change_password": true,
	})
}

func (h *AuthController) DeleteCompanyAdmin(c *gin.Context) {
	if _, ok := h.authorize(c, "platform_admin"); !ok {
		return
	}
	userID, err := strconv.ParseInt(c.Param("user_id"), 10, 64)
	if err != nil || userID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id inválido"})
		return
	}
	if err := h.Repo.DeleteCompanyAdmin(c.Request.Context(), userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "admin no encontrado"})
			return
		}
		msg := err.Error()
		if strings.Contains(msg, "super admin") {
			c.JSON(http.StatusBadRequest, gin.H{"error": msg})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "no se pudo borrar el admin"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
