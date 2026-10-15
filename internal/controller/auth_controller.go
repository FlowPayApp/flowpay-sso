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
	"github.com/flowpay/flowpay-sso/internal/ratelimit"
	"github.com/flowpay/flowpay-sso/internal/repository"
	"github.com/flowpay/flowpay-sso/internal/revoked"
	"github.com/flowpay/flowpay-sso/internal/session"
	"github.com/flowpay/flowpay-sso/internal/signup"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type AuthController struct {
	Repo              *repository.DB
	JWTSecret         []byte
	JWTTTL            time.Duration
	RefreshIdle       time.Duration
	RefreshAbsolute   time.Duration
	SignupSMTP        notify.SMTP
	SignupNotifyEmail string
	Revoked           *revoked.List
	attempts          *ratelimit.Limiter
	pending           *pendingLogins
}

func NewAuthController(db *repository.DB, secret []byte, accessTTL, idle, absolute time.Duration) *AuthController {
	if accessTTL <= 0 {
		accessTTL = 15 * time.Minute
	}
	if idle <= 0 {
		idle = 2 * time.Hour
	}
	if absolute <= 0 {
		absolute = 12 * time.Hour
	}
	list, attempts, pending := newSecurity()
	return &AuthController{
		Repo: db, JWTSecret: secret, JWTTTL: accessTTL, RefreshIdle: idle, RefreshAbsolute: absolute,
		Revoked: list, attempts: attempts, pending: pending,
	}
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
	if h.publicLimited(c, "register", body.Email) {
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
	if _, err := h.Repo.GetUserByEmail(c.Request.Context(), body.Email); err == nil {
		c.JSON(http.StatusCreated, h.registerAccepted())
		return
	} else if !errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
			c.JSON(http.StatusCreated, h.registerAccepted())
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
	c.JSON(http.StatusCreated, h.registerAccepted())
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
	if h.loginLimited(c, body.Email) {
		return
	}

	u, err := h.Repo.GetUserByEmail(c.Request.Context(), body.Email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			h.noteLoginFailure(body.Email, c.ClientIP())
			c.JSON(http.StatusUnauthorized, gin.H{"error": "credenciales inválidas"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(body.Password)); err != nil {
		h.noteLoginFailure(body.Email, c.ClientIP())
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
	if u.IsPlatformAdmin {
		h.beginMFA(c, u, cid, role)
		return
	}

	h.writeSession(c, u.ID, cid, u.Email, role)
}

func (h *AuthController) authorize(c *gin.Context, allowedRoles ...string) (*authjwt.AccessClaims, bool) {
	hdr := strings.TrimSpace(c.GetHeader("Authorization"))
	if hdr == "" || !strings.HasPrefix(hdr, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "se requiere Bearer token"})
		return nil, false
	}
	raw := strings.TrimSpace(strings.TrimPrefix(hdr, "Bearer "))
	claims, err := authjwt.ParseAccessToken(h.JWTSecret, raw)
	if err != nil || h.TokenRevoked(claims.ID) {
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
			c.JSON(http.StatusConflict, gin.H{"error": "Ese correo ya está registrado."})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if hashPtr != nil && !h.revokeUser(c, claims.UserID) {
		return
	}
	if hashPtr != nil {
		h.audit(c.Request.Context(), claims.UserID, claims.UserID, claims.CompanyID, "password_changed")
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
			c.JSON(http.StatusConflict, gin.H{"error": "Ese correo ya está registrado."})
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
			c.JSON(http.StatusConflict, gin.H{"error": "Ese correo ya está registrado."})
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
	h.audit(c.Request.Context(), claims.UserID, userID, claims.CompanyID, "user_created")
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
	currentRole, currentActive, err := h.Repo.CompanyMemberAccess(c.Request.Context(), claims.CompanyID, userID)
	if err != nil {
		writeCompanyMemberError(c, err)
		return
	}
	if err := h.Repo.UpdateCompanyMember(c.Request.Context(), claims.CompanyID, userID, body.Email, body.Name, body.Role, active); err != nil {
		writeCompanyMemberError(c, err)
		return
	}
	if (currentRole != body.Role || currentActive != active) && !h.revokeUser(c, userID) {
		return
	}
	if currentRole != body.Role {
		h.audit(c.Request.Context(), claims.UserID, userID, claims.CompanyID, "role_change")
	}
	if currentActive != active {
		action := "user_deactivated"
		if active {
			action = "user_activated"
		}
		h.audit(c.Request.Context(), claims.UserID, userID, claims.CompanyID, action)
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
	if !h.revokeUser(c, userID) {
		return
	}
	h.audit(c.Request.Context(), claims.UserID, userID, claims.CompanyID, "user_removed")
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
		c.JSON(http.StatusConflict, gin.H{"error": "Ese correo ya está registrado."})
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
}

func (h *AuthController) BootstrapPlatformAdmin(c *gin.Context) {
	if !h.bootstrapOpen(c) {
		return
	}
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
			c.JSON(http.StatusConflict, gin.H{"error": "Ese correo ya está registrado."})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"user_id": userID, "email": body.Email, "role": "platform_admin"})
}

func (h *AuthController) CreateCompanyAdmin(c *gin.Context) {
	claims, ok := h.authorize(c, "platform_admin")
	if !ok {
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

	userID, claimed, err := rw.ClaimOrphanUser(c.Request.Context(), body.Email, string(hash), body.Name)
	if err != nil {
		if errors.Is(err, repository.ErrEmailTaken) || errors.Is(err, repository.ErrPlatformEmail) || errors.Is(err, repository.ErrEmailStillInCompany) {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var revoked []string
	if claimed {
		revoked, err = rw.RevokeUserSessions(c.Request.Context(), userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudieron cerrar las sesiones"})
			return
		}
	} else {
		userID, err = rw.CreateUser(c.Request.Context(), body.Email, string(hash), body.Name, false, true, true)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(err.Error(), "23505") || strings.Contains(strings.ToLower(err.Error()), "unique constraint") {
				c.JSON(http.StatusConflict, gin.H{"error": "Ese correo ya está registrado."})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}
	if err := rw.AddCompanyUser(c.Request.Context(), body.CompanyID, userID, "admin"); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no se pudo vincular admin a empresa"})
		return
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if len(revoked) > 0 {
		h.Revoked.Add(revoked, time.Now().Add(h.JWTTTL))
	}
	if !h.deliverTempPassword(c, body.Email, body.Name, tempPassword) {
		return
	}
	h.audit(c.Request.Context(), claims.UserID, userID, body.CompanyID, "user_created")
	c.JSON(http.StatusCreated, gin.H{
		"user_id":              userID,
		"company_id":           body.CompanyID,
		"role":                 "admin",
		"password_sent":        true,
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
	if h.publicLimited(c, "first-change", body.Email) {
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
	if !h.revokeUser(c, u.ID) {
		return
	}
	h.audit(c.Request.Context(), u.ID, u.ID, 0, "password_changed")
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
	claims, ok := h.authorize(c, "platform_admin")
	if !ok {
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
		if !*body.IsActive && !h.revokeCompany(c, companyID) {
			return
		}
		if !*body.IsActive {
			h.audit(c.Request.Context(), claims.UserID, 0, companyID, "user_deactivated")
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
	if !h.revokeUser(c, signupAdmin.UserID) {
		return
	}
	if !h.deliverTempPassword(c, signupAdmin.Email, "", tempPassword) {
		return
	}
	h.audit(c.Request.Context(), claims.UserID, signupAdmin.UserID, companyID, "password_reset")
	c.JSON(http.StatusOK, gin.H{
		"ok":            true,
		"email":         signupAdmin.Email,
		"password_sent": true,
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
	_ = h.WarmRevoked(c.Request.Context())
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

type createPlatformAdminBody struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

type updatePlatformAdminBody struct {
	IsActive *bool `json:"is_active"`
}

func (h *AuthController) CreatePlatformAdmin(c *gin.Context) {
	claims, ok := h.authorize(c, "platform_admin")
	if !ok {
		return
	}
	var body createPlatformAdminBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "json inválido"})
		return
	}
	body.Email = strings.TrimSpace(strings.ToLower(body.Email))
	body.Name = strings.TrimSpace(body.Name)
	if body.Email == "" || body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email y name son obligatorios"})
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
	userID, claimed, err := rw.CreatePlatformAdmin(c.Request.Context(), body.Email, string(hash), body.Name)
	if err != nil {
		if errors.Is(err, repository.ErrEmailTaken) || errors.Is(err, repository.ErrPlatformEmail) || errors.Is(err, repository.ErrEmailStillInCompany) {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(err.Error(), "23505") || strings.Contains(strings.ToLower(err.Error()), "unique constraint") {
			c.JSON(http.StatusConflict, gin.H{"error": "Ese correo ya está registrado."})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var revoked []string
	if claimed {
		revoked, err = rw.RevokeUserSessions(c.Request.Context(), userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudieron cerrar las sesiones"})
			return
		}
	}
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if len(revoked) > 0 {
		h.Revoked.Add(revoked, time.Now().Add(h.JWTTTL))
	}
	if !h.deliverTempPassword(c, body.Email, body.Name, tempPassword) {
		return
	}
	h.audit(c.Request.Context(), claims.UserID, userID, 0, "user_created")
	c.JSON(http.StatusCreated, gin.H{
		"user_id":              userID,
		"role":                 "platform_admin",
		"password_sent":        true,
		"must_change_password": true,
	})
}

func (h *AuthController) UpdatePlatformAdmin(c *gin.Context) {
	claims, ok := h.authorize(c, "platform_admin")
	if !ok {
		return
	}
	userID, err := strconv.ParseInt(c.Param("user_id"), 10, 64)
	if err != nil || userID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id inválido"})
		return
	}
	var body updatePlatformAdminBody
	if err := c.ShouldBindJSON(&body); err != nil || body.IsActive == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "indica si queda activo"})
		return
	}
	if err := h.Repo.SetPlatformAdminActive(c.Request.Context(), userID, *body.IsActive); err != nil {
		if errors.Is(err, repository.ErrLastPlatformAdmin) {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "superadmin no encontrado"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !*body.IsActive && !h.revokeUser(c, userID) {
		return
	}
	action := "user_activated"
	if !*body.IsActive {
		action = "user_deactivated"
	}
	h.audit(c.Request.Context(), claims.UserID, userID, 0, action)
	c.JSON(http.StatusOK, gin.H{"ok": true, "signed_out": userID == claims.UserID && !*body.IsActive})
}

func (h *AuthController) DeletePlatformAdmin(c *gin.Context) {
	claims, ok := h.authorize(c, "platform_admin")
	if !ok {
		return
	}
	userID, err := strconv.ParseInt(c.Param("user_id"), 10, 64)
	if err != nil || userID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id inválido"})
		return
	}
	revoked, err := h.Repo.DeletePlatformAdmin(c.Request.Context(), userID)
	if err != nil {
		if errors.Is(err, repository.ErrLastPlatformAdmin) {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "superadmin no encontrado"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "no se pudo borrar el superadmin"})
		return
	}
	if len(revoked) > 0 {
		h.Revoked.Add(revoked, time.Now().Add(h.JWTTTL))
	}
	h.audit(c.Request.Context(), claims.UserID, userID, 0, "user_removed")
	c.JSON(http.StatusOK, gin.H{"ok": true, "signed_out": userID == claims.UserID})
}

func (h *AuthController) ListPlatformAdmins(c *gin.Context) {
	if _, ok := h.authorize(c, "platform_admin"); !ok {
		return
	}
	list, err := h.Repo.ListPlatformAdmins(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, list)
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
	claims, ok := h.authorize(c, "platform_admin")
	if !ok {
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
		if !*body.IsActive && !h.revokeUser(c, userID) {
			return
		}
		action := "user_activated"
		if !*body.IsActive {
			action = "user_deactivated"
		}
		companyID, _ := h.Repo.CompanyIDForUser(c.Request.Context(), userID)
		h.audit(c.Request.Context(), claims.UserID, userID, companyID, action)
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
			c.JSON(http.StatusConflict, gin.H{"error": "Ese correo ya está registrado."})
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
		if !*body.IsActive && !h.revokeUser(c, userID) {
			return
		}
		action := "user_activated"
		if !*body.IsActive {
			action = "user_deactivated"
		}
		companyID, _ := h.Repo.CompanyIDForUser(c.Request.Context(), userID)
		h.audit(c.Request.Context(), claims.UserID, userID, companyID, action)
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *AuthController) ResetCompanyAdminPassword(c *gin.Context) {
	claims, ok := h.authorize(c, "platform_admin")
	if !ok {
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
	target, err := h.Repo.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !h.revokeUser(c, userID) {
		return
	}
	if !h.deliverTempPassword(c, target.Email, target.Name, tempPassword) {
		return
	}
	companyID, _ := h.Repo.CompanyIDForUser(c.Request.Context(), userID)
	h.audit(c.Request.Context(), claims.UserID, userID, companyID, "password_reset")
	c.JSON(http.StatusOK, gin.H{
		"password_sent":        true,
		"must_change_password": true,
	})
}

func (h *AuthController) DeleteCompanyAdmin(c *gin.Context) {
	claims, ok := h.authorize(c, "platform_admin")
	if !ok {
		return
	}
	userID, err := strconv.ParseInt(c.Param("user_id"), 10, 64)
	if err != nil || userID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id inválido"})
		return
	}
	companyID, _ := h.Repo.CompanyIDForUser(c.Request.Context(), userID)
	if !h.revokeUser(c, userID) {
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
	h.audit(c.Request.Context(), claims.UserID, userID, companyID, "user_removed")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *AuthController) failRevoke(c *gin.Context, err error) bool {
	if err == nil {
		return false
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudieron cerrar las sesiones"})
	return true
}

func (h *AuthController) setRefreshCookie(c *gin.Context, raw string, absolute time.Time) {
	sec := int(time.Until(absolute).Seconds())
	if sec < 1 {
		sec = 1
	}
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(session.RefreshCookie, raw, sec, session.RefreshPath, "", true, true)
}

func (h *AuthController) clearRefreshCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(session.RefreshCookie, "", -1, session.RefreshPath, "", true, true)
}

func (h *AuthController) writeSession(c *gin.Context, userID, companyID int64, email, role string) {
	raw, hash, err := session.NewRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo abrir la sesión"})
		return
	}
	now := time.Now()
	absolute := now.Add(h.RefreshAbsolute)
	token, jti, err := authjwt.SignAccessToken(h.JWTSecret, userID, companyID, email, role, h.JWTTTL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := h.Repo.CreateAuthSession(c.Request.Context(), userID, hash, jti, now.Add(h.JWTTTL), now, absolute); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo abrir la sesión"})
		return
	}
	h.setRefreshCookie(c, raw, absolute)
	c.JSON(http.StatusOK, tokenResponse(token, h.JWTTTL))
}

func (h *AuthController) Refresh(c *gin.Context) {
	if !session.SameSiteOrigin(c.Request) {
		c.JSON(http.StatusForbidden, gin.H{"error": "origen no permitido"})
		return
	}
	raw, err := c.Cookie(session.RefreshCookie)
	if err != nil || strings.TrimSpace(raw) == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "sesión inválida"})
		return
	}
	nextRaw, nextHash, err := session.NewRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo renovar la sesión"})
		return
	}
	rotated, err := h.Repo.RotateRefresh(c.Request.Context(), session.Hash(raw), nextHash, time.Now(), h.RefreshIdle)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo renovar la sesión"})
		return
	}
	if rotated.Status != repository.RefreshOK {
		h.Revoked.Add(rotated.RevokedJTIs, time.Now().Add(h.JWTTTL))
		if rotated.Status == repository.RefreshReuse {
			h.alertReuse(c.Request.Context(), rotated.UserID)
		}
		h.clearRefreshCookie(c)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "sesión inválida"})
		return
	}

	u, err := h.Repo.GetUserByID(c.Request.Context(), rotated.UserID)
	if err != nil || !u.IsActive || u.MustChangePassword {
		if !h.revokeUser(c, rotated.UserID) {
			return
		}
		h.clearRefreshCookie(c)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "sesión inválida"})
		return
	}
	companyID := int64(0)
	role := "platform_admin"
	if !u.IsPlatformAdmin {
		var status string
		companyID, role, status, err = h.Repo.CompanyLoginForUser(c.Request.Context(), u.ID)
		if err != nil || status != "active" {
			if !h.revokeUser(c, u.ID) {
				return
			}
			h.clearRefreshCookie(c)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "sesión inválida"})
			return
		}
	}
	token, jti, err := authjwt.SignAccessToken(h.JWTSecret, u.ID, companyID, u.Email, role, h.JWTTTL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := h.Repo.RememberAccessJTI(c.Request.Context(), nextHash, jti, time.Now().Add(h.JWTTTL)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo renovar la sesión"})
		return
	}
	h.setRefreshCookie(c, nextRaw, rotated.AbsoluteAt)
	c.JSON(http.StatusOK, tokenResponse(token, h.JWTTTL))
}

func (h *AuthController) Logout(c *gin.Context) {
	if !session.SameSiteOrigin(c.Request) {
		c.JSON(http.StatusForbidden, gin.H{"error": "origen no permitido"})
		return
	}
	raw, _ := c.Cookie(session.RefreshCookie)
	h.clearRefreshCookie(c)
	if strings.TrimSpace(raw) == "" {
		c.JSON(http.StatusOK, gin.H{"ok": true})
		return
	}
	found, err := h.Repo.SessionUserByHash(c.Request.Context(), session.Hash(raw))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo cerrar la sesión"})
		return
	}
	if found > 0 && !h.revokeUser(c, found) {
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
