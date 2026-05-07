package handler

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/flowpay/flowpay-sso/internal/authjwt"
	"github.com/flowpay/flowpay-sso/internal/repo"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type Auth struct {
	Repo      *repo.Repository
	JWTSecret []byte
	JWTTTL    time.Duration
}

func NewAuth(r *repo.Repository, secret []byte, ttl time.Duration) *Auth {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &Auth{Repo: r, JWTSecret: secret, JWTTTL: ttl}
}

type registerBody struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	Name        string `json:"name"`
	CompanyName string `json:"company_name"`
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
	Name     *string `json:"name"`
	IsActive *bool   `json:"is_active"`
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

func (h *Auth) Register(c *gin.Context) {
	var body registerBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "json inválido"})
		return
	}
	body.Email = strings.TrimSpace(strings.ToLower(body.Email))
	if body.Email == "" || strings.TrimSpace(body.Name) == "" || strings.TrimSpace(body.CompanyName) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email, password, name y company_name son obligatorios"})
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
	userID, err := rw.CreateUser(c.Request.Context(), body.Email, string(hash), body.Name, false, false, true)
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

	token, err := authjwt.SignAccessToken(h.JWTSecret, userID, companyID, body.Email, "admin", h.JWTTTL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, tokenResponse(token, h.JWTTTL))
}

func (h *Auth) Login(c *gin.Context) {
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

	cid := int64(0)
	role := "platform_admin"
	if !u.IsPlatformAdmin {
		cid, role, err = h.Repo.FirstCompanyIDForUser(c.Request.Context(), u.ID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				c.JSON(http.StatusForbidden, gin.H{"error": "usuario sin empresa asignada"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	token, err := authjwt.SignAccessToken(h.JWTSecret, u.ID, cid, u.Email, role, h.JWTTTL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, tokenResponse(token, h.JWTTTL))
}

func (h *Auth) authorize(c *gin.Context, allowedRoles ...string) (*authjwt.AccessClaims, bool) {
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

func (h *Auth) GetProfile(c *gin.Context) {
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

func (h *Auth) UpdateProfile(c *gin.Context) {
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

func (h *Auth) CreateCompanyWithAdmin(c *gin.Context) {
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

func (h *Auth) CreateCompany(c *gin.Context) {
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

func (h *Auth) CreateCompanyUser(c *gin.Context) {
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

func (h *Auth) BootstrapPlatformAdmin(c *gin.Context) {
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

func (h *Auth) CreateCompanyAdmin(c *gin.Context) {
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

func (h *Auth) FirstPasswordChange(c *gin.Context) {
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

func (h *Auth) ListCompanies(c *gin.Context) {
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

func (h *Auth) UpdateCompany(c *gin.Context) {
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
	if body.Name == nil && body.IsActive == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "indica name y/o is_active"})
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
	if err := h.Repo.PatchCompany(c.Request.Context(), companyID, namePtr, body.IsActive); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "empresa no encontrada"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *Auth) ListCompanyAdmins(c *gin.Context) {
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

func (h *Auth) UpdateCompanyAdmin(c *gin.Context) {
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

func (h *Auth) ResetCompanyAdminPassword(c *gin.Context) {
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
