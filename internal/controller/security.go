package controller

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/flowpay/flowpay-sso/internal/config"
	"github.com/flowpay/flowpay-sso/internal/ratelimit"
	"github.com/flowpay/flowpay-sso/internal/repository"
	"github.com/flowpay/flowpay-sso/internal/revoked"
	"github.com/flowpay/flowpay-sso/internal/secretbox"
	"github.com/flowpay/flowpay-sso/internal/totp"
	"github.com/gin-gonic/gin"
)

const (
	attemptWindow  = 10 * time.Minute
	loginEmailMax  = 8
	loginIPMax     = 30
	loginAlertAt   = 5
	publicEmailMax = 5
	publicIPMax    = 20
	mfaTries       = 5
)

type pendingLogin struct {
	UserID    int64
	Email     string
	Name      string
	CompanyID int64
	Role      string
	Secret    string
	Setup     bool
	Tries     int
	Expires   time.Time
}

type pendingLogins struct {
	mu    sync.Mutex
	items map[string]pendingLogin
}

func (p *pendingLogins) put(token string, item pendingLogin) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for key, current := range p.items {
		if !current.Expires.After(now) {
			delete(p.items, key)
		}
	}
	p.items[token] = item
}

func (p *pendingLogins) get(token string) (pendingLogin, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	item, ok := p.items[token]
	if !ok || !item.Expires.After(time.Now()) {
		delete(p.items, token)
		return pendingLogin{}, false
	}
	return item, true
}

func (p *pendingLogins) fail(token string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	item, ok := p.items[token]
	if !ok {
		return
	}
	item.Tries++
	if item.Tries >= mfaTries {
		delete(p.items, token)
		return
	}
	p.items[token] = item
}

func (p *pendingLogins) consume(token string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.items, token)
}

func (h *AuthController) TokenRevoked(jti string) bool {
	if h == nil || h.Revoked == nil {
		return false
	}
	return h.Revoked.Has(jti)
}

func (h *AuthController) WarmRevoked(ctx context.Context) error {
	items, err := h.Repo.ListLiveRevokedJTIs(ctx)
	if err != nil {
		return err
	}
	next := map[string]time.Time{}
	for _, item := range items {
		next[item.JTI] = item.Expires
	}
	h.Revoked.Replace(next)
	return nil
}

func (h *AuthController) revokeUser(c *gin.Context, userID int64) bool {
	jtis, err := h.Repo.RevokeUserSessions(c.Request.Context(), userID)
	if h.failRevoke(c, err) {
		return false
	}
	h.Revoked.Add(jtis, time.Now().Add(h.JWTTTL))
	return true
}

func (h *AuthController) revokeCompany(c *gin.Context, companyID int64) bool {
	jtis, err := h.Repo.RevokeCompanySessions(c.Request.Context(), companyID)
	if h.failRevoke(c, err) {
		return false
	}
	h.Revoked.Add(jtis, time.Now().Add(h.JWTTTL))
	return true
}

func (h *AuthController) audit(ctx context.Context, actor, target, company int64, action string) {
	if err := h.Repo.InsertAudit(ctx, actor, target, company, action); err != nil {
		log.Printf("[FlowPay audit] %s: %v", action, err)
	}
}

func (h *AuthController) dataKey() []byte {
	material := strings.TrimSpace(os.Getenv("FLOWPAY_DATA_KEY"))
	if material == "" {
		if config.Production() {
			log.Fatal("FLOWPAY_DATA_KEY es obligatoria en producción (mín. 32 caracteres); no se deriva del JWT")
		}
		material = string(h.JWTSecret)
	}
	return secretbox.Key(material)
}

func (h *AuthController) tooMany(c *gin.Context) {
	c.JSON(http.StatusTooManyRequests, gin.H{"error": "Demasiados intentos. Espera unos minutos."})
}

func (h *AuthController) loginLimited(c *gin.Context, email string) bool {
	now := time.Now()
	if h.attempts.Blocked("login:ip:"+c.ClientIP(), loginIPMax, attemptWindow, now) ||
		h.attempts.Blocked("login:email:"+email, loginEmailMax, attemptWindow, now) {
		h.tooMany(c)
		return true
	}
	return false
}

func (h *AuthController) noteLoginFailure(email, ip string) {
	_, tripped := h.attempts.Hit("login:email:"+email, loginAlertAt, attemptWindow, time.Now())
	h.attempts.Hit("login:ip:"+ip, loginIPMax, attemptWindow, time.Now())
	if tripped {
		h.alertAdmins("Muchos intentos de ingreso", "El correo "+email+" falló varias veces al entrar. No se incluye la contraseña.")
	}
}

func (h *AuthController) publicLimited(c *gin.Context, kind, email string) bool {
	now := time.Now()
	ip := c.ClientIP()
	if h.attempts.Blocked(kind+":ip:"+ip, publicIPMax, attemptWindow, now) ||
		h.attempts.Blocked(kind+":email:"+email, publicEmailMax, attemptWindow, now) {
		h.tooMany(c)
		return true
	}
	h.attempts.Hit(kind+":ip:"+ip, publicIPMax, attemptWindow, now)
	h.attempts.Hit(kind+":email:"+email, publicEmailMax, attemptWindow, now)
	return false
}

func (h *AuthController) alertAdmins(subject, body string) {
	emails, err := h.Repo.ListPlatformAdminEmails(context.Background())
	if err != nil {
		log.Printf("[FlowPay security] %s", subject)
		return
	}
	_ = h.SignupSMTP.SendSecurity(emails, subject, body)
}

func (h *AuthController) alertReuse(ctx context.Context, userID int64) {
	who := "una sesión"
	if userID > 0 {
		if u, err := h.Repo.GetUserByID(ctx, userID); err == nil {
			who = u.Email
		}
	}
	h.alertAdmins("Sesión reutilizada", "Se volvió a usar un refresh token ya gastado de "+who+". Esa sesión quedó cerrada.")
}

func (h *AuthController) deliverTempPassword(c *gin.Context, email, name, password string) bool {
	if err := h.SignupSMTP.SendTemporaryPassword(email, name, password); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "no se pudo enviar la clave por correo"})
		return false
	}
	return true
}

func (h *AuthController) bootstrapOpen(c *gin.Context) bool {
	secret := os.Getenv("FLOWPAY_BOOTSTRAP_SECRET")
	production := strings.EqualFold(strings.TrimSpace(os.Getenv("FLOWPAY_ENV")), "production")
	if production && strings.TrimSpace(secret) == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "no encontrado"})
		return false
	}
	if strings.TrimSpace(secret) != "" && subtle.ConstantTimeCompare([]byte(c.GetHeader("X-Bootstrap-Secret")), []byte(secret)) != 1 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no encontrado"})
		return false
	}
	return true
}

func (h *AuthController) registerAccepted() gin.H {
	return gin.H{
		"pending": true,
		"message": "Recibimos tu solicitud. La revisamos y, cuando la empresa quede lista, te escribimos con la contraseña para entrar.",
	}
}

func (h *AuthController) beginMFA(c *gin.Context, u *repository.User, companyID int64, role string) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo iniciar la verificación"})
		return
	}
	token := base64.RawURLEncoding.EncodeToString(buf)
	item := pendingLogin{
		UserID:    u.ID,
		Email:     u.Email,
		Name:      u.Name,
		CompanyID: companyID,
		Role:      role,
		Expires:   time.Now().Add(5 * time.Minute),
	}
	if strings.TrimSpace(u.TotpSecret) == "" {
		secret, uri, err := totp.New(u.Email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo preparar el código"})
			return
		}
		item.Setup = true
		item.Secret = secret
		h.pending.put(token, item)
		c.JSON(http.StatusOK, gin.H{
			"mfa_setup":   true,
			"mfa_token":   token,
			"secret":      secret,
			"otpauth_url": uri,
		})
		return
	}
	h.pending.put(token, item)
	c.JSON(http.StatusOK, gin.H{"mfa_required": true, "mfa_token": token})
}

type mfaBody struct {
	Token string `json:"mfa_token"`
	Code  string `json:"code"`
}

// LoginMFA godoc
// @Summary Completar login con TOTP
// @Description Tras /auth/login de un superadmin. En el primer ingreso también enrola el secreto.
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body MFARequest true "Token MFA y código"
// @Success 200 {object} TokenBody
// @Failure 400 {object} ErrorBody
// @Failure 401 {object} ErrorBody
// @Failure 429 {object} ErrorBody
// @Failure 500 {object} ErrorBody
// @Router /auth/login/mfa [post]
func (h *AuthController) LoginMFA(c *gin.Context) {
	var body mfaBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "json inválido"})
		return
	}
	body.Token = strings.TrimSpace(body.Token)
	body.Code = strings.TrimSpace(body.Code)
	now := time.Now()
	if h.attempts.Blocked("mfa:ip:"+c.ClientIP(), publicIPMax, attemptWindow, now) {
		h.tooMany(c)
		return
	}
	item, ok := h.pending.get(body.Token)
	if !ok {
		h.attempts.Hit("mfa:ip:"+c.ClientIP(), publicIPMax, attemptWindow, now)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "código inválido"})
		return
	}
	secret := item.Secret
	if !item.Setup {
		u, err := h.Repo.GetUserByID(c.Request.Context(), item.UserID)
		if err != nil || strings.TrimSpace(u.TotpSecret) == "" {
			h.pending.consume(body.Token)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "código inválido"})
			return
		}
		secret, err = secretbox.Open(h.dataKey(), u.TotpSecret)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo verificar el código"})
			return
		}
	}
	if !totp.Verify(secret, body.Code, now) {
		h.pending.fail(body.Token)
		h.attempts.Hit("mfa:ip:"+c.ClientIP(), publicIPMax, attemptWindow, now)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "código inválido"})
		return
	}
	if item.Setup {
		sealed, err := secretbox.Seal(h.dataKey(), secret)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo guardar el código"})
			return
		}
		if err := h.Repo.SetUserTOTP(c.Request.Context(), item.UserID, sealed); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		h.audit(c.Request.Context(), item.UserID, item.UserID, item.CompanyID, "mfa_enrolled")
	}
	h.pending.consume(body.Token)
	h.writeSession(c, item.UserID, item.CompanyID, item.Email, item.Role)
}

// ResetPlatformMFA godoc
// @Summary Resetear TOTP de otro superadmin
// @Tags Plataforma
// @Produce json
// @Security BearerAuth
// @Param user_id path int true "ID de usuario"
// @Success 200 {object} OKBody
// @Failure 400 {object} ErrorBody
// @Failure 401 {object} ErrorBody
// @Failure 403 {object} ErrorBody
// @Failure 404 {object} ErrorBody
// @Failure 500 {object} ErrorBody
// @Router /auth/platform/admins/{user_id}/reset-mfa [post]
func (h *AuthController) ResetPlatformMFA(c *gin.Context) {
	claims, ok := h.authorize(c, "platform_admin")
	if !ok {
		return
	}
	userID, err := strconv.ParseInt(c.Param("user_id"), 10, 64)
	if err != nil || userID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_id inválido"})
		return
	}
	if userID == claims.UserID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "otro superadmin debe resetear tu código"})
		return
	}
	u, err := h.Repo.GetUserByID(c.Request.Context(), userID)
	if err != nil || !u.IsPlatformAdmin {
		c.JSON(http.StatusNotFound, gin.H{"error": "superadmin no encontrado"})
		return
	}
	if err := h.Repo.SetUserTOTP(c.Request.Context(), userID, ""); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !h.revokeUser(c, userID) {
		return
	}
	h.audit(c.Request.Context(), claims.UserID, userID, 0, "mfa_reset")
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func newSecurity() (*revoked.List, *ratelimit.Limiter, *pendingLogins) {
	return revoked.New(), ratelimit.New(), &pendingLogins{items: map[string]pendingLogin{}}
}
