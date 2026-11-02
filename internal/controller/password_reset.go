package controller

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/flowpay/flowpay-sso/internal/audit"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

const (
	resetCodeTTL      = 15 * time.Minute
	resetCodeAttempts = 5
	resetCodeAck      = "Si el correo está registrado, enviamos un código para restablecer la contraseña."
)

type forgotPasswordBody struct {
	Email string `json:"email"`
}

type resetPasswordBody struct {
	Email       string `json:"email"`
	Code        string `json:"code"`
	NewPassword string `json:"new_password"`
}

func (h *AuthController) RequestPasswordReset(c *gin.Context) {
	var body forgotPasswordBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "json inválido"})
		return
	}
	email := strings.TrimSpace(strings.ToLower(body.Email))
	if !validAccountEmail(email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "correo inválido"})
		return
	}
	if !h.SignupSMTP.Configured() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "no se pudo enviar el código por correo"})
		return
	}
	if h.publicLimited(c, "password-forgot", email) {
		return
	}

	u, err := h.Repo.GetUserByEmail(c.Request.Context(), email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusOK, gin.H{"ok": true, "message": resetCodeAck})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo iniciar la recuperación"})
		return
	}
	if !u.IsActive {
		c.JSON(http.StatusOK, gin.H{"ok": true, "message": resetCodeAck})
		return
	}

	code, err := newResetCode()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo generar el código"})
		return
	}
	hash := hashResetCode(h.dataKey(), u.ID, code)
	expires := time.Now().Add(resetCodeTTL)
	if err := h.Repo.SavePasswordReset(c.Request.Context(), u.ID, hash, expires); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo guardar el código"})
		return
	}
	if err := h.SignupSMTP.SendResetCode(u.Email, u.Name, code); err != nil {
		_ = h.Repo.DeletePasswordReset(c.Request.Context(), u.ID)
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "no se pudo enviar el código por correo"})
		return
	}
	companyID, _ := h.Repo.CompanyIDForUser(c.Request.Context(), u.ID)
	h.audit(c, audit.Event{
		Domain:     audit.DomainAuth,
		Action:     audit.ActionPasswordReset,
		ActorID:    u.ID,
		CompanyID:  companyID,
		TargetType: audit.TargetUser,
		TargetID:   audit.ID(u.ID),
		Summary:    "Envió un código para restablecer la contraseña",
		Meta:       map[string]any{"email": audit.MaskEmail(u.Email)},
	})
	c.JSON(http.StatusOK, gin.H{"ok": true, "message": resetCodeAck})
}

func (h *AuthController) ConfirmPasswordReset(c *gin.Context) {
	var body resetPasswordBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "json inválido"})
		return
	}
	email := strings.TrimSpace(strings.ToLower(body.Email))
	code := onlyDigits(body.Code)
	if !validAccountEmail(email) || len(code) != 6 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "correo y código de 6 dígitos son obligatorios"})
		return
	}
	if err := validatePasswordPolicy(body.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if h.resetGuessLimited(c) {
		return
	}

	u, err := h.Repo.GetUserByEmail(c.Request.Context(), email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "El código no es válido o ya venció."})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo restablecer la contraseña"})
		return
	}
	if !u.IsActive {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "El código no es válido o ya venció."})
		return
	}

	item, err := h.Repo.GetPasswordReset(c.Request.Context(), u.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "El código no es válido o ya venció."})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo restablecer la contraseña"})
		return
	}
	if !item.ExpiresAt.After(time.Now()) {
		_ = h.Repo.DeletePasswordReset(c.Request.Context(), u.ID)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "El código no es válido o ya venció."})
		return
	}
	if item.Attempts >= resetCodeAttempts {
		_ = h.Repo.DeletePasswordReset(c.Request.Context(), u.ID)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Se agotaron los intentos de este código. Pide uno nuevo."})
		return
	}
	got := hashResetCode(h.dataKey(), u.ID, code)
	if subtle.ConstantTimeCompare([]byte(got), []byte(item.CodeHash)) != 1 {
		attempts, attemptErr := h.Repo.AddPasswordResetAttempt(c.Request.Context(), u.ID)
		if attemptErr != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "El código no es válido o ya venció."})
			return
		}
		if attempts >= resetCodeAttempts {
			_ = h.Repo.DeletePasswordReset(c.Request.Context(), u.ID)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Se agotaron los intentos de este código. Pide uno nuevo."})
			return
		}
		c.JSON(http.StatusUnauthorized, gin.H{"error": resetAttemptsLeftMessage(resetCodeAttempts - attempts)})
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(body.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash"})
		return
	}
	if err := h.Repo.DeletePasswordReset(c.Request.Context(), u.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo restablecer la contraseña"})
		return
	}
	if err := h.Repo.SetUserPasswordAndClearMustChange(c.Request.Context(), u.ID, string(passwordHash)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !h.revokeUser(c, u.ID) {
		return
	}
	companyID, _ := h.Repo.CompanyIDForUser(c.Request.Context(), u.ID)
	h.audit(c, audit.Event{
		Domain:     audit.DomainAuth,
		Action:     audit.ActionPasswordChanged,
		ActorID:    u.ID,
		CompanyID:  companyID,
		TargetType: audit.TargetUser,
		TargetID:   audit.ID(u.ID),
		Summary:    "Restableció su contraseña con un código",
	})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *AuthController) resetGuessLimited(c *gin.Context) bool {
	const maxGuessesPerIP = 30
	now := time.Now()
	key := "password-reset:ip:" + c.ClientIP()
	if h.attempts.Blocked(key, maxGuessesPerIP, attemptWindow, now) {
		h.tooMany(c)
		return true
	}
	if _, tripped := h.attempts.Hit(key, maxGuessesPerIP, attemptWindow, now); tripped {
		h.noteAccessBlocked(c, "password-reset", "")
	}
	return false
}

func resetAttemptsLeftMessage(left int) string {
	if left == 1 {
		return "Código incorrecto. Te queda 1 intento."
	}
	return fmt.Sprintf("Código incorrecto. Te quedan %d intentos.", left)
}

func newResetCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return strconv.FormatInt(n.Int64()+1_000_000, 10)[1:], nil
}

func hashResetCode(key []byte, userID int64, code string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(strconv.FormatInt(userID, 10)))
	_, _ = mac.Write([]byte{':'})
	_, _ = mac.Write([]byte(code))
	return hex.EncodeToString(mac.Sum(nil))
}

func validAccountEmail(email string) bool {
	if email == "" || len(email) > 254 || strings.ContainsAny(email, " \t\r\n") {
		return false
	}
	at := strings.LastIndex(email, "@")
	if at < 1 || at > len(email)-4 {
		return false
	}
	domain := email[at+1:]
	return strings.Contains(domain, ".") && !strings.HasPrefix(domain, ".") && !strings.HasSuffix(domain, ".")
}
