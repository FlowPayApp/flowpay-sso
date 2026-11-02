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
		if audit.Once("password-forgot-smtp:"+email, attemptWindow) {
			h.noteRecovery(c, 0, 0, "", email, "No se pudo enviar el código de recuperación", audit.OutcomeFailure, "recovery_smtp_unconfigured", "el correo de la plataforma no está configurado")
		}
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "no se pudo enviar el código por correo"})
		return
	}
	if h.publicLimited(c, "password-forgot", email) {
		return
	}

	u, err := h.Repo.GetUserByEmail(c.Request.Context(), email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			h.noteRecovery(c, 0, 0, "", email, "Intento de recuperación de "+audit.MaskEmail(email), audit.OutcomeFailure, "recovery_unknown_email", "no hay una cuenta con ese correo")
			c.JSON(http.StatusOK, gin.H{"ok": true, "message": resetCodeAck})
			return
		}
		h.noteRecovery(c, 0, 0, "", email, "No se pudo iniciar la recuperación", audit.OutcomeFailure, "recovery_lookup_error", "no se pudo comprobar la cuenta")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo iniciar la recuperación"})
		return
	}
	if !u.IsActive {
		h.noteRecovery(c, u.ID, 0, u.Name, u.Email, "Cuenta inactiva pidió restablecer la contraseña", audit.OutcomeDenied, "recovery_inactive", "la cuenta está desactivada")
		c.JSON(http.StatusOK, gin.H{"ok": true, "message": resetCodeAck})
		return
	}

	code, err := newResetCode()
	if err != nil {
		h.noteRecovery(c, u.ID, 0, u.Name, u.Email, "No se pudo generar el código de recuperación", audit.OutcomeFailure, "recovery_code_error", "no se pudo generar el código")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo generar el código"})
		return
	}
	hash := hashResetCode(h.dataKey(), u.ID, code)
	expires := time.Now().Add(resetCodeTTL)
	if err := h.Repo.SavePasswordReset(c.Request.Context(), u.ID, hash, expires); err != nil {
		h.noteRecovery(c, u.ID, 0, u.Name, u.Email, "No se pudo guardar el código de recuperación", audit.OutcomeFailure, "recovery_store_error", "no se pudo guardar el código")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo guardar el código"})
		return
	}
	if err := h.SignupSMTP.SendResetCode(u.Email, u.Name, code); err != nil {
		_ = h.Repo.DeletePasswordReset(c.Request.Context(), u.ID)
		h.noteRecovery(c, u.ID, 0, u.Name, u.Email, "No se pudo enviar el código de recuperación", audit.OutcomeFailure, "recovery_send_error", audit.Cause(err))
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "no se pudo enviar el código por correo"})
		return
	}
	companyID, _ := h.Repo.CompanyIDForUser(c.Request.Context(), u.ID)
	h.noteRecovery(c, u.ID, companyID, u.Name, u.Email, "Pidió restablecer la contraseña", audit.OutcomeSuccess, "", "")
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
			h.noteRecovery(c, 0, 0, "", email, "Intento de restablecer la contraseña de "+audit.MaskEmail(email), audit.OutcomeFailure, "recovery_unknown_email", "no hay una cuenta con ese correo")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "El código no es válido o ya venció."})
			return
		}
		h.noteRecovery(c, 0, 0, "", email, "No se pudo restablecer la contraseña", audit.OutcomeFailure, "recovery_lookup_error", "no se pudo comprobar la cuenta")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo restablecer la contraseña"})
		return
	}
	if !u.IsActive {
		h.noteRecovery(c, u.ID, 0, u.Name, u.Email, "Cuenta inactiva intentó restablecer la contraseña", audit.OutcomeDenied, "recovery_inactive", "la cuenta está desactivada")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "El código no es válido o ya venció."})
		return
	}

	item, err := h.Repo.GetPasswordReset(c.Request.Context(), u.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			h.noteRecovery(c, u.ID, 0, u.Name, u.Email, "Intentó restablecer la contraseña sin un código vigente", audit.OutcomeFailure, "recovery_no_code", "no hay un código vigente")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "El código no es válido o ya venció."})
			return
		}
		h.noteRecovery(c, u.ID, 0, u.Name, u.Email, "No se pudo restablecer la contraseña", audit.OutcomeFailure, "recovery_lookup_error", "no se pudo leer el código")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo restablecer la contraseña"})
		return
	}
	if !item.ExpiresAt.After(time.Now()) {
		_ = h.Repo.DeletePasswordReset(c.Request.Context(), u.ID)
		h.noteRecovery(c, u.ID, 0, u.Name, u.Email, "Usó un código de recuperación vencido", audit.OutcomeFailure, "recovery_expired", "el código venció")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "El código no es válido o ya venció."})
		return
	}
	if item.Attempts >= resetCodeAttempts {
		_ = h.Repo.DeletePasswordReset(c.Request.Context(), u.ID)
		h.noteRecovery(c, u.ID, 0, u.Name, u.Email, "Se agotaron los intentos del código de recuperación", audit.OutcomeDenied, "recovery_attempts", "se agotaron los intentos")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Se agotaron los intentos de este código. Pide uno nuevo."})
		return
	}
	got := hashResetCode(h.dataKey(), u.ID, code)
	if subtle.ConstantTimeCompare([]byte(got), []byte(item.CodeHash)) != 1 {
		attempts, attemptErr := h.Repo.AddPasswordResetAttempt(c.Request.Context(), u.ID)
		if attemptErr != nil {
			h.noteRecovery(c, u.ID, 0, u.Name, u.Email, "No se pudo restablecer la contraseña", audit.OutcomeFailure, "recovery_attempt_error", "no se pudo anotar el intento")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "El código no es válido o ya venció."})
			return
		}
		if attempts >= resetCodeAttempts {
			_ = h.Repo.DeletePasswordReset(c.Request.Context(), u.ID)
			h.noteRecovery(c, u.ID, 0, u.Name, u.Email, "Se agotaron los intentos del código de recuperación", audit.OutcomeDenied, "recovery_attempts", "se agotaron los intentos")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Se agotaron los intentos de este código. Pide uno nuevo."})
			return
		}
		h.noteRecovery(c, u.ID, 0, u.Name, u.Email, "Código de recuperación incorrecto", audit.OutcomeFailure, "recovery_wrong_code", "el código no coincide")
		c.JSON(http.StatusUnauthorized, gin.H{"error": resetAttemptsLeftMessage(resetCodeAttempts - attempts)})
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(body.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		h.noteRecovery(c, u.ID, 0, u.Name, u.Email, "No se pudo restablecer la contraseña", audit.OutcomeFailure, "recovery_hash_error", "no se pudo guardar la nueva contraseña")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "hash"})
		return
	}
	if err := h.Repo.DeletePasswordReset(c.Request.Context(), u.ID); err != nil {
		h.noteRecovery(c, u.ID, 0, u.Name, u.Email, "No se pudo restablecer la contraseña", audit.OutcomeFailure, "recovery_store_error", "no se pudo cerrar el código usado")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo restablecer la contraseña"})
		return
	}
	if err := h.Repo.SetUserPasswordAndClearMustChange(c.Request.Context(), u.ID, string(passwordHash)); err != nil {
		h.noteRecovery(c, u.ID, 0, u.Name, u.Email, "No se pudo restablecer la contraseña", audit.OutcomeFailure, "recovery_store_error", "no se pudo guardar la nueva contraseña")
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	companyID, _ := h.Repo.CompanyIDForUser(c.Request.Context(), u.ID)
	who := strings.TrimSpace(u.Name)
	if who == "" {
		who = audit.MaskEmail(u.Email)
	}
	h.audit(c, audit.Event{
		Domain:     audit.DomainAuth,
		Action:     audit.ActionPasswordChanged,
		ActorID:    u.ID,
		CompanyID:  companyID,
		TargetType: audit.TargetUser,
		TargetID:   audit.ID(u.ID),
		Summary:    "Restableció la contraseña " + who,
		Meta:       map[string]any{"email": audit.MaskEmail(u.Email)},
	})
	if !h.revokeUser(c, u.ID) {
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *AuthController) resetGuessLimited(c *gin.Context) bool {
	const maxGuessesPerIP = 30
	now := time.Now()
	key := "password-reset:ip:" + audit.RequestIP(c)
	if h.attempts.Blocked(key, maxGuessesPerIP, attemptWindow, now) {
		h.tooMany(c)
		return true
	}
	if _, tripped := h.attempts.Hit(key, maxGuessesPerIP, attemptWindow, now); tripped {
		h.noteAccessBlocked(c, "password-reset", "")
	}
	return false
}

func (h *AuthController) noteRecovery(c *gin.Context, userID, companyID int64, name, email, summary, outcome, code, reason string) {
	reason = strings.TrimSpace(reason)
	if reason != "" && !strings.Contains(summary, reason) {
		summary = strings.TrimSpace(summary) + ": " + reason
	}
	who := strings.TrimSpace(name)
	if who != "" && userID > 0 {
		summary = strings.TrimSpace(summary) + " · " + who
	}
	meta := map[string]any{}
	if strings.TrimSpace(email) != "" {
		meta["email"] = audit.MaskEmail(email)
	}
	if strings.TrimSpace(code) != "" {
		meta["code"] = code
	}
	if reason != "" {
		meta["reason"] = reason
	}
	event := audit.Event{
		Domain:    audit.DomainAuth,
		Action:    audit.ActionPasswordReset,
		Outcome:   outcome,
		ActorID:   userID,
		CompanyID: companyID,
		Summary:   summary,
		Meta:      meta,
	}
	if userID > 0 {
		event.TargetType = audit.TargetUser
		event.TargetID = audit.ID(userID)
	}
	h.audit(c, event)
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
