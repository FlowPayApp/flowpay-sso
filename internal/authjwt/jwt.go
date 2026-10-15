package authjwt

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AccessClaims debe coincidir con flowpay-backend/internal/authjwt (mismos JSON tags).
type AccessClaims struct {
	UserID    int64  `json:"uid"`
	CompanyID int64  `json:"company_id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	jwt.RegisteredClaims
}

// SignAccessToken firma el access token y devuelve su jti.
// El jti son 32 caracteres hex (16 bytes aleatorios) en el claim estándar `jti`.
// Si la sesión se revoca, ese valor queda en revoked_access_tokens hasta expires_at.
// Backend y payments rechazan el token cuando el jti está en esa tabla. Validar la firma no consulta la base.
func SignAccessToken(secret []byte, userID, companyID int64, email, role string, ttl time.Duration) (string, string, error) {
	if len(secret) < 16 {
		return "", "", fmt.Errorf("FLOWPAY_JWT_SECRET demasiado corto (mín. 16 caracteres)")
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	jti := hex.EncodeToString(buf)
	now := time.Now()
	claims := AccessClaims{
		UserID:    userID,
		CompanyID: companyID,
		Email:     email,
		Role:      role,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Subject:   fmt.Sprintf("%d", userID),
			Issuer:    "flowpay-sso",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)
	signed, err := t.SignedString(secret)
	if err != nil {
		return "", "", err
	}
	return signed, jti, nil
}

func ParseAccessToken(secret []byte, raw string) (*AccessClaims, error) {
	if raw == "" {
		return nil, errors.New("token vacío")
	}
	tok, err := jwt.ParseWithClaims(raw, &AccessClaims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("algoritmo inesperado")
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := tok.Claims.(*AccessClaims)
	if !ok || !tok.Valid {
		return nil, errors.New("token inválido")
	}
	return claims, nil
}
