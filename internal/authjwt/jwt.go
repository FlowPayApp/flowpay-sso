package authjwt

import (
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

func SignAccessToken(secret []byte, userID, companyID int64, email, role string, ttl time.Duration) (string, error) {
	if len(secret) < 16 {
		return "", fmt.Errorf("FLOWPAY_JWT_SECRET demasiado corto (mín. 16 caracteres)")
	}
	now := time.Now()
	claims := AccessClaims{
		UserID:    userID,
		CompanyID: companyID,
		Email:     email,
		Role:      role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   fmt.Sprintf("%d", userID),
			Issuer:    "flowpay-sso",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)
	return t.SignedString(secret)
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
