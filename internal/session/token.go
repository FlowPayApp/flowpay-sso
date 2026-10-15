package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
)

const (
	RefreshCookie = "flowpay_refresh"
	RefreshPath   = "/api/auth"
)

// NewRefreshToken devuelve el valor opaco de la cookie y el hash que se guarda.
func NewRefreshToken() (raw, hash string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", err
	}
	raw = base64.RawURLEncoding.EncodeToString(buf)
	return raw, Hash(raw), nil
}

func Hash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// SameSiteOrigin exige que el Origin del navegador coincida con el host público
// (el que ve el front), no con el host interno del SSO detrás del proxy.
func SameSiteOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.Scheme == "" {
		return false
	}
	host := firstHeader(r.Header.Get("X-Flowpay-Public-Host"))
	if host == "" {
		host = firstHeader(r.Header.Get("X-Forwarded-Host"))
	}
	if host == "" {
		host = r.Host
	}
	if !strings.EqualFold(u.Host, host) {
		return false
	}
	proto := firstHeader(r.Header.Get("X-Flowpay-Public-Proto"))
	if proto == "" {
		proto = firstHeader(r.Header.Get("X-Forwarded-Proto"))
	}
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	return strings.EqualFold(u.Scheme, proto)
}

func firstHeader(v string) string {
	if i := strings.Index(v, ","); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}
