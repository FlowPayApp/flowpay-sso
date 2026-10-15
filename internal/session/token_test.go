package session

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHashIsStableAndNotTheRawToken(t *testing.T) {
	raw, hash, err := NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	if raw == "" || hash == "" || raw == hash {
		t.Fatalf("token opaco inválido")
	}
	if Hash(raw) != hash {
		t.Fatal("el hash no corresponde al token")
	}
}

func TestSameSiteOrigin(t *testing.T) {
	ok := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	ok.Host = "127.0.0.1:9090"
	ok.Header.Set("Origin", "http://localhost:5173")
	ok.Header.Set("X-Forwarded-Host", "localhost:5173")
	ok.Header.Set("X-Forwarded-Proto", "http")
	if !SameSiteOrigin(ok) {
		t.Fatal("el origen del front detrás del proxy debería valer")
	}

	evil := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	evil.Host = "geldflus.com"
	evil.Header.Set("Origin", "https://evil.example")
	evil.Header.Set("X-Forwarded-Host", "geldflus.com")
	evil.Header.Set("X-Forwarded-Proto", "https")
	if SameSiteOrigin(evil) {
		t.Fatal("un Origin ajeno no debería pasar")
	}

	missing := httptest.NewRequest(http.MethodPost, "/api/auth/refresh", nil)
	missing.Host = "geldflus.com"
	missing.Header.Set("X-Forwarded-Proto", "https")
	if SameSiteOrigin(missing) {
		t.Fatal("sin Origin no debería pasar")
	}
}
