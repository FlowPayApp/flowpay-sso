package notify

import (
	"strings"
	"testing"
	"time"
)

func TestSendFailsFastWhenPortIsClosed(t *testing.T) {
	s := SMTP{
		Host:     "127.0.0.1",
		Port:     "1",
		Username: "cuenta",
		Password: "secreto",
		From:     "cuenta@example.com",
	}
	start := time.Now()
	err := s.SendTemporaryPassword("destino@example.com", "Ana", "clave-temporal")
	if err == nil {
		t.Fatal("esperaba un error de conexión")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("tardó %s, el envío no debe quedar colgado", time.Since(start))
	}
	if strings.Contains(err.Error(), "clave-temporal") {
		t.Fatal("el error no debe incluir la clave")
	}
}
