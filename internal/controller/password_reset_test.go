package controller

import "testing"

func TestResetCodeIsSixDigitsAndStableHash(t *testing.T) {
	code, err := newResetCode()
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 6 {
		t.Fatalf("código de %d dígitos: %q", len(code), code)
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			t.Fatalf("código no numérico: %q", code)
		}
	}
	key := []byte("clave-de-prueba")
	a := hashResetCode(key, 7, code)
	b := hashResetCode(key, 7, code)
	other := hashResetCode(key, 7, "000000")
	if a != b || a == other || len(a) != 64 {
		t.Fatalf("hash inesperado")
	}
}

func TestResetAttemptsLeftMessage(t *testing.T) {
	if got := resetAttemptsLeftMessage(1); got != "Código incorrecto. Te queda 1 intento." {
		t.Fatal(got)
	}
	if got := resetAttemptsLeftMessage(4); got != "Código incorrecto. Te quedan 4 intentos." {
		t.Fatal(got)
	}
}

func TestValidAccountEmail(t *testing.T) {
	if !validAccountEmail("ana@geldflus.com") {
		t.Fatal("correo válido rechazado")
	}
	for _, bad := range []string{"", "ana", "ana@", "@geldflus.com", "ana@geldflus", "ana geld@flus.com"} {
		if validAccountEmail(bad) {
			t.Fatalf("correo inválido aceptado: %q", bad)
		}
	}
}
