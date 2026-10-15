package totp

import "testing"

func TestRFC4226Vector(t *testing.T) {
	// RFC 6238, secreto ASCII, tiempo 59 → contador 1 → 287082.
	got := HOTP([]byte("12345678901234567890"), 1)
	if got != "287082" {
		t.Fatalf("got %s", got)
	}
}
