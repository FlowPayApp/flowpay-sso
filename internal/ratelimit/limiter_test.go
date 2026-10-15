package ratelimit

import (
	"testing"
	"time"
)

func TestHitTripsOnce(t *testing.T) {
	l := New()
	now := time.Now()
	if blocked, tripped := l.Hit("a", 3, time.Minute, now); blocked || tripped {
		t.Fatalf("primer intento no debe topar")
	}
	l.Hit("a", 3, time.Minute, now)
	blocked, tripped := l.Hit("a", 3, time.Minute, now)
	if !blocked || !tripped {
		t.Fatalf("el tercero debe topar una sola vez")
	}
	blocked, tripped = l.Hit("a", 3, time.Minute, now)
	if !blocked || tripped {
		t.Fatalf("el cuarto sigue bloqueado pero no vuelve a avisar")
	}
	if !l.Blocked("a", 3, time.Minute, now) {
		t.Fatal("debería seguir bloqueado")
	}
	if l.Blocked("a", 3, time.Minute, now.Add(2*time.Minute)) {
		t.Fatal("la ventana debe expirar")
	}
}
