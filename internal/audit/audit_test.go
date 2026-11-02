package audit

import (
	"context"
	"testing"
	"time"
)

func TestFinishTakesActorFromContext(t *testing.T) {
	ctx := WithActor(WithHTTP(context.Background(), "203.0.113.8", "TestAgent"), 7, 3, "admin")
	got := Finish(ctx, Event{Domain: DomainAuth, Action: ActionLogout, Summary: "Cerró sesión"})
	if got.Service != ServiceName || got.Outcome != OutcomeSuccess {
		t.Fatalf("service/outcome: %+v", got)
	}
	if got.ActorID != 7 || got.CompanyID != 3 || got.ActorRole != "admin" || got.IP != "203.0.113.8" {
		t.Fatalf("contexto: %+v", got)
	}
}

func TestFinishKeepsExplicitActor(t *testing.T) {
	ctx := WithActor(context.Background(), 1, 1, "member")
	got := Finish(ctx, Event{ActorID: 9, ActorRole: "platform_admin", CompanyID: 4})
	if got.ActorID != 9 || got.ActorRole != "platform_admin" || got.CompanyID != 4 {
		t.Fatalf("no debía pisar el actor explícito: %+v", got)
	}
}

func TestOnceCollapsesRepeats(t *testing.T) {
	key := "once-" + t.Name()
	if !Once(key, time.Minute) {
		t.Fatal("la primera vez debe pasar")
	}
	if Once(key, time.Minute) {
		t.Fatal("el reintento dentro de la ventana no debe pasar")
	}
	if !Once(key+"-otra", time.Minute) {
		t.Fatal("otra clave debe pasar")
	}
}

func TestMaskEmail(t *testing.T) {
	if got := MaskEmail("Ana@Empresa.CL"); got != "a***@empresa.cl" {
		t.Fatalf("mask: %s", got)
	}
	if got := MaskEmail("sin-arroba"); got != "***" {
		t.Fatalf("mask vacío: %s", got)
	}
}

func TestID(t *testing.T) {
	if ID(0) != "" || ID(42) != "42" {
		t.Fatal(ID(0), ID(42))
	}
}
