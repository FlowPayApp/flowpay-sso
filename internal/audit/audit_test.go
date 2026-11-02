package audit

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestScrubHidesSecretValues(t *testing.T) {
	got := Scrub("auth smtp: 535 password=supersecret extra")
	if strings.Contains(got, "supersecret") || !strings.Contains(got, "auth smtp") {
		t.Fatal(got)
	}
	if Cause(errors.New("conectar mail.ejemplo: timeout")) != "conectar mail.ejemplo: timeout" {
		t.Fatal(Cause(errors.New("conectar mail.ejemplo: timeout")))
	}
}

func TestFinishTakesActorFromContext(t *testing.T) {
	ctx := WithActor(WithHTTP(context.Background(), "203.0.113.8", "TestAgent", ""), 7, 3, "admin")
	got := Finish(ctx, Event{Domain: DomainAuth, Action: ActionLogout, Summary: "Cerró sesión"})
	if got.Service != ServiceName || got.Outcome != OutcomeSuccess {
		t.Fatalf("service/outcome: %+v", got)
	}
	if got.ActorID != 7 || got.CompanyID != 3 || got.ActorRole != "admin" || got.IP != "203.0.113.8" || got.UserAgent != "TestAgent" {
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

func TestPickIPUsesBrowserWhenProxyConnects(t *testing.T) {
	if got := pickIP("127.0.0.1", "203.0.113.8", "10.0.0.1", ""); got != "203.0.113.8" {
		t.Fatalf("proxy local: %s", got)
	}
	if got := pickIP("10.1.2.3", "", "198.51.100.20, 10.1.2.3", ""); got != "198.51.100.20" {
		t.Fatalf("forwarded: %s", got)
	}
	if got := pickIP("100.64.0.5", "203.0.113.8", "", ""); got != "203.0.113.8" {
		t.Fatalf("balanceador: %s", got)
	}
}

func TestPreferHintKeepsBraveOverChromeAgent(t *testing.T) {
	brave := `"Chromium";v="156", "Brave";v="156", "Not)A;Brand";v="24"`
	chrome := `"Chromium";v="156", "Google Chrome";v="156", "Not)A;Brand";v="24"`
	if got := preferHint(brave, chrome); got != brave {
		t.Fatalf("marca: %s", got)
	}
	if specificBrand(chrome) {
		t.Fatal("Chrome no trae una marca propia")
	}
}

func TestChooseIPUsesVisitorWhenEdgeMatches(t *testing.T) {
	t.Setenv("FLOWPAY_EDGE_SECRET", "borde-local")
	if got := chooseIP("56.125.194.93", "190.45.10.2", "", "", "borde-local"); got != "190.45.10.2" {
		t.Fatalf("visitante: %s", got)
	}
	if got := chooseIP("56.125.194.93", "190.45.10.2", "", "", "otro"); got != "56.125.194.93" {
		t.Fatalf("secreto ajeno: %s", got)
	}
	t.Setenv("FLOWPAY_EDGE_SECRET", "")
	if got := chooseIP("56.125.194.93", "190.45.10.2", "", "", "borde-local"); got != "56.125.194.93" {
		t.Fatalf("sin secreto: %s", got)
	}
}

func TestPickIPIgnoresSpoofedHeaderFromPublicPeer(t *testing.T) {
	if got := pickIP("203.0.113.9", "198.51.100.1", "", ""); got != "203.0.113.9" {
		t.Fatalf("peer público: %s", got)
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
