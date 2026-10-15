package notify

import (
	"strings"
	"testing"
)

func TestLetterIsFormalAndEscaped(t *testing.T) {
	note := letter{
		Kicker:   "Acceso a su cuenta",
		Greeting: "Estimado <b>Ana</b>,",
		Lines:    []string{"Le escribimos para entregarle su clave.", "No reenvíe <b>este</b> mensaje."},
		Secret:   "clave<1>",
	}
	htmlBody, err := note.html()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(htmlBody, "<b>Ana</b>") || strings.Contains(htmlBody, "clave<1>") || strings.Contains(htmlBody, "<b>este</b>") {
		t.Fatal("el texto del usuario no debe interpretarse como HTML")
	}
	for _, want := range []string{"GeldFlus", "Equipo GeldFlus", "Saludos cordiales", "contacto@geldflus.com", "www.geldflus.com", "clave&lt;1&gt;", "Tenga en cuenta", "Acceso a su cuenta"} {
		if !strings.Contains(htmlBody, want) {
			t.Fatalf("falta %s", want)
		}
	}
	plain := note.plain()
	if !strings.Contains(plain, "Saludos cordiales,") || !strings.Contains(plain, "clave<1>") {
		t.Fatal("el texto plano no trae la firma o la clave")
	}
	raw := SMTP{From: "contacto@geldflus.com"}.writeMessage([]string{"a@b.c"}, "Clave", plain, htmlBody)
	text := string(raw)
	if !strings.Contains(text, "text/html") || strings.Contains(text, "image/png") {
		t.Fatal("el mensaje debe ir en HTML y sin logo")
	}
	for _, line := range strings.Split(text, "\n") {
		if len(line) > 998 {
			t.Fatalf("línea demasiado larga para SMTP: %d", len(line))
		}
	}
}
