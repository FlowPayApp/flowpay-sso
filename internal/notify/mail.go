package notify

import (
	"fmt"
	"log"
	"net/smtp"
	"strings"
)

// SMTP envío simple por STARTTLS, puerto 587.
type SMTP struct {
	Host     string
	Port     string
	Username string
	Password string
	From     string
}

func (s SMTP) enabled() bool {
	return strings.TrimSpace(s.Host) != "" && strings.TrimSpace(s.Username) != "" && strings.TrimSpace(s.Password) != "" && strings.TrimSpace(s.From) != ""
}

// SignupNotice datos para contactar a quien pidió una cuenta.
type SignupNotice struct {
	CompanyName string
	PersonName  string
	Email       string
	Phone       string
	PlanLabel   string
}

// SendSignup avisa a los super admin. Si no hay SMTP, lo deja en el log y no falla el registro.
func (s SMTP) SendSignup(to []string, n SignupNotice) error {
	to = clean(to)
	if len(to) == 0 {
		log.Printf("[FlowPay signup] sin destinatario super admin; %s", n.summary())
		return nil
	}
	if !s.enabled() {
		log.Printf("[FlowPay signup] sin SMTP; %s", n.summary())
		return nil
	}
	port := strings.TrimSpace(s.Port)
	if port == "" {
		port = "587"
	}
	body := strings.Join([]string{
		"Alguien pidió crear una cuenta en FlowPay. La empresa queda pendiente hasta que la actives.",
		"",
		"Empresa: " + n.CompanyName,
		"Nombre: " + n.PersonName,
		"Correo: " + n.Email,
		"Teléfono: " + n.Phone,
		"Plan: " + n.PlanLabel,
		"",
		"Puedes contactarlos y, cuando corresponda, activar la empresa en el panel.",
	}, "\r\n")
	subject := "Nueva solicitud de cuenta: " + strings.NewReplacer("\r", "", "\n", "").Replace(n.CompanyName)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		strings.TrimSpace(s.From), strings.Join(to, ", "), subject, body)
	addr := strings.TrimSpace(s.Host) + ":" + port
	auth := smtp.PlainAuth("", s.Username, s.Password, s.Host)
	if err := smtp.SendMail(addr, auth, strings.TrimSpace(s.From), to, []byte(msg)); err != nil {
		log.Printf("[FlowPay signup] no se pudo enviar el aviso: %v", err)
		return err
	}
	log.Printf("[FlowPay signup] aviso enviado a %s", strings.Join(to, ", "))
	return nil
}

func (n SignupNotice) summary() string {
	return fmt.Sprintf("empresa=%s nombre=%s correo=%s telefono=%s plan=%s", n.CompanyName, n.PersonName, n.Email, n.Phone, n.PlanLabel)
}

func clean(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range in {
		email := strings.TrimSpace(strings.ToLower(raw))
		if email == "" || seen[email] {
			continue
		}
		seen[email] = true
		out = append(out, email)
	}
	return out
}
