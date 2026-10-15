package notify

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"strings"
	"time"
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
	subject := "Nueva solicitud de cuenta: " + strings.NewReplacer("\r", "", "\n", "").Replace(n.CompanyName)
	note := letter{
		Kicker:   "Solicitud de cuenta",
		Greeting: "Estimado,",
		Lines: []string{
			"Alguien pidió crear una cuenta en GeldFlus. La empresa queda pendiente hasta que la active en el panel.",
			"Puede contactarlos y, cuando corresponda, habilitar el acceso.",
		},
		Rows: [][2]string{
			{"Empresa", n.CompanyName},
			{"Nombre", n.PersonName},
			{"Correo", n.Email},
			{"Teléfono", n.Phone},
			{"Plan", n.PlanLabel},
		},
	}
	if err := s.send(to, subject, note); err != nil {
		log.Printf("[FlowPay signup] no se pudo enviar el aviso: %v", err)
		return err
	}
	log.Printf("[FlowPay signup] aviso enviado a %s", strings.Join(to, ", "))
	return nil
}

func (n SignupNotice) summary() string {
	return fmt.Sprintf("empresa=%s nombre=%s correo=%s telefono=%s plan=%s", n.CompanyName, n.PersonName, n.Email, n.Phone, n.PlanLabel)
}

// SendTemporaryPassword entrega la clave una sola vez. Si no hay SMTP, falla: no hay otro canal.
func (s SMTP) SendTemporaryPassword(to, name, password string) error {
	to = strings.TrimSpace(strings.ToLower(to))
	if to == "" {
		return fmt.Errorf("sin destinatario")
	}
	if !s.enabled() {
		log.Printf("[FlowPay] no se envió la clave temporal: SMTP sin configurar")
		return fmt.Errorf("smtp sin configurar")
	}
	who := strings.TrimSpace(name)
	greeting := "Estimado,"
	if who != "" && who != to {
		greeting = "Estimado " + who + ","
	}
	err := s.send([]string{to}, "Su clave temporal de acceso a GeldFlus", letter{
		Kicker:   "Acceso a su cuenta",
		Greeting: greeting,
		Lines: []string{
			"Le escribimos para entregarle su clave temporal de acceso a GeldFlus.",
			"Al ingresar, reemplácela por una contraseña propia.",
			"No reenvíe este mensaje.",
		},
		Secret: password,
	})
	if err != nil {
		log.Printf("[FlowPay] no se pudo enviar la clave temporal a %s: %v", to, err)
	}
	return err
}

// SendSecurity avisa a los super admin. No incluye contraseñas ni cuerpos de mensajes.
func (s SMTP) SendSecurity(to []string, subject, body string) error {
	to = clean(to)
	if len(to) == 0 || !s.enabled() {
		log.Printf("[FlowPay security] %s", strings.ReplaceAll(subject, "\n", " "))
		return nil
	}
	if err := s.send(to, subject, letter{
		Kicker:   "Aviso de seguridad",
		Greeting: "Estimado,",
		Lines:    []string{body},
	}); err != nil {
		log.Printf("[FlowPay security] no se pudo avisar: %v", err)
		return err
	}
	return nil
}

const smtpTimeout = 12 * time.Second

func (s SMTP) send(to []string, subject string, note letter) error {
	htmlBody, err := note.html()
	if err != nil {
		return err
	}
	host := strings.TrimSpace(s.Host)
	port := strings.TrimSpace(s.Port)
	if port == "" {
		port = "587"
	}
	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: smtpTimeout}
	var conn net.Conn
	if port == "465" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: host})
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("conectar %s: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(smtpTimeout))

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("cliente smtp: %w", err)
	}
	defer client.Close()
	if port != "465" {
		if err := client.StartTLS(&tls.Config{ServerName: host}); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	}
	if err := client.Auth(smtp.PlainAuth("", s.Username, s.Password, host)); err != nil {
		return fmt.Errorf("auth smtp: %w", err)
	}
	from := strings.TrimSpace(s.From)
	if err := client.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(s.writeMessage(to, subject, note.plain(), htmlBody)); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
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
