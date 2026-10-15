package notify

import (
	"bytes"
	"encoding/base64"
	"html/template"
	"mime"
	"net/mail"
	"strings"
)

const (
	brandColor = "#0f6e6b"
	siteURL    = "https://www.geldflus.com"
)

type letter struct {
	Kicker   string
	Greeting string
	Lines    []string
	Rows     [][2]string
	Secret   string
}

func (n letter) Lead() string {
	if len(n.Lines) == 0 {
		return ""
	}
	return n.Lines[0]
}

func (n letter) Notes() []string {
	if len(n.Lines) < 2 {
		return nil
	}
	return n.Lines[1:]
}

func (s SMTP) fromHeader() string {
	addr := strings.TrimSpace(s.From)
	return (&mail.Address{Name: "GeldFlus", Address: addr}).String()
}

func (s SMTP) writeMessage(to []string, subject, plain, htmlBody string) []byte {
	subject = mime.QEncoding.Encode("utf-8", strings.NewReplacer("\r", "", "\n", "").Replace(subject))
	alternative := "geldflus-alternative"
	var buf bytes.Buffer
	buf.WriteString("From: " + s.fromHeader() + "\r\n")
	buf.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	buf.WriteString("Subject: " + subject + "\r\n")
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString(`Content-Type: multipart/alternative; boundary="` + alternative + `"` + "\r\n")
	buf.WriteString("\r\n")
	writeBase64Part(&buf, alternative, "text/plain; charset=UTF-8", []byte(plain))
	writeBase64Part(&buf, alternative, "text/html; charset=UTF-8", []byte(htmlBody))
	buf.WriteString("--" + alternative + "--\r\n")
	return buf.Bytes()
}

func writeBase64Part(buf *bytes.Buffer, boundary, contentType string, body []byte) {
	buf.WriteString("--" + boundary + "\r\n")
	buf.WriteString("Content-Type: " + contentType + "\r\n")
	buf.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	writeWrappedBase64(buf, body)
}

func writeWrappedBase64(buf *bytes.Buffer, body []byte) {
	encoded := base64.StdEncoding.EncodeToString(body)
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		buf.WriteString(encoded[i:end] + "\r\n")
	}
	buf.WriteString("\r\n")
}

func (n letter) plain() string {
	var lines []string
	lines = append(lines, "GeldFlus", "")
	if n.Greeting != "" {
		lines = append(lines, n.Greeting, "")
	}
	lines = append(lines, n.Lines...)
	if len(n.Rows) > 0 {
		lines = append(lines, "")
		for _, row := range n.Rows {
			lines = append(lines, row[0]+": "+row[1])
		}
	}
	if n.Secret != "" {
		lines = append(lines, "", "Clave temporal: "+n.Secret)
	}
	lines = append(lines,
		"",
		"Saludos cordiales,",
		"Equipo GeldFlus",
		"Plataforma de cobranza",
		"contacto@geldflus.com",
		"www.geldflus.com",
	)
	return strings.Join(lines, "\r\n")
}

func (n letter) html() (string, error) {
	var buf bytes.Buffer
	err := letterTmpl.Execute(&buf, n)
	return buf.String(), err
}

var letterTmpl = template.Must(template.New("letter").Funcs(template.FuncMap{
	"add": func(a, b int) int { return a + b },
}).Parse(`<!DOCTYPE html>
<html lang="es">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#efeae3;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#efeae3;">
<tr><td align="center" style="padding:28px 12px;">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="width:600px;max-width:600px;background:#ffffff;border-radius:18px;overflow:hidden;">
<tr><td bgcolor="` + brandColor + `" style="background:` + brandColor + `;padding:26px 32px;">
<p style="margin:0;font-family:Georgia,'Times New Roman',serif;font-size:22px;letter-spacing:0.04em;color:#ffffff;">GeldFlus</p>
</td></tr>
<tr><td style="padding:34px 36px 8px;font-family:Arial,Helvetica,sans-serif;color:#1c1917;">
{{if .Kicker}}<p style="margin:0 0 8px;font-size:11px;letter-spacing:0.16em;text-transform:uppercase;color:` + brandColor + `;">{{.Kicker}}</p>{{end}}
{{if .Greeting}}<p style="margin:0;font-family:Georgia,'Times New Roman',serif;font-size:28px;line-height:1.25;color:#1c1917;">{{.Greeting}}</p>{{end}}
<table role="presentation" cellpadding="0" cellspacing="0" style="margin:16px 0 0;"><tr><td style="width:42px;height:3px;background:` + brandColor + `;font-size:0;line-height:0;">&nbsp;</td></tr></table>
{{if .Lead}}<p style="margin:22px 0 0;font-size:16px;line-height:1.7;color:#292524;">{{.Lead}}</p>{{end}}
{{if .Secret}}
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:22px 0 0;">
<tr><td align="center" style="background:#f3faf9;border:1px solid #d5ebe8;border-radius:16px;padding:22px 18px;">
<p style="margin:0;font-size:11px;letter-spacing:0.14em;text-transform:uppercase;color:` + brandColor + `;">Clave temporal</p>
<p style="margin:12px 0 0;padding:12px 16px;background:#ffffff;border:1px dashed #b7ddd9;border-radius:10px;font-family:Consolas,'Courier New',monospace;font-size:22px;letter-spacing:0.08em;line-height:1.4;color:#1c1917;">{{.Secret}}</p>
<p style="margin:12px 0 0;font-size:12px;line-height:1.5;color:#6b645c;">Cópiela tal cual. Sirve solo para el primer ingreso.</p>
</td></tr>
</table>
{{end}}
{{if .Notes}}
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:18px 0 0;background:#f7f4ef;border-radius:14px;">
<tr><td style="padding:6px 18px 8px;">
<p style="margin:12px 0 4px;font-size:11px;letter-spacing:0.14em;text-transform:uppercase;color:#6b645c;">Tenga en cuenta</p>
{{range $i, $line := .Notes}}
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 8px;">
<tr>
<td width="28" valign="top" style="width:28px;padding-top:2px;">
<table role="presentation" cellpadding="0" cellspacing="0"><tr>
<td width="22" height="22" align="center" valign="middle" bgcolor="` + brandColor + `" style="width:22px;height:22px;background:` + brandColor + `;border-radius:11px;font-size:12px;font-weight:700;color:#ffffff;">{{add $i 1}}</td>
</tr></table>
</td>
<td valign="middle" style="padding:0 0 0 10px;font-size:14px;line-height:1.55;color:#3f3a36;">{{$line}}</td>
</tr>
</table>
{{end}}
</td></tr>
</table>
{{end}}
{{if .Rows}}
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:20px 0 0;border:1px solid #e7e1d8;border-radius:14px;">
{{range .Rows}}<tr>
<td style="padding:12px 16px;border-bottom:1px solid #efeae3;">
<p style="margin:0;font-size:11px;letter-spacing:0.12em;text-transform:uppercase;color:#6b645c;">{{index . 0}}</p>
<p style="margin:4px 0 0;font-size:15px;line-height:1.4;font-weight:700;color:#1c1917;">{{index . 1}}</p>
</td>
</tr>{{end}}
</table>
{{end}}
</td></tr>
<tr><td style="padding:28px 36px 32px;font-family:Georgia,'Times New Roman',serif;">
<p style="margin:0;border-top:1px solid #e7e1d8;padding-top:22px;font-size:16px;font-style:italic;color:#1c1917;">Saludos cordiales,</p>
<p style="margin:12px 0 0;font-size:18px;color:#1c1917;">Equipo GeldFlus</p>
<p style="margin:8px 0 0;font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:1.6;color:#8a837b;">
Plataforma de cobranza
<span style="color:#d6d0c8;">&nbsp;&middot;&nbsp;</span>
<a href="mailto:contacto@geldflus.com" style="color:#8a837b;text-decoration:none;">contacto@geldflus.com</a>
<span style="color:#d6d0c8;">&nbsp;&middot;&nbsp;</span>
<a href="` + siteURL + `" style="color:#8a837b;text-decoration:none;">www.geldflus.com</a>
</p>
</td></tr>
<tr><td style="background:` + brandColor + `;padding:14px 32px;font-family:Arial,Helvetica,sans-serif;font-size:12px;line-height:1.5;color:#e7f3f2;">
GeldFlus · Mensaje confidencial. Si usted no esperaba este correo, puede ignorarlo.
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>`))
