package signup

import (
	"strconv"
	"strings"
)

// Plan es la oferta que ve quien pide una cuenta y la que edita el super admin.
type Plan struct {
	ID                string   `json:"id"`
	Label             string   `json:"label"`
	Detail            string   `json:"detail"`
	Price             string   `json:"price"`
	Period            string   `json:"period"`
	Features          []string `json:"features"`
	Highlight         bool     `json:"highlight"`
	PriceCLP          int      `json:"price_clp"`
	CommissionPercent float64  `json:"commission_percent"`
}

// FormatCLP formatea un monto en pesos chilenos, por ejemplo 39000 → $39.000.
func FormatCLP(n int) string {
	neg := n < 0
	if neg {
		n = -n
	}
	s := strconv.Itoa(n)
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte('.')
		}
		b.WriteRune(r)
	}
	if neg {
		return "-$" + b.String()
	}
	return "$" + b.String()
}

// Plans opciones del registro público. Valores de referencia hasta definir la tabla comercial.
var Plans = []Plan{
	{
		ID:       "esencial",
		Label:    "Esencial",
		Detail:   "Para una operación chica que hoy cobra a mano.",
		Price:    "$39.000",
		PriceCLP: 39000,
		Period:   "mes",
		Features: []string{
			"Hasta 25 sucursales",
			"Recordatorios por correo y WhatsApp",
			"Enlace de pago con Webpay",
			"1 administrador",
		},
	},
	{
		ID:        "crecimiento",
		Label:     "Crecimiento",
		Detail:    "Para quien ya recorre varias sucursales y necesita equipo.",
		Price:     "$89.000",
		PriceCLP:  89000,
		Period:    "mes",
		Highlight: true,
		Features: []string{
			"Hasta 120 sucursales",
			"Todo lo de Esencial",
			"Cobradores en el equipo",
			"Carga de sucursales desde Excel",
		},
	},
	{
		ID:       "empresa",
		Label:    "Empresa",
		Detail:   "Para una red grande, con puesta en marcha acompañada.",
		Price:    "$169.000",
		PriceCLP: 169000,
		Period:   "mes",
		Features: []string{
			"Sucursales sin tope",
			"Todo lo de Crecimiento",
			"Varios administradores",
			"Acompañamiento en la carga inicial",
		},
	},
}

// Find devuelve el plan si el id es uno de los publicados.
func Find(id string) (Plan, bool) {
	for _, p := range Plans {
		if p.ID == id {
			return p, true
		}
	}
	return Plan{}, false
}
