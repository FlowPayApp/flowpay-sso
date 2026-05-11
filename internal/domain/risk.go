package domain

// RiskLevel heurística por cobros vencidos sin pagar del cliente (alineado con flowpay-backend).
func RiskLevel(overdueCount int, overdueAmount float64) string {
	if overdueCount >= 2 || overdueAmount >= 500000 {
		return "high"
	}
	if overdueCount == 1 || overdueAmount >= 150000 {
		return "medium"
	}
	return "low"
}
