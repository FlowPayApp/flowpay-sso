package audit

const (
	ActionLoginSucceeded         = "login_succeeded"
	ActionLoginFailed            = "login_failed"
	ActionAccessBlocked          = "access_blocked"
	ActionBootstrapRejected      = "bootstrap_rejected"
	ActionMFAFailed              = "mfa_failed"
	ActionMFAEnrolled            = "mfa_enrolled"
	ActionMFAReset               = "mfa_reset"
	ActionRefreshReused          = "refresh_reused"
	ActionLogout                 = "logout"
	ActionPasswordChanged        = "password_changed"
	ActionPasswordReset          = "password_reset"
	ActionUserCreated            = "user_created"
	ActionRoleChanged            = "role_changed"
	ActionUserActivated          = "user_activated"
	ActionUserDeactivated        = "user_deactivated"
	ActionUserRemoved            = "user_removed"
	ActionRegister               = "register"
	ActionBootstrapPlatformAdmin = "bootstrap_platform_admin"
	ActionProfileUpdated         = "profile_updated"

	ActionCompanyCreated = "company_created"
	ActionCompanyUpdated = "company_updated"
	ActionCompanyDeleted = "company_deleted"
	ActionPlanUpdated    = "plan_updated"

	ActionClientCreated   = "client_created"
	ActionClientUpdated   = "client_updated"
	ActionClientDeleted   = "client_deleted"
	ActionClientsImported = "clients_imported"
)

// DomainInfo es un cajón de la auditoría: el lugar donde se busca.
type DomainInfo struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Service string `json:"service"`
	Hint    string `json:"hint"`
}

// Domains es el mapa para la pantalla de plataforma. El orden es el de la barra.
func Domains() []DomainInfo {
	return []DomainInfo{
		{ID: DomainAuth, Label: "Acceso", Service: "sso", Hint: "Ingresos, claves, roles y sesiones"},
		{ID: DomainTenant, Label: "Empresas", Service: "sso", Hint: "Altas, planes y bajas de empresas"},
		{ID: DomainClient, Label: "Clientes", Service: "sso", Hint: "Ficha, importación y exportación"},
		{ID: DomainCharge, Label: "Cobros", Service: "backend", Hint: "Altas, cambios y cobros marcados"},
		{ID: DomainPayment, Label: "Pagos", Service: "payments", Hint: "Enlaces, pasarelas y webhooks"},
		{ID: DomainCredential, Label: "Credenciales", Service: "backend", Hint: "Medios de pago, correo y WhatsApp"},
		{ID: DomainMessage, Label: "Avisos", Service: "backend", Hint: "Recordatorios y mensajes"},
	}
}

func DomainLabel(id string) string {
	for _, d := range Domains() {
		if d.ID == id {
			return d.Label
		}
	}
	return id
}
