package controller

// Tipos solo para Swagger. El bind JSON sigue usando las structs internas de cada handler.

type ErrorBody struct {
	Error string `json:"error" example:"json inválido"`
}

type MessageBody struct {
	Error                  string `json:"error,omitempty"`
	RequiresPasswordChange bool   `json:"requires_password_change,omitempty"`
	Message                string `json:"message,omitempty"`
}

type OKBody struct {
	OK bool `json:"ok" example:"true"`
}

type OKSignedOutBody struct {
	OK        bool `json:"ok"`
	SignedOut bool `json:"signed_out"`
}

type HealthBody struct {
	Service string `json:"service" example:"flowpay-sso"`
	Status  string `json:"status" example:"ok"`
}

type TokenBody struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type" example:"Bearer"`
	ExpiresIn   int    `json:"expires_in" example:"900"`
}

type LoginResult struct {
	AccessToken string `json:"access_token,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	ExpiresIn   int    `json:"expires_in,omitempty"`
	MFARequired bool   `json:"mfa_required,omitempty"`
	MFASetup    bool   `json:"mfa_setup,omitempty"`
	MFAToken    string `json:"mfa_token,omitempty"`
	Secret      string `json:"secret,omitempty"`
	OTPAuthURL  string `json:"otpauth_url,omitempty"`
}

type RegisterAcceptedBody struct {
	Pending bool   `json:"pending" example:"true"`
	Message string `json:"message"`
}

type RegisterRequest struct {
	Email       string `json:"email" example:"ana@distribuidora.cl"`
	Password    string `json:"password"`
	Name        string `json:"name" example:"Ana Pérez"`
	CompanyName string `json:"company_name" example:"Distribuidora Sur"`
	Phone       string `json:"phone" example:"+56912345678"`
	Plan        string `json:"plan" example:"crecimiento"`
}

type LoginRequest struct {
	Email    string `json:"email" example:"ana@distribuidora.cl"`
	Password string `json:"password"`
}

type MFARequest struct {
	MFAToken string `json:"mfa_token"`
	Code     string `json:"code" example:"123456"`
}

type FirstPasswordChangeRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	NewPassword string `json:"new_password"`
}

type UpdateOwnProfileRequest struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password,omitempty"`
}

type ProfileBody struct {
	UserID    int64  `json:"user_id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	Role      string `json:"role" example:"admin"`
	CompanyID int64  `json:"company_id"`
	IsActive  bool   `json:"is_active"`
}

type BootstrapPlatformAdminRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type BootstrapPlatformAdminBody struct {
	UserID int64  `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role" example:"platform_admin"`
}

type CreateCompanyRequest struct {
	Name string `json:"name"`
}

type CreateCompanyBody struct {
	CompanyID int64 `json:"company_id"`
}

type CreateCompanyWithAdminRequest struct {
	CompanyName   string `json:"company_name"`
	AdminEmail    string `json:"admin_email"`
	AdminPassword string `json:"admin_password"`
	AdminName     string `json:"admin_name"`
}

type CreateCompanyWithAdminBody struct {
	CompanyID   int64 `json:"company_id"`
	AdminUserID int64 `json:"admin_user_id,omitempty"`
}

type UpdateCompanyRequest struct {
	Name                      *string  `json:"name"`
	IsActive                  *bool    `json:"is_active"`
	RequestedPlan             *string  `json:"requested_plan"`
	PriceCLPOverride          *int     `json:"price_clp_override"`
	CommissionPercentOverride *float64 `json:"commission_percent_override"`
	ClearPriceOverride        *bool    `json:"clear_price_override"`
	ClearCommissionOverride   *bool    `json:"clear_commission_override"`
	AllowEmail                *bool    `json:"allow_email"`
	AllowWhatsApp             *bool    `json:"allow_whatsapp"`
}

type CompanyActivatedBody struct {
	OK           bool   `json:"ok"`
	Email        string `json:"email,omitempty"`
	PasswordSent bool   `json:"password_sent,omitempty"`
}

type UpdatePlanRequest struct {
	Label             string   `json:"label"`
	Detail            string   `json:"detail"`
	PriceCLP          int      `json:"price_clp"`
	Features          []string `json:"features"`
	Highlight         bool     `json:"highlight"`
	CommissionPercent float64  `json:"commission_percent"`
}

type CreateCompanyUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
	Role     string `json:"role" example:"member"`
}

type CreateCompanyUserBody struct {
	UserID    int64  `json:"user_id"`
	CompanyID int64  `json:"company_id"`
	Role      string `json:"role"`
}

type UpdateCompanyUserRequest struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Role     string `json:"role"`
	IsActive *bool  `json:"is_active"`
}

type CreateCompanyAdminRequest struct {
	CompanyID int64  `json:"company_id"`
	Email     string `json:"email"`
	Password  string `json:"password,omitempty"`
	Name      string `json:"name"`
}

type TempPasswordCreatedBody struct {
	UserID             int64  `json:"user_id,omitempty"`
	CompanyID          int64  `json:"company_id,omitempty"`
	Role               string `json:"role,omitempty"`
	PasswordSent       bool   `json:"password_sent"`
	MustChangePassword bool   `json:"must_change_password"`
}

type CreatePlatformAdminRequest struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

type UpdatePlatformAdminRequest struct {
	IsActive *bool `json:"is_active"`
}

type UpdateCompanyAdminRequest struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	IsActive *bool  `json:"is_active"`
}

type CreateClientRequest struct {
	Name         string `json:"name"`
	Email        string `json:"email"`
	Phone        string `json:"phone"`
	Address      string `json:"address"`
	ClientCode   string `json:"client_code"`
	BranchName   string `json:"branch_name"`
	PaymentTerms string `json:"payment_terms"`
	AssignedTo   *int64 `json:"assigned_to"`
}

type CreatedIDBody struct {
	ID int64 `json:"id"`
}

type PatchClientRequest struct {
	IsActive        *bool   `json:"is_active"`
	FollowupChannel *string `json:"followup_channel"`
	Name            *string `json:"name"`
	Email           *string `json:"email"`
	Phone           *string `json:"phone"`
	Address         *string `json:"address"`
	ClientCode      *string `json:"client_code"`
	BranchName      *string `json:"branch_name"`
	PaymentTerms    *string `json:"payment_terms"`
	AssignedTo      *int64  `json:"assigned_to"`
}

type ImportDistributorRowsRequest struct {
	Rows     [][]string `json:"rows"`
	Filename *string    `json:"filename"`
}
