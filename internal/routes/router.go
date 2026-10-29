package routes

import (
	"net/http"

	"github.com/flowpay/flowpay-sso/internal/controller"
	"github.com/flowpay/flowpay-sso/internal/middleware"
	"github.com/gin-gonic/gin"
)

func Register(r *gin.Engine, auth *controller.AuthController, clients *controller.ClientsController, jwtSecret string) {
	r.GET("/health", Health)
	r.GET("/auth/plans", auth.ListSignupPlans)
	r.PATCH("/auth/platform/plans/:id", auth.UpdateSignupPlan)
	r.POST("/auth/register", auth.Register)
	r.POST("/auth/login", auth.Login)
	r.POST("/auth/login/mfa", auth.LoginMFA)
	r.POST("/api/auth/refresh", auth.Refresh)
	r.POST("/api/auth/logout", auth.Logout)
	r.GET("/auth/me", auth.GetProfile)
	r.PATCH("/auth/me", auth.UpdateProfile)
	r.POST("/auth/password/first-change", auth.FirstPasswordChange)
	r.POST("/auth/bootstrap/platform-admin", auth.BootstrapPlatformAdmin)
	r.POST("/auth/company/users", auth.CreateCompanyUser)
	r.GET("/auth/company/users", auth.ListCompanyUsers)
	r.PATCH("/auth/company/users/:user_id", auth.UpdateCompanyUser)
	r.DELETE("/auth/company/users/:user_id", auth.DeleteCompanyUser)
	r.GET("/auth/platform/companies", auth.ListCompanies)
	r.POST("/auth/platform/companies", auth.CreateCompany)
	r.POST("/auth/platform/companies-with-admin", auth.CreateCompanyWithAdmin)
	r.PATCH("/auth/platform/companies/:id", auth.UpdateCompany)
	r.DELETE("/auth/platform/companies/:id", auth.DeleteCompany)
	r.GET("/auth/platform/admins", auth.ListPlatformAdmins)
	r.POST("/auth/platform/admins", auth.CreatePlatformAdmin)
	r.PATCH("/auth/platform/admins/:user_id", auth.UpdatePlatformAdmin)
	r.DELETE("/auth/platform/admins/:user_id", auth.DeletePlatformAdmin)
	r.GET("/auth/platform/company-admins", auth.ListCompanyAdmins)
	r.POST("/auth/platform/company-admins", auth.CreateCompanyAdmin)
	r.PATCH("/auth/platform/company-admins/:user_id", auth.UpdateCompanyAdmin)
	r.POST("/auth/platform/company-admins/:user_id/reset-password", auth.ResetCompanyAdminPassword)
	r.POST("/auth/platform/admins/:user_id/reset-mfa", auth.ResetPlatformMFA)
	r.DELETE("/auth/platform/company-admins/:user_id", auth.DeleteCompanyAdmin)

	api := r.Group("/api")
	api.Use(middleware.BearerJWT(jwtSecret, auth.TokenRevoked))
	{
		api.GET("/clients", clients.ListClients)
		api.POST("/clients", clients.CreateClient)
		api.PATCH("/clients/:id", clients.PatchClient)
		api.POST("/clients/import-distributor-rows", clients.ImportDistributorRows)
		api.GET("/clients/import-batches", clients.ListImportBatches)
		api.GET("/clients/import-batches/:id", clients.GetImportBatch)
		api.GET("/clients/:id", clients.GetClient)
		api.DELETE("/clients/:id", clients.DeleteClient)
	}
}

// Health godoc
// @Summary Estado del servicio
// @Tags Salud
// @Produce json
// @Success 200 {object} controller.HealthBody
// @Router /health [get]
func Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"service": "flowpay-sso", "status": "ok"})
}
