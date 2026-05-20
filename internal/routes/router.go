package routes

import (
	"net/http"

	"github.com/flowpay/flowpay-sso/internal/controller"
	"github.com/flowpay/flowpay-sso/internal/middleware"
	"github.com/gin-gonic/gin"
)

func Register(r *gin.Engine, auth *controller.AuthController, clients *controller.ClientsController, jwtSecret string) {
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"service": "flowpay-sso", "status": "ok"})
	})

	r.POST("/auth/register", auth.Register)
	r.POST("/auth/login", auth.Login)
	r.GET("/auth/me", auth.GetProfile)
	r.PATCH("/auth/me", auth.UpdateProfile)
	r.POST("/auth/password/first-change", auth.FirstPasswordChange)
	r.POST("/auth/bootstrap/platform-admin", auth.BootstrapPlatformAdmin)
	r.POST("/auth/company/users", auth.CreateCompanyUser)
	r.GET("/auth/platform/companies", auth.ListCompanies)
	r.POST("/auth/platform/companies", auth.CreateCompany)
	r.POST("/auth/platform/companies-with-admin", auth.CreateCompanyWithAdmin)
	r.PATCH("/auth/platform/companies/:id", auth.UpdateCompany)
	r.GET("/auth/platform/company-admins", auth.ListCompanyAdmins)
	r.POST("/auth/platform/company-admins", auth.CreateCompanyAdmin)
	r.PATCH("/auth/platform/company-admins/:user_id", auth.UpdateCompanyAdmin)
	r.POST("/auth/platform/company-admins/:user_id/reset-password", auth.ResetCompanyAdminPassword)

	api := r.Group("/api")
	api.Use(middleware.BearerJWT(jwtSecret))
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
