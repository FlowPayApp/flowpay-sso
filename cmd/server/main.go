package main

import (
	"database/sql"
	"log"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/joho/godotenv/autoload"

	"github.com/flowpay/flowpay-sso/internal/config"
	"github.com/flowpay/flowpay-sso/internal/handler"
	"github.com/flowpay/flowpay-sso/internal/repo"
)

func main() {
	cfg := config.Load()
	if cfg.JWTSecret == "" {
		log.Fatal("FLOWPAY_JWT_SECRET es obligatorio (mín. 16 caracteres, compartido con flowpay-backend)")
	}

	db, err := sql.Open("mysql", cfg.DSN)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		log.Fatal("mysql ping:", err)
	}

	rp := repo.New(db)
	auth := handler.NewAuth(rp, []byte(cfg.JWTSecret), cfg.JWTTTL)

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173", "http://127.0.0.1:5173"},
		AllowMethods:     []string{"GET", "POST", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
		MaxAge:           12 * 3600,
	}))

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"service": "flowpay-sso", "status": "ok"})
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

	log.Printf("flowpay-sso en %s (POST /auth/login, /auth/register, /auth/bootstrap/platform-admin, /auth/company/users, /auth/platform/companies, /auth/platform/company-admins)", cfg.Addr)
	if err := r.Run(cfg.Addr); err != nil {
		log.Fatal(err)
	}
}
