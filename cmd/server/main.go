package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/url"
	"strings"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/joho/godotenv/autoload"

	"github.com/flowpay/flowpay-sso/internal/config"
	"github.com/flowpay/flowpay-sso/internal/controller"
	"github.com/flowpay/flowpay-sso/internal/repository"
	"github.com/flowpay/flowpay-sso/internal/routes"
	"github.com/flowpay/flowpay-sso/internal/service"
)

func main() {
	cfg := config.Load()
	if cfg.JWTSecret == "" {
		log.Fatal("FLOWPAY_JWT_SECRET es obligatorio (mín. 16 caracteres, compartido con flowpay-backend)")
	}

	db, err := sql.Open("pgx", cfg.DSN)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		log.Fatal("postgres ping:", err)
	}

	repo := repository.New(db)
	auth := controller.NewAuthController(repo, []byte(cfg.JWTSecret), cfg.JWTTTL)
	clientSvc := service.NewClientsService(repo)
	clients := controller.NewClientsController(clientSvc)

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

	routes.Register(r, auth, clients, cfg.JWTSecret)

	printStartupStatus(db, cfg.Addr, cfg.DSN, cfg.JWTSecret)
	if err := r.Run(cfg.Addr); err != nil {
		log.Fatal(err)
	}
}

func printStartupStatus(db *sql.DB, addr, dsn, jwtSecret string) {
	const (
		reset  = "\033[0m"
		bold   = "\033[1m"
		cyan   = "\033[36m"
		green  = "\033[32m"
		yellow = "\033[33m"
	)
	ok := func(v string) string { return green + "OK" + reset + " " + v }
	warn := func(v string) string { return yellow + "WARN" + reset + " " + v }

	check := func(table string) bool {
		var exists bool
		err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=$1)`, table).Scan(&exists)
		return err == nil && exists
	}

	log.Println(cyan + "╔══════════════════════════════════════════════════════╗" + reset)
	log.Println(cyan + "║" + reset + " " + bold + "FlowPay SSO · Estado de inicio" + reset + "                  " + cyan + "║" + reset)
	log.Println(cyan + "╠══════════════════════════════════════════════════════╣" + reset)
	log.Printf(cyan+"║"+reset+" %s", ok("DB conectada"))
	log.Printf(cyan+"║"+reset+" %s", ok("DB destino: "+safeDSN(dsn)))
	log.Printf(cyan+"║"+reset+" %s", ok("HTTP listening en "+addr))
	log.Printf(cyan+"║"+reset+" %s", ok("Healthcheck: GET "+addr+"/health"))
	log.Printf(cyan+"║"+reset+" %s", fmt.Sprintf("%sAuth endpoints:%s /auth/login, /auth/register, /auth/me", bold, reset))
	log.Printf(cyan+"║"+reset+" %s", fmt.Sprintf("%sAdmin endpoints:%s /auth/platform/*", bold, reset))
	log.Printf(cyan+"║"+reset+" %s", fmt.Sprintf("%sClientes (JWT):%s GET/POST/PATCH/DELETE %s/api/clients*", bold, reset, addr))

	if strings.TrimSpace(jwtSecret) == "" {
		log.Printf(cyan+"║"+reset+" %s", warn("FLOWPAY_JWT_SECRET vacío"))
	} else {
		log.Printf(cyan+"║"+reset+" %s", ok("JWT secret cargado"))
	}

	required := []string{"users", "companies", "company_users"}
	var miss []string
	for _, t := range required {
		if !check(t) {
			miss = append(miss, t)
		}
	}
	if len(miss) == 0 {
		log.Printf(cyan+"║"+reset+" %s", ok("Tablas críticas en public: "+strings.Join(required, ", ")))
	} else {
		log.Printf(cyan+"║"+reset+" %s", warn("Faltan tablas: "+strings.Join(miss, ", ")))
	}
	log.Println(cyan + "╚══════════════════════════════════════════════════════╝" + reset)
}

func safeDSN(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(dsn inválido)"
	}
	if u.User != nil {
		user := u.User.Username()
		if user != "" {
			u.User = url.User(user)
		}
	}
	return u.Redacted()
}
