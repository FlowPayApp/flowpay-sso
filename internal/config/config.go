package config

import (
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Addr              string
	DSN               string
	JWTSecret         string
	JWTTTL            time.Duration
	RefreshIdle       time.Duration
	RefreshAbsolute   time.Duration
	SMTPHost          string
	SMTPPort          string
	SMTPUser          string
	SMTPPassword      string
	SMTPFrom          string
	SignupNotifyEmail string
}

func Load() Config {
	_ = godotenv.Load()
	addr := listenAddr("FLOWPAY_SSO_ADDR", ":9090")
	dsn := os.Getenv("FLOWPAY_SSO_DSN")
	if dsn == "" {
		dsn = os.Getenv("FLOWPAY_DSN")
	}
	if dsn == "" {
		dsn = "postgres://flowpay:flowpay@127.0.0.1:5432/flowpay?sslmode=disable"
	}
	secret := strings.TrimSpace(os.Getenv("FLOWPAY_JWT_SECRET"))
	access := durationEnv("FLOWPAY_ACCESS_TTL", 15*time.Minute)
	idle := durationEnv("FLOWPAY_REFRESH_IDLE", 2*time.Hour)
	absolute := durationEnv("FLOWPAY_REFRESH_ABSOLUTE", 12*time.Hour)
	return Config{
		Addr:              addr,
		DSN:               dsn,
		JWTSecret:         secret,
		JWTTTL:            access,
		RefreshIdle:       idle,
		RefreshAbsolute:   absolute,
		SMTPHost:          os.Getenv("FLOWPAY_SMTP_HOST"),
		SMTPPort:          os.Getenv("FLOWPAY_SMTP_PORT"),
		SMTPUser:          os.Getenv("FLOWPAY_SMTP_USER"),
		SMTPPassword:      os.Getenv("FLOWPAY_SMTP_PASSWORD"),
		SMTPFrom:          os.Getenv("FLOWPAY_SMTP_FROM"),
		SignupNotifyEmail: os.Getenv("FLOWPAY_SIGNUP_NOTIFY_EMAIL"),
	}
}

func durationEnv(key string, fallback time.Duration) time.Duration {
	s := strings.TrimSpace(os.Getenv(key))
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

// Production es FLOWPAY_ENV=production o un despliegue que define PORT.
func Production() bool {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("FLOWPAY_ENV")), "production") {
		return true
	}
	return strings.TrimSpace(os.Getenv("PORT")) != ""
}

func listenAddr(primaryKey, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(primaryKey)); v != "" {
		return v
	}
	if p := strings.TrimSpace(os.Getenv("PORT")); p != "" {
		if strings.HasPrefix(p, ":") {
			return p
		}
		return ":" + p
	}
	return fallback
}
