package config

import (
	"os"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Addr              string
	DSN               string
	JWTSecret         string
	JWTTTL            time.Duration
	SMTPHost          string
	SMTPPort          string
	SMTPUser          string
	SMTPPassword      string
	SMTPFrom          string
	SignupNotifyEmail string
}

func Load() Config {
	_ = godotenv.Load()
	addr := os.Getenv("FLOWPAY_SSO_ADDR")
	if addr == "" {
		addr = ":9090"
	}
	dsn := os.Getenv("FLOWPAY_SSO_DSN")
	if dsn == "" {
		dsn = os.Getenv("FLOWPAY_DSN")
	}
	if dsn == "" {
		dsn = "postgres://flowpay:flowpay@127.0.0.1:5432/flowpay?sslmode=disable"
	}
	secret := os.Getenv("FLOWPAY_JWT_SECRET")
	ttl := 24 * time.Hour
	if s := os.Getenv("FLOWPAY_JWT_TTL"); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			ttl = d
		}
	}
	return Config{
		Addr:              addr,
		DSN:               dsn,
		JWTSecret:         secret,
		JWTTTL:            ttl,
		SMTPHost:          os.Getenv("FLOWPAY_SMTP_HOST"),
		SMTPPort:          os.Getenv("FLOWPAY_SMTP_PORT"),
		SMTPUser:          os.Getenv("FLOWPAY_SMTP_USER"),
		SMTPPassword:      os.Getenv("FLOWPAY_SMTP_PASSWORD"),
		SMTPFrom:          os.Getenv("FLOWPAY_SMTP_FROM"),
		SignupNotifyEmail: os.Getenv("FLOWPAY_SIGNUP_NOTIFY_EMAIL"),
	}
}
