package config

import (
	"os"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Addr      string
	DSN       string
	JWTSecret string
	JWTTTL    time.Duration
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
		dsn = "flowpay:flowpay@tcp(127.0.0.1:3306)/flowpay?parseTime=true&loc=Local&clientFoundRows=true"
	}
	secret := os.Getenv("FLOWPAY_JWT_SECRET")
	ttl := 24 * time.Hour
	if s := os.Getenv("FLOWPAY_JWT_TTL"); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			ttl = d
		}
	}
	return Config{Addr: addr, DSN: dsn, JWTSecret: secret, JWTTTL: ttl}
}
