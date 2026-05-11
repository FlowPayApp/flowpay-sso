package dberrors

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

func PgCode(err error) string {
	var e *pgconn.PgError
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func IsUniqueViolation(err error) bool {
	return PgCode(err) == "23505"
}

func IsUndefinedTable(err error) bool {
	return PgCode(err) == "42P01"
}
