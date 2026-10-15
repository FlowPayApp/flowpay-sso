package revoked

import (
	"sync"
	"time"
)

// List es la copia en memoria de los jti revocados. El camino feliz no va a la base.
type List struct {
	mu    sync.Mutex
	until map[string]time.Time
}

func New() *List {
	return &List{until: map[string]time.Time{}}
}

func (l *List) Add(jtis []string, exp time.Time) {
	if len(jtis) == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for id, until := range l.until {
		if !until.After(now) {
			delete(l.until, id)
		}
	}
	for _, jti := range jtis {
		if jti == "" {
			continue
		}
		if prev, ok := l.until[jti]; !ok || exp.After(prev) {
			l.until[jti] = exp
		}
	}
}

func (l *List) Replace(items map[string]time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.until = items
}

func (l *List) Has(jti string) bool {
	if jti == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	exp, ok := l.until[jti]
	if !ok {
		return false
	}
	if !exp.After(time.Now()) {
		delete(l.until, jti)
		return false
	}
	return true
}
