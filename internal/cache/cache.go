// Package cache stores short-lived installation tokens on disk, one file per
// login/owner pair, guarded by a lock file so concurrent invocations do not
// mint twice.
package cache

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Skew is how long a cached token must still be valid to be reused.
const Skew = 300 * time.Second

// Dir returns $XDG_CACHE_HOME/gh-vault-agent-app-token or
// ~/.cache/gh-vault-agent-app-token.
func Dir(getenv func(string) string) (string, error) {
	if x := getenv("XDG_CACHE_HOME"); x != "" {
		return filepath.Join(x, "gh-vault-agent-app-token"), nil
	}
	h := getenv("HOME")
	if h == "" {
		var err error
		if h, err = os.UserHomeDir(); err != nil {
			return "", err
		}
	}
	return filepath.Join(h, ".cache", "gh-vault-agent-app-token"), nil
}

// Sanitize replaces every byte outside [A-Za-z0-9._-] with '_'.
func Sanitize(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			b[i] = '_'
		}
	}
	return string(b)
}

// Entry is a cached token.
type Entry struct {
	Expires        time.Time
	Token          string
	InstallationID int64 // 0 if unknown
	AppID          int64 // App that minted the token; 0 if unknown
}

// Valid reports whether e can be reused at now.
func (e *Entry) Valid(now time.Time) bool {
	return e != nil && e.Token != "" && e.Expires.Sub(now) > Skew
}

// Format renders
// "<expires_epoch>\t<token>[\t<installation_id>\t<app_id>]\n".
func (e *Entry) Format() string {
	s := strconv.FormatInt(e.Expires.Unix(), 10) + "\t" + e.Token
	if e.InstallationID > 0 || e.AppID > 0 {
		s += "\t" + strconv.FormatInt(e.InstallationID, 10) + "\t" + strconv.FormatInt(e.AppID, 10)
	}
	return s + "\n"
}

// Parse reads a cache file's content. Fields after the token are optional.
func Parse(data string) (*Entry, error) {
	line := strings.TrimRight(strings.SplitN(data, "\n", 2)[0], "\r")
	f := strings.Split(line, "\t")
	if len(f) < 2 || f[1] == "" {
		return nil, fmt.Errorf("malformed cache entry")
	}
	exp, err := strconv.ParseInt(f[0], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("malformed cache expiry")
	}
	e := &Entry{Expires: time.Unix(exp, 0), Token: f[1]}
	if len(f) > 2 {
		e.InstallationID, _ = strconv.ParseInt(f[2], 10, 64)
	}
	if len(f) > 3 {
		e.AppID, _ = strconv.ParseInt(f[3], 10, 64)
	}
	return e, nil
}

// Store is a cache directory.
type Store struct{ Dir string }

// Open creates the directory with mode 0700.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{Dir: dir}, nil
}

// Scope identifies one cache entry. Tokens for different GitHub hosts never
// share an entry.
type Scope struct {
	Login, Owner string
	Host         string // "" for github.com
}

func (s *Store) path(sc Scope) string {
	name := sc.Login + "__" + strings.ToLower(sc.Owner)
	if sc.Host != "" {
		name += "__" + strings.ToLower(sc.Host)
	}
	return filepath.Join(s.Dir, Sanitize(name))
}

// Lock takes the exclusive per-entry lock. Call the returned func to release.
func (s *Store) Lock(sc Scope) (func(), error) {
	f, err := os.OpenFile(s.path(sc)+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(f); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		unlockFile(f)
		f.Close()
	}, nil
}

// Get returns the cached entry, or nil if missing or unreadable.
func (s *Store) Get(sc Scope) *Entry {
	data, err := os.ReadFile(s.path(sc))
	if err != nil {
		return nil
	}
	e, err := Parse(string(data))
	if err != nil {
		return nil
	}
	return e
}

// Put atomically writes the entry with mode 0600.
func (s *Store) Put(sc Scope, e *Entry) error {
	p := s.path(sc)
	tmp, err := os.CreateTemp(s.Dir, filepath.Base(p)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(e.Format()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}
