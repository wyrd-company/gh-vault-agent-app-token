package cache

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestValidSkew(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cases := []struct {
		left time.Duration
		want bool
	}{
		{time.Hour, true},
		{301 * time.Second, true},
		{300 * time.Second, false},
		{10 * time.Second, false},
		{-time.Minute, false},
	}
	for _, c := range cases {
		e := &Entry{Expires: now.Add(c.left), Token: "t"}
		if got := e.Valid(now); got != c.want {
			t.Errorf("left %v: got %v want %v", c.left, got, c.want)
		}
	}
	var nilEntry *Entry
	if nilEntry.Valid(now) {
		t.Error("nil entry must not be valid")
	}
}

func TestFormatParse(t *testing.T) {
	e := &Entry{Expires: time.Unix(1700003600, 0), Token: "ghs_abc"}
	if got := e.Format(); got != "1700003600\tghs_abc\n" {
		t.Fatalf("format = %q", got)
	}
	e.InstallationID, e.AppID = 42, 1001
	if got := e.Format(); got != "1700003600\tghs_abc\t42\t1001\n" {
		t.Fatalf("format = %q", got)
	}
	p, err := Parse(e.Format())
	if err != nil || p.Token != "ghs_abc" || p.Expires.Unix() != 1700003600 || p.InstallationID != 42 || p.AppID != 1001 {
		t.Fatalf("parse = %+v %v", p, err)
	}
	// File written by the original shell shim.
	p, err = Parse("1700003600\tghs_old\n")
	if err != nil || p.Token != "ghs_old" || p.InstallationID != 0 {
		t.Fatalf("parse shim format = %+v %v", p, err)
	}
	for _, bad := range []string{"", "x\ttok\n", "123\n", "123\t\n"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func TestSanitize(t *testing.T) {
	if got := Sanitize("my-app[bot]__Acme/x y"); got != "my-app_bot___Acme_x_y" {
		t.Fatalf("got %q", got)
	}
}

func TestStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "c")
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	sc := Scope{Login: "a[bot]", Owner: "Acme"}
	if s.Get(sc) != nil {
		t.Fatal("expected miss")
	}
	e := &Entry{Expires: time.Unix(1700003600, 0), Token: "ghs_x", InstallationID: 7}
	if err := s.Put(sc, e); err != nil {
		t.Fatal(err)
	}
	got := s.Get(Scope{Login: "a[bot]", Owner: "acme"}) // owner is case-insensitive
	if got == nil || got.Token != "ghs_x" {
		t.Fatalf("got %+v", got)
	}
	if s.Get(Scope{Login: "a[bot]", Owner: "Acme", Host: "ghe.example.com"}) != nil {
		t.Fatal("entries must not be shared across hosts")
	}
	p := filepath.Join(dir, "a_bot___acme")
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(p)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("file mode %v %v", fi, err)
		}
		di, _ := os.Stat(dir)
		if di.Mode().Perm() != 0o700 {
			t.Fatalf("dir mode %v", di.Mode())
		}
	}
}

func TestLockSerialises(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	inside, maxInside := 0, 0
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock, err := s.Lock(Scope{Login: "a", Owner: "b"})
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			inside++
			if inside > maxInside {
				maxInside = inside
			}
			mu.Unlock()
			time.Sleep(5 * time.Millisecond)
			mu.Lock()
			inside--
			mu.Unlock()
			unlock()
		}()
	}
	wg.Wait()
	if maxInside != 1 {
		t.Fatalf("lock not exclusive: %d holders at once", maxInside)
	}
}
