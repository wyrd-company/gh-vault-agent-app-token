// Package github calls the GitHub App endpoints needed to mint an
// installation token.
package github

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// BaseURL returns the REST API root for GH_HOST (empty → github.com).
func BaseURL(ghHost string) string {
	h := strings.ToLower(strings.TrimSpace(ghHost))
	if h == "" || h == "github.com" || h == "api.github.com" {
		return "https://api.github.com"
	}
	return "https://" + ghHost + "/api/v3"
}

// Client calls the GitHub REST API with an App JWT.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// Error is a GitHub API failure.
type Error struct {
	Method, Path string
	Status       int // 0 when unreachable
	Message      string
}

func (e *Error) Error() string {
	if e.Status == 0 {
		return fmt.Sprintf("GitHub API %s %s: %s", e.Method, e.Path, e.Message)
	}
	return fmt.Sprintf("GitHub API %s %s: HTTP %d: %s", e.Method, e.Path, e.Status, e.Message)
}

// ErrNotInstalled is returned when no installation matches the owner.
type ErrNotInstalled struct{ Owner string }

func (e *ErrNotInstalled) Error() string { return "not installed on " + e.Owner }

type Installation struct {
	ID      int64 `json:"id"`
	Account struct {
		Login string `json:"login"`
	} `json:"account"`
}

// Token is an installation access token.
type Token struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (c *Client) do(method, path, jwt string, out any) (*http.Response, error) {
	u := path
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		u = strings.TrimRight(c.BaseURL, "/") + path
	}
	req, err := http.NewRequest(method, u, nil)
	if err != nil {
		return nil, &Error{Method: method, Path: path, Message: err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "gh-vault-agent-app-token")
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, &Error{Method: method, Path: path, Message: err.Error()}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode/100 != 2 {
		var m struct {
			Message string `json:"message"`
		}
		msg := strings.TrimSpace(string(raw))
		if json.Unmarshal(raw, &m) == nil && m.Message != "" {
			msg = m.Message
		}
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return resp, &Error{Method: method, Path: path, Status: resp.StatusCode, Message: msg}
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return resp, &Error{Method: method, Path: path, Status: resp.StatusCode, Message: "invalid JSON response: " + err.Error()}
	}
	return resp, nil
}

var nextLink = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// FindInstallation lists the App's installations and returns the one whose
// account login equals owner, case-insensitively.
func (c *Client) FindInstallation(jwt, owner string) (int64, error) {
	path := "/app/installations?per_page=100"
	for path != "" {
		var page []Installation
		resp, err := c.do(http.MethodGet, path, jwt, &page)
		if err != nil {
			return 0, err
		}
		for _, in := range page {
			if strings.EqualFold(in.Account.Login, owner) {
				return in.ID, nil
			}
		}
		path = ""
		if m := nextLink.FindStringSubmatch(resp.Header.Get("Link")); m != nil {
			path = m[1]
		}
	}
	return 0, &ErrNotInstalled{Owner: owner}
}

// CreateToken mints an installation access token.
func (c *Client) CreateToken(jwt string, installationID int64) (*Token, error) {
	var t Token
	path := fmt.Sprintf("/app/installations/%d/access_tokens", installationID)
	if _, err := c.do(http.MethodPost, path, jwt, &t); err != nil {
		return nil, err
	}
	if t.Token == "" || t.ExpiresAt.IsZero() {
		return nil, &Error{Method: http.MethodPost, Path: path, Status: http.StatusCreated, Message: "response missing token or expires_at"}
	}
	return &t, nil
}
