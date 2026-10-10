package github

import "testing"

func TestBaseURL(t *testing.T) {
	for in, want := range map[string]string{
		"":                "https://api.github.com",
		"GitHub.com":      "https://api.github.com",
		"ghe.example.com": "https://ghe.example.com/api/v3",
		"acme.ghe.com":    "https://api.acme.ghe.com",
	} {
		if got := BaseURL(in); got != want {
			t.Errorf("BaseURL(%q) = %q, want %q", in, got, want)
		}
	}
}
