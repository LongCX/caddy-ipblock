package ipblockchecker

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(IPBlockChecker{})
	httpcaddyfile.RegisterHandlerDirective("ipblockchecker", parseCaddyfile)
}

// IPBlockChecker checks if an IP is blocked via an external API
type IPBlockChecker struct {
	// API endpoint URL to check IP status
	APIEndpoint string `json:"api_endpoint,omitempty"`
	
	// Request timeout duration (default: 5s)
	Timeout     string `json:"timeout,omitempty"`
	
	timeout     time.Duration
	client      *http.Client
}

// CaddyModule returns the Caddy module information
func (IPBlockChecker) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ipblockchecker",
		New: func() caddy.Module { return new(IPBlockChecker) },
	}
}

// Provision sets up the module
func (m *IPBlockChecker) Provision(ctx caddy.Context) error {
	if m.APIEndpoint == "" {
		return fmt.Errorf("api_endpoint is required")
	}

	if m.Timeout == "" {
		m.timeout = 5 * time.Second
	} else {
		var err error
		m.timeout, err = time.ParseDuration(m.Timeout)
		if err != nil {
			return fmt.Errorf("invalid timeout: %v", err)
		}
	}

	m.client = &http.Client{
		Timeout: m.timeout,
	}

	return nil
}

// Validate checks the configuration
func (m *IPBlockChecker) Validate() error {
	if m.APIEndpoint == "" {
		return fmt.Errorf("api_endpoint cannot be empty")
	}
	return nil
}

// ServeHTTP handles the HTTP request
func (m IPBlockChecker) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Extract IP from request
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}

	// Check X-Forwarded-For header (if behind a proxy)
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ip = forwarded
	}

	// Check if IP is blocked
	isBlocked, err := m.checkIPBlocked(ip)
	if err != nil {
		// Log error but allow request to continue
		return next.ServeHTTP(w, r)
	}

	// If IP is blocked, return 403 Forbidden
	if isBlocked {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("Access Denied"))
		return nil
	}

	// IP is not blocked, continue processing request
	return next.ServeHTTP(w, r)
}

// checkIPBlocked calls the API to check if IP is blocked
func (m *IPBlockChecker) checkIPBlocked(ip string) (bool, error) {
	url := fmt.Sprintf("%s?ip=%s", m.APIEndpoint, ip)

	resp, err := m.client.Get(url)
	if err != nil {
		return false, fmt.Errorf("failed to connect to API: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response: %v", err)
	}

	// Try to parse JSON response first
	var result struct {
		Blocked int `json:"blocked"`
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		// If JSON parsing fails, try plain text
		if string(body) == "1" {
			return true, nil
		} else if string(body) == "0" {
			return false, nil
		}
		return false, fmt.Errorf("failed to parse response: %v", err)
	}

	return result.Blocked == 1, nil
}

// UnmarshalCaddyfile sets up the module from Caddyfile
func (m *IPBlockChecker) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "api_endpoint":
				if !d.Args(&m.APIEndpoint) {
					return d.ArgErr()
				}
			case "timeout":
				if !d.Args(&m.Timeout) {
					return d.ArgErr()
				}
			default:
				return d.Errf("invalid option: %s", d.Val())
			}
		}
	}
	return nil
}

// parseCaddyfile parses the directive from Caddyfile
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m IPBlockChecker
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// Interface guards
var (
	_ caddy.Provisioner           = (*IPBlockChecker)(nil)
	_ caddy.Validator             = (*IPBlockChecker)(nil)
	_ caddyhttp.MiddlewareHandler = (*IPBlockChecker)(nil)
	_ caddyfile.Unmarshaler       = (*IPBlockChecker)(nil)
)