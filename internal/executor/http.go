package executor

import (
	"context"
	"errors"
	"io"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	"github.com/safe-agentic-world/nomos/internal/normalize"
)

type HTTPParams struct {
	Method string            `json:"method"`
	Body   string            `json:"body"`
	Header map[string]string `json:"headers"`
}

type HTTPResult struct {
	StatusCode    int
	Body          string
	Truncated     bool
	FinalResource string
	RedirectHops  int
}

type RedirectPolicy struct {
	Enabled    bool
	HopLimit   int
	AllowHosts []string
}

type HTTPRunner struct {
	client   *http.Client
	maxBytes int
}

var (
	ErrRedirectDenied         = errors.New("http redirects are not allowed")
	ErrRedirectHopLimit       = errors.New("http redirect hop limit exceeded")
	ErrRedirectDisallowedHost = errors.New("http redirect destination is not allowlisted")
	ErrRedirectInvalidTarget  = errors.New("http redirect target is invalid")
)

func NewHTTPRunner(maxBytes int) *HTTPRunner {
	if maxBytes <= 0 {
		maxBytes = 64 * 1024
	}
	return &HTTPRunner{
		client:   &http.Client{Timeout: 5 * time.Second},
		maxBytes: maxBytes,
	}
}

func (r *HTTPRunner) Do(url string, params HTTPParams) (HTTPResult, error) {
	return r.DoWithPolicy(url, params, RedirectPolicy{})
}

func (r *HTTPRunner) DoWithPolicy(url string, params HTTPParams, policy RedirectPolicy) (HTTPResult, error) {
	safeURL, normalizedTarget, err := resolveHTTPRequestTarget(url, policy.AllowHosts)
	if err != nil {
		return HTTPResult{}, err
	}
	if params.Method == "" {
		params.Method = http.MethodGet
	}
	client := *r.client
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	timeout := client.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	redirectHops := 0
	currentURL := safeURL
	currentNormalized := normalizedTarget
	currentMethod := params.Method

	for {
		req, err := newHTTPRequest(currentMethod, currentURL, params)
		if err != nil {
			return HTTPResult{}, err
		}
		ctx, cancel := context.WithTimeout(req.Context(), timeout)
		req = req.WithContext(ctx)
		resp, err := transport.RoundTrip(req)
		cancel()
		if err != nil {
			return HTTPResult{}, err
		}
		if !isRedirectResponse(resp.StatusCode) {
			defer resp.Body.Close()
			limited := io.LimitReader(resp.Body, int64(r.maxBytes+1))
			body, err := io.ReadAll(limited)
			if err != nil {
				return HTTPResult{}, err
			}
			truncated := len(body) > r.maxBytes
			if truncated {
				body = body[:r.maxBytes]
			}
			return HTTPResult{
				StatusCode:    resp.StatusCode,
				Body:          string(body),
				Truncated:     truncated,
				FinalResource: currentNormalized,
				RedirectHops:  redirectHops,
			}, nil
		}
		if err := resp.Body.Close(); err != nil {
			return HTTPResult{}, err
		}
		location := strings.TrimSpace(resp.Header.Get("Location"))
		if location == "" {
			return HTTPResult{}, ErrRedirectInvalidTarget
		}
		currentURL, currentNormalized, currentMethod, err = nextRedirectTarget(currentURL, currentMethod, location, policy, redirectHops)
		if err != nil {
			return HTTPResult{}, err
		}
		redirectHops++
	}
}

func (r *HTTPRunner) Client() *http.Client {
	return r.client
}

func (r *HTTPRunner) SetClient(client *http.Client) {
	if client != nil {
		r.client = client
	}
}

func hostAllowlisted(allowHosts []string, host string) bool {
	for _, allowed := range allowHosts {
		if strings.TrimSpace(allowed) == host {
			return true
		}
	}
	return false
}

func hostFromNormalizedURL(resource string) string {
	trimmed := strings.TrimPrefix(resource, "url://")
	idx := strings.Index(trimmed, "/")
	if idx == -1 {
		return trimmed
	}
	return trimmed[:idx]
}

func resolveHTTPRequestTarget(rawURL string, allowHosts []string) (*neturl.URL, string, error) {
	parsed, err := neturl.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, "", ErrRedirectInvalidTarget
	}
	normalized, err := normalize.NormalizeRedirectURL(rawURL)
	if err != nil {
		return nil, "", ErrRedirectInvalidTarget
	}
	host := hostFromNormalizedURL(normalized)
	if len(allowHosts) > 0 && !hostAllowlisted(allowHosts, host) {
		return nil, "", ErrRedirectDisallowedHost
	}
	path := pathFromNormalizedURL(normalized)
	scheme := strings.ToLower(parsed.Scheme)
	return &neturl.URL{
		Scheme: scheme,
		Host:   host,
		Path:   path,
	}, normalized, nil
}

func pathFromNormalizedURL(resource string) string {
	trimmed := strings.TrimPrefix(resource, "url://")
	idx := strings.Index(trimmed, "/")
	if idx == -1 {
		return "/"
	}
	return trimmed[idx:]
}

func newHTTPRequest(method string, target *neturl.URL, params HTTPParams) (*http.Request, error) {
	req, err := http.NewRequest(method, "", strings.NewReader(params.Body))
	if err != nil {
		return nil, err
	}
	req.URL = cloneURL(target)
	req.Host = target.Host
	for key, value := range params.Header {
		req.Header.Set(key, value)
	}
	return req, nil
}

func nextRedirectTarget(current *neturl.URL, method, location string, policy RedirectPolicy, redirectHops int) (*neturl.URL, string, string, error) {
	if !policy.Enabled {
		return nil, "", "", ErrRedirectDenied
	}
	limit := policy.HopLimit
	if limit <= 0 {
		limit = 3
	}
	if redirectHops+1 > limit {
		return nil, "", "", ErrRedirectHopLimit
	}
	parsedLocation, err := neturl.Parse(location)
	if err != nil {
		return nil, "", "", ErrRedirectInvalidTarget
	}
	resolved := current.ResolveReference(parsedLocation)
	safeURL, normalized, err := resolveHTTPRequestTarget(resolved.String(), policy.AllowHosts)
	if err != nil {
		return nil, "", "", err
	}
	return safeURL, normalized, redirectMethod(method), nil
}

func redirectMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead:
		return method
	default:
		return http.MethodGet
	}
}

func isRedirectResponse(statusCode int) bool {
	switch statusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func cloneURL(value *neturl.URL) *neturl.URL {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
