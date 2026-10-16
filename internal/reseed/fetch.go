// Reseed fetching: HTTPS download of the SU3 router-info bundle
// through the upstream proxy, TLS-verified against the pinned reseed
// certificates, then SU3 signature verification and extraction.
//
// The bundled certs are also the TLS trust roots; hostname
// verification is replaced by chain verification against those roots
// (reseed certs commonly carry no matching SANs), which is safe here
// because the SU3 signature pins the content to a known signer key.
//
// Reference: Reseeder.java, SSLProxyFetcher / EepGet fetch in the
// Java router.
package reseed

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/goose-network/i2p-go/internal/proxy"
)

//go:embed certs/*.crt
var certFS embed.FS

// maxSU3Size bounds the download (a full RI bundle is a few MB).
const maxSU3Size = 64 << 20

// fetchTimeout bounds one HTTPS download.
const fetchTimeout = 90 * time.Second

// TrustedKeys returns the bundled reseed signer public keys, keyed
// by certificate common name (the SU3 Signer field).
func TrustedKeys() (map[string]crypto.PublicKey, error) {
	entries, err := certFS.ReadDir("certs")
	if err != nil {
		return nil, fmt.Errorf("reseed: certs: %w", err)
	}
	keys := make(map[string]crypto.PublicKey, len(entries))
	for _, e := range entries {
		b, err := certFS.ReadFile("certs/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("reseed: cert %s: %w", e.Name(), err)
		}
		m, err := ParseCertsPEM(b)
		if err != nil {
			return nil, fmt.Errorf("reseed: cert %s: %w", e.Name(), err)
		}
		for k, v := range m {
			keys[k] = v
		}
	}
	return keys, nil
}

// certPool builds a TLS root pool from the bundled reseed certs.
func certPool() (*x509.CertPool, error) {
	entries, err := certFS.ReadDir("certs")
	if err != nil {
		return nil, fmt.Errorf("reseed: certs: %w", err)
	}
	pool := x509.NewCertPool()
	for _, e := range entries {
		b, err := certFS.ReadFile("certs/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("reseed: cert %s: %w", e.Name(), err)
		}
		if !pool.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("reseed: cert %s: not PEM", e.Name())
		}
	}
	return pool, nil
}

// Fetch downloads, TLS-verifies, SU3-signature-verifies and parses
// the SU3 bundle from one URL. upstream may be nil for direct
// connections.
func Fetch(ctx context.Context, seedURL string, upstream *proxy.Dialer) (*SU3, error) {
	pool, err := certPool()
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(seedURL)
	if err != nil {
		return nil, fmt.Errorf("reseed: bad URL %q: %w", seedURL, err)
	}
	if u.Scheme != "https" || u.Hostname() == "" {
		return nil, fmt.Errorf("reseed: bad URL %q", seedURL)
	}
	serverName := u.Hostname()

	// Chain verification against the pinned roots (no hostname check:
	// see the package comment). The SU3 signature pins the content.
	verifyChain := func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("reseed: no server certificate")
		}
		for _, raw := range rawCerts {
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				return fmt.Errorf("reseed: bad cert: %w", err)
			}
			if _, err := cert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
				return fmt.Errorf("reseed: cert not from a pinned root: %w", err)
			}
		}
		return nil
	}
	tlsCfg := &tls.Config{
		ServerName:            serverName,
		InsecureSkipVerify:    true, // replaced by VerifyPeerCertificate below
		VerifyPeerCertificate: verifyChain,
		MinVersion:            tls.VersionTLS12,
	}

	tr := &http.Transport{
		ForceAttemptHTTP2: false, // some reseed hosts reject h2 via CONNECT
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := dialUpstream(ctx, upstream, network, addr)
			if err != nil {
				return nil, err
			}
			c := tls.Client(raw, tlsCfg.Clone())
			if err := c.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, fmt.Errorf("reseed: TLS handshake: %w", err)
			}
			return c, nil
		},
	}
	client := &http.Client{Transport: tr, Timeout: fetchTimeout}

	full := seedURL
	if full[len(full)-1] != '/' {
		full += "/"
	}
	full += SU3Filename

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reseed: fetch %s: %w", full, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("reseed: fetch %s: status %d", full, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSU3Size))
	if err != nil {
		return nil, fmt.Errorf("reseed: read %s: %w", full, err)
	}
	if len(body) == maxSU3Size {
		return nil, fmt.Errorf("reseed: %s too large", full)
	}

	su3, err := ParseSU3(body)
	if err != nil {
		return nil, fmt.Errorf("reseed: parse %s: %w", full, err)
	}
	keys, err := TrustedKeys()
	if err != nil {
		return nil, err
	}
	if err := su3.Verify(keys); err != nil {
		return nil, fmt.Errorf("reseed: verify %s: %w", full, err)
	}
	return su3, nil
}

// dialUpstream dials through the proxy (or directly when nil).
func dialUpstream(ctx context.Context, upstream *proxy.Dialer, network, addr string) (net.Conn, error) {
	if upstream == nil {
		var nd net.Dialer
		return nd.DialContext(ctx, network, addr)
	}
	return upstream.Dial(ctx, network, addr)
}

// FetchAny tries the seed URLs in random order until one yields a
// verified SU3 bundle. Returns the first error if all fail.
func FetchAny(ctx context.Context, urls []string, upstream *proxy.Dialer) (*SU3, error) {
	if len(urls) == 0 {
		urls = DefaultSeedURLs
	}
	order := make([]string, len(urls))
	copy(order, urls)
	rand.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
	var firstErr error
	for _, u := range order {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		su3, err := Fetch(ctx, u, upstream)
		if err == nil {
			return su3, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, firstErr
}
