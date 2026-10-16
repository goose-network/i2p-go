// Reseed fetching: HTTPS download of the SU3 router-info bundle
// through the upstream proxy, TLS-verified against the system roots
// plus the pinned reseed certificates, then SU3 signature verification
// and extraction.
//
// The pinned certs are also added as TLS trust roots (Java does the
// same via SSLEepGet: system key store + certificates/ssl/), since
// reseed hosts use a mix of public CAs and pinned self-signed certs.
// The SU3 signature pins the downloaded content to a known signer key
// regardless of the TLS layer.
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

// certPool builds the TLS root pool: the pinned reseed certs plus the
// system roots. Java does the same (KeyStoreUtil.loadSystemKeyStore
// then addCerts(certificates/ssl/)) — most reseed hosts use public CAs
// (Let's Encrypt etc.), a few use the pinned self-signed certs.
func certPool() (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	entries, err := certFS.ReadDir("certs")
	if err != nil {
		return nil, fmt.Errorf("reseed: certs: %w", err)
	}
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

	// Standard chain + hostname verification of the leaf against the
	// system roots plus the pinned reseed certs, using the server-sent
	// intermediates (what Java's SSLEepGet does). The SU3 signature
	// additionally pins the content to a known signer key.
	verifyChain := func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("reseed: no server certificate")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("reseed: bad cert: %w", err)
		}
		intermediates := x509.NewCertPool()
		for _, raw := range rawCerts[1:] {
			if c, err := x509.ParseCertificate(raw); err == nil {
				intermediates.AddCert(c)
			}
		}
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:         pool,
			Intermediates: intermediates,
			DNSName:       serverName,
		}); err != nil {
			return fmt.Errorf("reseed: cert not trusted: %w", err)
		}
		return nil
	}
	tlsCfg := &tls.Config{
		ServerName:            serverName,
		MinVersion:            tls.VersionTLS12,
		VerifyPeerCertificate: verifyChain,
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
