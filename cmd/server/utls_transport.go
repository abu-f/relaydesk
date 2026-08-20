package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
)

// splitHTTPSTransport keeps ordinary HTTP proxy behavior while taking full
// control of the connection and ClientHello for HTTPS requests.
type splitHTTPSTransport struct {
	httpTransport  *http.Transport
	httpsTransport *http.Transport
	tlsConfig      *tls.Config
}

type utlsNetConn struct {
	*utls.UConn
	state tls.ConnectionState
}

func (c *utlsNetConn) ConnectionState() tls.ConnectionState { return c.state }

func standardConnectionState(state utls.ConnectionState) tls.ConnectionState {
	return tls.ConnectionState{
		Version:                     state.Version,
		HandshakeComplete:           state.HandshakeComplete,
		DidResume:                   state.DidResume,
		CipherSuite:                 state.CipherSuite,
		NegotiatedProtocol:          state.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  state.NegotiatedProtocolIsMutual,
		ServerName:                  state.ServerName,
		PeerCertificates:            cloneCertificates(state.PeerCertificates),
		VerifiedChains:              cloneChains(state.VerifiedChains),
		SignedCertificateTimestamps: state.SignedCertificateTimestamps,
		OCSPResponse:                state.OCSPResponse,
		TLSUnique:                   state.TLSUnique,
	}
}

func cloneCertificates(in []*x509.Certificate) []*x509.Certificate {
	return append([]*x509.Certificate(nil), in...)
}

func cloneChains(in [][]*x509.Certificate) [][]*x509.Certificate {
	out := make([][]*x509.Certificate, len(in))
	for i := range in {
		out[i] = cloneCertificates(in[i])
	}
	return out
}

func (t *splitHTTPSTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.EqualFold(req.URL.Scheme, "https") {
		return t.httpsTransport.RoundTrip(req)
	}
	return t.httpTransport.RoundTrip(req)
}

func (t *splitHTTPSTransport) CloseIdleConnections() {
	t.httpTransport.CloseIdleConnections()
	t.httpsTransport.CloseIdleConnections()
}

type routedDialer struct {
	proxyURL *url.URL
	dialer   *net.Dialer
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (d routedDialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if d.proxyURL == nil {
		return d.dialer.DialContext(ctx, network, address)
	}
	u := d.proxyURL
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if u.User != nil {
			password, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: password}
		}
		socks, err := proxy.SOCKS5(network, u.Host, auth, proxy.Direct)
		if err != nil {
			return nil, err
		}
		if contextDialer, ok := socks.(proxy.ContextDialer); ok {
			return contextDialer.DialContext(ctx, network, address)
		}
		return socks.Dial(network, address)
	case "http", "https":
		conn, err := d.dialer.DialContext(ctx, network, u.Host)
		if err != nil {
			return nil, err
		}
		if strings.EqualFold(u.Scheme, "https") {
			serverName := u.Hostname()
			if serverName == "" {
				conn.Close()
				return nil, fmt.Errorf("proxy host is empty")
			}
			proxyTLS := tls.Client(conn, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12})
			if err := proxyTLS.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, fmt.Errorf("proxy TLS handshake: %w", err)
			}
			conn = proxyTLS
		}
		routedConn := conn
		conn, err = writeConnect(ctx, routedConn, address, u)
		if err != nil {
			routedConn.Close()
			return nil, err
		}
		return conn, nil
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", u.Scheme)
	}
}

func writeConnect(ctx context.Context, conn net.Conn, address string, proxyURL *url.URL) (net.Conn, error) {
	deadline := time.Now().Add(time.Minute)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = conn.SetDeadline(deadline)
	defer conn.SetDeadline(time.Time{})
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: address}, Host: address, Header: make(http.Header)}
	if proxyURL.User != nil {
		password, _ := proxyURL.User.Password()
		req.SetBasicAuth(proxyURL.User.Username(), password)
		req.Header.Set("Proxy-Authorization", req.Header.Get("Authorization"))
		req.Header.Del("Authorization")
	}
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("proxy CONNECT write: %w", err)
	}
	br := bufio.NewReaderSize(conn, 16<<10)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, fmt.Errorf("proxy CONNECT response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("proxy CONNECT returned %s", resp.Status)
	}
	return &bufferedConn{Conn: conn, reader: br}, nil
}

func newSplitTransport(proxyURL *url.URL) *splitHTTPSTransport {
	return newSplitTransportWithTLSConfig(proxyURL, nil)
}

func newSplitTransportWithTLSConfig(proxyURL *url.URL, tlsConfig *tls.Config) *splitHTTPSTransport {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil
	base.DialContext = dialer.DialContext
	base.ResponseHeaderTimeout = upstreamRequestTimeout

	httpTr := base.Clone()
	if proxyURL != nil {
		httpTr.Proxy = http.ProxyURL(proxyURL)
	}
	httpsTr := base.Clone()
	httpsTr.Proxy = nil
	httpsTr.ForceAttemptHTTP2 = true
	route := routedDialer{proxyURL: proxyURL, dialer: dialer}
	httpsTr.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialUTLS(ctx, route, network, address, tlsConfig)
	}
	return &splitHTTPSTransport{httpTransport: httpTr, httpsTransport: httpsTr, tlsConfig: tlsConfig}
}

func dialUTLS(ctx context.Context, route routedDialer, network, address string, baseConfig *tls.Config) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	conn, err := route.dial(ctx, network, address)
	if err != nil {
		return nil, err
	}
	config := &utls.Config{ServerName: host, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}
	if baseConfig != nil {
		config.RootCAs = baseConfig.RootCAs
		config.ClientCAs = baseConfig.ClientCAs
		config.InsecureSkipVerify = baseConfig.InsecureSkipVerify
		config.MinVersion = baseConfig.MinVersion
		config.MaxVersion = baseConfig.MaxVersion
		if baseConfig.ServerName != "" {
			config.ServerName = baseConfig.ServerName
		}
		if len(baseConfig.NextProtos) > 0 {
			config.NextProtos = append([]string(nil), baseConfig.NextProtos...)
		}
	}
	client := utls.UClient(conn, config, utls.HelloChrome_Auto)
	if err := client.HandshakeContext(ctx); err == nil {
		return &utlsNetConn{UConn: client, state: standardConnectionState(client.ConnectionState())}, nil
	} else {
		conn.Close()
		log.Printf("uTLS handshake failed for %s via %s; retrying with standard TLS: %v", host, routeLabel(route), err)
	}
	conn, err = route.dial(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("uTLS failed and standard TLS reconnect failed: %w", err)
	}
	standardConfig := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}
	if baseConfig != nil {
		standardConfig = baseConfig.Clone()
		if standardConfig.ServerName == "" {
			standardConfig.ServerName = host
		}
		if len(standardConfig.NextProtos) == 0 {
			standardConfig.NextProtos = []string{"h2", "http/1.1"}
		}
	}
	standard := tls.Client(conn, standardConfig)
	if err := standard.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("uTLS handshake failed (%v); standard TLS handshake failed: %w", err, err)
	}
	return standard, nil
}

func routeLabel(route routedDialer) string {
	if route.proxyURL == nil {
		return "direct"
	}
	return strings.ToLower(route.proxyURL.Scheme)
}

var _ http.RoundTripper = (*splitHTTPSTransport)(nil)
var _ interface{ CloseIdleConnections() } = (*splitHTTPSTransport)(nil)
