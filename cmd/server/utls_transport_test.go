package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func testTLSClient(t *testing.T, proxyURL *url.URL, server *httptest.Server) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	transport := newSplitTransportWithTLSConfig(proxyURL, &tls.Config{RootCAs: pool, NextProtos: []string{"h2", "http/1.1"}})
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport}
}

func TestSplitTransportUsesUTLSForDirectHTTPS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Protocol", r.Proto)
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()

	resp, err := testTLSClient(t, nil, server).Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Protocol"); got == "" {
		t.Fatal("TLS request did not reach the test server")
	}
}

func TestSplitTransportUsesUTLSThroughHTTPConnectProxy(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "proxied")
	}))
	defer server.Close()
	proxyURL, closeProxy := startConnectProxy(t)
	defer closeProxy()

	resp, err := testTLSClient(t, proxyURL, server).Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "proxied" {
		t.Fatalf("body=%q", body)
	}
}

func TestSplitTransportUsesUTLSThroughSOCKS5Proxy(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "socks")
	}))
	defer server.Close()
	proxyURL, closeProxy := startSOCKS5Proxy(t)
	defer closeProxy()

	resp, err := testTLSClient(t, proxyURL, server).Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "socks" {
		t.Fatalf("body=%q", body)
	}
}

func startConnectProxy(t *testing.T) (*url.URL, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				select {
				case <-stop:
					return
				default:
				}
				continue
			}
			go proxyConnection(conn)
		}
	}()
	u, _ := url.Parse("http://" + listener.Addr().String())
	return u, func() {
		close(stop)
		listener.Close()
	}
}

func proxyConnection(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	request, err := http.ReadRequest(reader)
	if err != nil || request.Method != http.MethodConnect {
		return
	}
	target, err := net.Dial("tcp", request.Host)
	if err != nil {
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer target.Close()
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	joined := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(target, io.MultiReader(reader, conn)); joined <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, target); joined <- struct{}{} }()
	<-joined
}

func startSOCKS5Proxy(t *testing.T) (*url.URL, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				select {
				case <-stop:
					return
				default:
				}
				continue
			}
			go socksConnection(conn)
		}
	}()
	u, _ := url.Parse("socks5://" + listener.Addr().String())
	return u, func() {
		close(stop)
		listener.Close()
	}
}

func socksConnection(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	version, err := reader.ReadByte()
	if err != nil || version != 5 {
		return
	}
	methodCount, err := reader.ReadByte()
	if err != nil {
		return
	}
	if _, err := io.CopyN(io.Discard, reader, int64(methodCount)); err != nil {
		return
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}
	requestHeader := make([]byte, 4)
	if _, err := io.ReadFull(reader, requestHeader); err != nil || requestHeader[0] != 5 || requestHeader[1] != 1 {
		return
	}
	var host string
	switch requestHeader[3] {
	case 1:
		address := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(reader, address); err != nil {
			return
		}
		host = net.IP(address).String()
	case 3:
		length, err := reader.ReadByte()
		if err != nil {
			return
		}
		address := make([]byte, length)
		if _, err := io.ReadFull(reader, address); err != nil {
			return
		}
		host = string(address)
	default:
		return
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(reader, port); err != nil {
		return
	}
	target, err := net.Dial("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", int(port[0])<<8|int(port[1]))))
	if err != nil {
		_, _ = conn.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()
	if _, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	joined := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(target, io.MultiReader(reader, conn)); joined <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, target); joined <- struct{}{} }()
	<-joined
}

func TestRouteLabelDoesNotExposeProxyCredentials(t *testing.T) {
	u, _ := url.Parse("socks5://user:secret@example.test:1080")
	label := routeLabel(routedDialer{proxyURL: u})
	if label != "socks5" || strings.Contains(label, "secret") {
		t.Fatalf("unexpected route label %q", label)
	}
}

func TestUTLSContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (&net.Dialer{}).DialContext(ctx, "tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatal("expected canceled dial")
	}
}
